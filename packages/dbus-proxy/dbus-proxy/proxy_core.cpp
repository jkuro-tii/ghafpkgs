#include "dbus_proxy.h"
#include <gio/gio.h>
#include <glib-unix.h>
#include <glib.h>
#include <string.h>

/* forward decl for free function used by hash table init */
void free_proxied_object(gpointer data);

// Forward declarations of functions implemented here but used in handlers
gboolean discover_and_proxy_object_tree(const char *base_path,
                                        gboolean need_lock);
gboolean proxy_single_object(const char *object_path, GDBusNodeInfo *node_info,
                             gboolean need_lock);
gboolean register_single_interface(const char *object_path,
                                   const char *interface_name,
                                   ProxiedObject *proxied_obj);

gboolean init_proxy_state(const ProxyConfig *config) {
  proxy_state = g_new0(ProxyState, 1);
  if (!proxy_state) {
    log_error("Failed to allocate ProxyState");
    return FALSE;
  }
  g_rw_lock_init(&proxy_state->rw_lock);
  proxy_state->config = *config;
  proxy_state->registered_objects =
      g_hash_table_new_full(g_direct_hash, g_direct_equal, nullptr, g_free);
  proxy_state->signal_subscriptions =
      g_hash_table_new_full(g_direct_hash, g_direct_equal, nullptr, g_free);
  proxy_state->catch_all_subscription_id = 0;
  proxy_state->catch_interfaces_added_subscription_id = 0;
  proxy_state->catch_interfaces_removed_subscription_id = 0;
  proxy_state->proxied_objects = g_hash_table_new_full(
      g_str_hash, g_str_equal, g_free, free_proxied_object);
  proxy_state->node_info_cache = g_hash_table_new_full(
      g_str_hash, g_str_equal, g_free, (GDestroyNotify)g_dbus_node_info_unref);

  // Set up signal handlers
  proxy_state->sigint_source_id =
      g_unix_signal_add(SIGINT, signal_handler, GINT_TO_POINTER(SIGINT));
  proxy_state->sigterm_source_id =
      g_unix_signal_add(SIGTERM, signal_handler, GINT_TO_POINTER(SIGTERM));

  return TRUE;
}

gboolean register_nm_secret_agent() {
  const char *nm_secret_agent_xml = g_getenv("NM_SECRET_AGENT_XML");
  const char *object_path = "/org/freedesktop/NetworkManager/SecretAgent";

  if (!nm_secret_agent_xml) {
    log_error("NM secret agent mode enabled but NM_SECRET_AGENT_XML not set");
    return FALSE;
  }

  if (proxy_state->secret_agent_reg_id != 0) {
    log_error("Secret agent already registered (ID: %u), skipping",
              proxy_state->secret_agent_reg_id);
    return TRUE;
  }

  GError *error = nullptr;
  gchar *interface_xml = nullptr;
  GDBusNodeInfo *info = nullptr;

  if (!g_file_get_contents(nm_secret_agent_xml, &interface_xml, nullptr,
                           &error)) {
    log_error("Failed to read NM secret agent XML from %s: %s",
              nm_secret_agent_xml, error ? error->message : "unknown error");
    g_clear_error(&error);
    return FALSE;
  }

  info = g_dbus_node_info_new_for_xml(interface_xml, &error);
  g_free(interface_xml);

  if (!info) {
    log_error("Failed to parse NM secret agent XML: %s",
              error ? error->message : "unknown error");
    g_clear_error(&error);
    return FALSE;
  }

  if (!info->interfaces || !info->interfaces[0]) {
    log_error("No interfaces found in NM secret agent XML");
    g_dbus_node_info_unref(info);
    return FALSE;
  }

  const char *expected_interface = DBUS_INTERFACE_SECRET_AGENT;
  if (g_strcmp0(info->interfaces[0]->name, expected_interface) != 0) {
    log_verbose("Unexpected interface: %s (expected %s)",
                info->interfaces[0]->name, expected_interface);
  }

  log_info("Registering secret agent interface %s at %s",
           info->interfaces[0]->name, object_path);

  g_hash_table_insert(proxy_state->node_info_cache, g_strdup("secret_agent"),
                      info);

  static const GDBusInterfaceVTable vtable = {.method_call =
                                                  handle_method_call_generic,
                                              .get_property = nullptr,
                                              .set_property = nullptr,
                                              .padding = {nullptr}};

  proxy_state->secret_agent_reg_id = g_dbus_connection_register_object(
      proxy_state->source_bus, object_path, info->interfaces[0], &vtable,
      g_strdup(object_path), g_free, &error);

  if (proxy_state->secret_agent_reg_id == 0) {
    log_error("Failed to register secret agent at %s: %s", object_path,
              error ? error->message : "unknown error");
    g_clear_error(&error);
    g_hash_table_remove(proxy_state->node_info_cache, "secret_agent");
    return FALSE;
  }

  log_info("Secret agent registered: %s at %s (ID: %u)",
           info->interfaces[0]->name, object_path,
           proxy_state->secret_agent_reg_id);

  return TRUE;
}

void unregister_nm_secret_agent() {
  if (proxy_state->secret_agent_reg_id == 0) {
    return; // Not registered
  }

  log_info("Unregistering secret agent (ID: %u)",
           proxy_state->secret_agent_reg_id);

  g_rw_lock_writer_lock(&proxy_state->rw_lock);
  g_dbus_connection_unregister_object(proxy_state->source_bus,
                                      proxy_state->secret_agent_reg_id);
  g_hash_table_remove(proxy_state->node_info_cache, "secret_agent");
  proxy_state->secret_agent_reg_id = 0;
  g_rw_lock_writer_unlock(&proxy_state->rw_lock);
}

gboolean connect_to_buses() {
  GError *error = nullptr;

  proxy_state->source_bus =
      g_bus_get_sync(proxy_state->config.source_bus_type, nullptr, &error);
  if (!proxy_state->source_bus) {
    log_error("Failed to connect to source bus: %s", error->message);
    g_clear_error(&error);
    return FALSE;
  }
  log_info("Connected to source bus (%s)",
           proxy_state->config.source_bus_type == G_BUS_TYPE_SYSTEM
               ? "system"
               : "session");
  if (proxy_state->config.nm_mode) {
    if (!register_nm_secret_agent()) {
      return FALSE;
    }
  }
  proxy_state->target_bus =
      g_bus_get_sync(proxy_state->config.target_bus_type, nullptr, &error);
  if (!proxy_state->target_bus) {
    log_error("Failed to connect to target bus: %s", error->message);
    g_clear_error(&error);
    return FALSE;
  }
  log_info("Connected to target bus (%s)",
           proxy_state->config.target_bus_type == G_BUS_TYPE_SYSTEM
               ? "system"
               : "session");

  return TRUE;
}

gboolean fetch_introspection_data() {
  GError *error = nullptr;

  log_info("Fetching introspection data from %s%s",
           proxy_state->config.source_bus_name,
           proxy_state->config.source_object_path);

  GVariant *xml_variant = g_dbus_connection_call_sync(
      proxy_state->source_bus, proxy_state->config.source_bus_name,
      proxy_state->config.source_object_path, DBUS_INTERFACE_INTROSPECTABLE,
      "Introspect", nullptr, G_VARIANT_TYPE("(s)"), G_DBUS_CALL_FLAGS_NONE, -1,
      nullptr, &error);

  if (!xml_variant) {
    log_error("Introspection failed: %s", error->message);
    g_clear_error(&error);
    return FALSE;
  }

  const char *xml_data;
  g_variant_get(xml_variant, "(&s)", &xml_data);

  log_verbose("Introspection XML received (%zu bytes)", strlen(xml_data));

  proxy_state->introspection_data =
      g_dbus_node_info_new_for_xml(xml_data, &error);
  g_variant_unref(xml_variant);

  if (!proxy_state->introspection_data) {
    log_error("Failed to parse introspection XML: %s", error->message);
    g_clear_error(&error);
    return FALSE;
  }

  log_info("Introspection data parsed successfully");
  return TRUE;
}

gboolean discover_and_proxy_object_tree(const char *base_path,
                                        gboolean need_lock) {
  GError *error = nullptr;
  GDBusNodeInfo *node_info = nullptr;
  gboolean success = FALSE;

  log_info("Discovering object tree starting from: %s", base_path);

  // Get introspection data for this path
  GVariant *xml_variant = g_dbus_connection_call_sync(
      proxy_state->source_bus, proxy_state->config.source_bus_name, base_path,
      DBUS_INTERFACE_INTROSPECTABLE, "Introspect", nullptr,
      G_VARIANT_TYPE("(s)"), G_DBUS_CALL_FLAGS_NONE,
      10000, // 10 second timeout
      nullptr, &error);

  if (!xml_variant) {
    // Some objects might not be introspectable, that's ok
    if (error && error->domain == G_DBUS_ERROR &&
        error->code == G_DBUS_ERROR_UNKNOWN_OBJECT) {
      log_verbose("Object %s does not exist, skipping", base_path);
    } else {
      log_verbose("Could not introspect %s: %s", base_path,
                  error ? error->message : "Unknown error");
    }
    g_clear_error(&error);
    return TRUE; // Continue with other objects
  }

  const char *xml_data;
  g_variant_get(xml_variant, "(&s)", &xml_data);

  log_verbose("Introspection XML for %s (%zu bytes)", base_path,
              strlen(xml_data));

  node_info = g_dbus_node_info_new_for_xml(xml_data, &error);
  g_variant_unref(xml_variant);

  if (!node_info) {
    log_error("Failed to parse introspection XML for %s: %s", base_path,
              error ? error->message : "Unknown");
    g_clear_error(&error);
    return FALSE;
  }

  // Log what we found
  if (proxy_state->config.verbose && node_info->interfaces) {
    for (int i = 0; node_info->interfaces[i]; i++) {
      log_verbose("Found interface: %s", node_info->interfaces[i]->name);
    }
  }

  if (proxy_state->config.verbose && node_info->nodes) {
    for (int i = 0; node_info->nodes[i]; i++) {
      const char *child_name = node_info->nodes[i]->path;
      log_verbose("Found child node: %s",
                  child_name ? child_name : "(unnamed)");
    }
  }

  // Acquire lock if needed
  if (need_lock) {
    g_rw_lock_writer_lock(&proxy_state->rw_lock);
  }

  // Proxy this object if it has interfaces
  if (!proxy_single_object(base_path, node_info, FALSE)) {
    // proxy_single_object failed
    success = FALSE;
    goto cleanup;
  }

  // Release lock before recursion to avoid holding it during slow operations
  if (need_lock) {
    g_rw_lock_writer_unlock(&proxy_state->rw_lock);
  }

  // Recursively handle child nodes
  if (node_info->nodes) {
    for (int i = 0; node_info->nodes[i]; i++) {
      const char *child_name = node_info->nodes[i]->path;

      if (!child_name || child_name[0] == '\0') {
        log_verbose("Skipping unnamed child node");
        continue;
      }

      // Build full child path
      char *child_path;
      if (g_str_has_suffix(base_path, "/")) {
        child_path = g_strdup_printf("%s%s", base_path, child_name);
      } else {
        child_path = g_strdup_printf("%s/%s", base_path, child_name);
      }

      log_verbose("Recursively processing child: %s", child_path);

      // Recurse into child (don't fail if child fails)
      discover_and_proxy_object_tree(child_path,
                                     TRUE); // Need lock for recursive calls
      g_free(child_path);
    }
  }

  success = TRUE;

  // No need to cleanup lock here since we already released it before recursion
  g_dbus_node_info_unref(node_info);
  return success;

cleanup:
  if (need_lock) {
    g_rw_lock_writer_unlock(&proxy_state->rw_lock);
  }
  g_dbus_node_info_unref(node_info);
  return success;
}

void free_proxied_object(gpointer data) {
  ProxiedObject *obj = static_cast<ProxiedObject *>(data);
  if (!obj)
    return;

  g_free(obj->object_path);
  if (obj->node_info) {
    g_dbus_node_info_unref(obj->node_info);
  }
  if (obj->registration_ids) {
    g_hash_table_destroy(obj->registration_ids);
  }
  g_free(obj);
}

gboolean proxy_single_object(const char *object_path, GDBusNodeInfo *node_info,
                             gboolean need_lock) {
  // Validate parameters
  if (!object_path || !node_info) {
    log_error("Invalid parameters to proxy_single_object");
    return FALSE;
  }

  // Early validation before locking
  if (!node_info->interfaces || !node_info->interfaces[0]) {
    log_verbose("Object %s has no interfaces, skipping", object_path);
    return TRUE;
  }

  // Count non-standard interfaces
  guint interface_count = 0;
  for (int i = 0; node_info->interfaces[i]; i++) {
    if (!g_strv_contains(standard_interfaces, node_info->interfaces[i]->name)) {
      interface_count++;
    }
  }

  if (interface_count == 0) {
    log_verbose("Object %s has only standard interfaces, skipping",
                object_path);
    return TRUE;
  }

  log_info("Proxying object %s (%u custom interface%s)", object_path,
           interface_count, interface_count == 1 ? "" : "s");

  if (need_lock) {
    g_rw_lock_writer_lock(&proxy_state->rw_lock);
  }

  // Check for duplicate
  if (g_hash_table_contains(proxy_state->proxied_objects, object_path)) {
    log_verbose("Object %s is already proxied", object_path);
    if (need_lock) {
      g_rw_lock_writer_unlock(&proxy_state->rw_lock);
    }
    return TRUE;
  }

  // Create proxied object structure
  ProxiedObject *proxied_obj = g_new0(ProxiedObject, 1);
  proxied_obj->object_path = g_strdup(object_path);
  proxied_obj->node_info = g_dbus_node_info_ref(node_info);
  proxied_obj->registration_ids =
      g_hash_table_new_full(g_str_hash, g_str_equal, g_free, nullptr);

  // Static vtable (shared across all calls)
  static const GDBusInterfaceVTable vtable = {
      .method_call = handle_method_call_generic,
      .get_property = handle_get_property_generic,
      .set_property = handle_set_property_generic,
      .padding = {nullptr}};

  guint registered_count = 0;

  // Register each interface (except standard ones)
  for (int i = 0; node_info->interfaces[i]; i++) {
    GDBusInterfaceInfo *iface = node_info->interfaces[i];

    // Skip standard D-Bus interfaces
    if (g_strv_contains(standard_interfaces, iface->name)) {
      log_verbose("Skipping standard interface: %s", iface->name);
      continue;
    }

    log_verbose("Registering interface %s on object %s", iface->name,
                object_path);

    GError *error = nullptr;
    guint registration_id = g_dbus_connection_register_object(
        proxy_state->target_bus, object_path, iface, &vtable,
        g_strdup(object_path), // Pass object path as user_data for forwarding
        g_free, &error);

    if (registration_id == 0) {
      log_error("Failed to register interface %s on %s: %s", iface->name,
                object_path, error ? error->message : "Unknown error");
      if (error)
        g_clear_error(&error);
      continue; // Try other interfaces
    }

    registered_count++;

    // Store registration ID
    g_hash_table_insert(proxied_obj->registration_ids, g_strdup(iface->name),
                        GUINT_TO_POINTER(registration_id));

    // Add to global registry for cleanup
    g_hash_table_insert(proxy_state->registered_objects,
                        GUINT_TO_POINTER(registration_id),
                        g_strdup_printf("%s:%s", object_path, iface->name));

    log_verbose("Interface %s registered on %s with ID %u", iface->name,
                object_path, registration_id);
  }

  if (registered_count > 0) {
    // Store the proxied object
    g_hash_table_insert(proxy_state->proxied_objects, g_strdup(object_path),
                        proxied_obj);

    log_info("Successfully proxied object %s with %u interface%s", object_path,
             registered_count, registered_count == 1 ? "" : "s");
  } else {
    // No interfaces registered, clean up
    log_verbose("No custom interfaces registered for %s", object_path);
    free_proxied_object(proxied_obj);
  }

  if (need_lock) {
    g_rw_lock_writer_unlock(&proxy_state->rw_lock);
  }

  return TRUE;
}

gboolean register_single_interface(const char *object_path,
                                   const char *interface_name,
                                   ProxiedObject *proxied_obj) {
  // Skip standard interfaces
  if (g_strv_contains(standard_interfaces, interface_name)) {
    log_verbose("Skipping standard interface: %s", interface_name);
    return TRUE;
  }

  // Need to get interface info - introspect the object
  GError *error = nullptr;
  GVariant *xml_variant = g_dbus_connection_call_sync(
      proxy_state->source_bus, proxy_state->config.source_bus_name, object_path,
      DBUS_INTERFACE_INTROSPECTABLE, "Introspect", nullptr,
      G_VARIANT_TYPE("(s)"), G_DBUS_CALL_FLAGS_NONE, 5000, nullptr, &error);

  if (!xml_variant) {
    log_error("Failed to introspect %s for interface %s: %s", object_path,
              interface_name, error ? error->message : "Unknown");
    if (error)
      g_clear_error(&error);
    return FALSE;
  }

  const char *xml_data;
  g_variant_get(xml_variant, "(&s)", &xml_data);

  GDBusNodeInfo *node_info = g_dbus_node_info_new_for_xml(xml_data, &error);
  g_variant_unref(xml_variant);

  if (!node_info) {
    log_error("Failed to parse introspection XML: %s",
              error ? error->message : "Unknown");
    g_clear_error(&error);
    return FALSE;
  }

  // Find the specific interface
  GDBusInterfaceInfo *iface_info =
      g_dbus_node_info_lookup_interface(node_info, interface_name);

  if (!iface_info) {
    log_error("Interface %s not found in introspection data", interface_name);
    g_dbus_node_info_unref(node_info);
    return FALSE;
  }

  // Register the interface
  static const GDBusInterfaceVTable vtable = {
      .method_call = handle_method_call_generic,
      .get_property = handle_get_property_generic,
      .set_property = handle_set_property_generic,
      .padding = {nullptr}};

  guint registration_id = g_dbus_connection_register_object(
      proxy_state->target_bus, object_path, iface_info, &vtable,
      g_strdup(object_path), g_free, &error);

  if (registration_id == 0) {
    log_error("Failed to register interface %s on %s: %s", interface_name,
              object_path, error ? error->message : "Unknown");
    g_clear_error(&error);
    g_dbus_node_info_unref(node_info);
    return FALSE;
  }

  // Store node_info in global cache (keeps iface_info alive)
  char *cache_key = g_strdup_printf("%s:%s", object_path, interface_name);
  g_hash_table_insert(proxy_state->node_info_cache, cache_key,
                      node_info); // Don't unref - stored in cache

  // Store registration ID
  g_hash_table_insert(proxied_obj->registration_ids, g_strdup(interface_name),
                      GUINT_TO_POINTER(registration_id));

  // Add to global registry
  g_hash_table_insert(proxy_state->registered_objects,
                      GUINT_TO_POINTER(registration_id),
                      g_strdup_printf("%s:%s", object_path, interface_name));

  log_info("Successfully registered interface %s on %s (ID: %u)",
           interface_name, object_path, registration_id);

  return TRUE;
}

// Setup signal forwarding with both catch-all and specific PropertiesChanged
// handling
gboolean setup_signal_forwarding() {
  log_info("Setting up signal forwarding");

  g_rw_lock_writer_lock(&proxy_state->rw_lock);

  // Subscribe to ALL signals from the source bus name
  proxy_state->catch_all_subscription_id = g_dbus_connection_signal_subscribe(
      proxy_state->source_bus,
      proxy_state->config.source_bus_name, // sender (our source service)
      nullptr,                             // interface_name (all interfaces)
      nullptr,                             // method: member (all signals)
      nullptr, // object_path (all paths - we filter in callback)
      nullptr, // arg0 (no filtering)
      G_DBUS_SIGNAL_FLAGS_NONE, on_signal_received_catchall, nullptr, nullptr);

  if (proxy_state->catch_all_subscription_id == 0) {
    log_error("Failed to set up catch-all signal subscription");
    g_rw_lock_writer_unlock(&proxy_state->rw_lock);
    return FALSE;
  }
  g_hash_table_insert(proxy_state->signal_subscriptions,
                      GUINT_TO_POINTER(proxy_state->catch_all_subscription_id),
                      g_strdup("catch-all"));
  log_info("Catch-all signal subscription established (ID: %u)",
           proxy_state->catch_all_subscription_id);

  proxy_state->catch_interfaces_added_subscription_id =
      g_dbus_connection_signal_subscribe(
          proxy_state->source_bus, proxy_state->config.source_bus_name,
          DBUS_INTERFACE_OBJECT_MANAGER, // interface
          DBUS_SIGNAL_INTERFACES_ADDED,  // method: New objects appear
          nullptr,                       // Any object path
          nullptr,                       // No arg0 filtering
          G_DBUS_SIGNAL_FLAGS_NONE, on_interfaces_added, nullptr, nullptr);

  if (proxy_state->catch_interfaces_added_subscription_id == 0) {
    log_error("Failed to set up InterfacesAdded signal subscription");
    g_rw_lock_writer_unlock(&proxy_state->rw_lock);
    return FALSE;
  }
  g_hash_table_insert(
      proxy_state->signal_subscriptions,
      GUINT_TO_POINTER(proxy_state->catch_interfaces_added_subscription_id),
      g_strdup(DBUS_SIGNAL_INTERFACES_ADDED));
  log_info("InterfacesAdded signal subscription established (ID: %u)",
           proxy_state->catch_interfaces_added_subscription_id);

  proxy_state->catch_interfaces_removed_subscription_id =
      g_dbus_connection_signal_subscribe(
          proxy_state->source_bus, proxy_state->config.source_bus_name,
          DBUS_INTERFACE_OBJECT_MANAGER,  // interface
          DBUS_SIGNAL_INTERFACES_REMOVED, // method: Objects removed
          nullptr,                        // Any object path
          nullptr,                        // No arg0 filtering
          G_DBUS_SIGNAL_FLAGS_NONE, on_interfaces_removed, nullptr, nullptr);

  if (proxy_state->catch_interfaces_removed_subscription_id == 0) {
    log_error("Failed to set up InterfacesRemoved signal subscription");
    g_rw_lock_writer_unlock(&proxy_state->rw_lock);
    return FALSE;
  }
  g_hash_table_insert(
      proxy_state->signal_subscriptions,
      GUINT_TO_POINTER(proxy_state->catch_interfaces_removed_subscription_id),
      g_strdup(DBUS_SIGNAL_INTERFACES_REMOVED));
  log_info("InterfacesRemoved signal subscription established (ID: %u)",
           proxy_state->catch_interfaces_removed_subscription_id);
  g_rw_lock_writer_unlock(&proxy_state->rw_lock);
  return TRUE;
}

// Register interfaces
gboolean setup_proxy_interfaces() {
  log_info("Setting up proxy interfaces - discovering full object tree");

  // Set up signal forwarding
  if (!setup_signal_forwarding()) {
    return FALSE;
  }

  // First, proxy the D-Bus daemon interface that clients use for service
  // discovery
  if (!discover_and_proxy_object_tree(DBUS_OBJECT_PATH, TRUE)) {
    log_error("Failed to discover and proxy D-Bus daemon interface");
    return FALSE;
  }

  log_info("Object tree proxying complete - %u objects proxied",
           g_hash_table_size(proxy_state->proxied_objects));

  return TRUE;
}

void on_bus_acquired_for_owner(GDBusConnection *connection, const gchar *name,
                               gpointer user_data G_GNUC_UNUSED) {
  log_info("Bus acquired for name: %s", name ? name : "(none)");
  if (!proxy_state)
    return;

  // Keep a reference to the connection
  if (proxy_state->target_bus) {
    g_object_unref(proxy_state->target_bus);
    proxy_state->target_bus = nullptr;
  }
  proxy_state->target_bus = g_object_ref(connection);

  // Register interfaces & set up signal forwarding
  if (!setup_proxy_interfaces()) {
    log_error("Failed to set up interfaces on target bus");
    if (proxy_state->name_owner_watch_id) {
      g_bus_unown_name(proxy_state->name_owner_watch_id);
      proxy_state->name_owner_watch_id = 0;
    }
  }
}

void on_name_acquired_log(G_GNUC_UNUSED GDBusConnection *conn,
                          const gchar *name, gpointer user_data G_GNUC_UNUSED) {
  log_info("Name successfully acquired: %s", name);
}

void on_name_lost_log(G_GNUC_UNUSED GDBusConnection *conn, const gchar *name,
                      gpointer user_data G_GNUC_UNUSED) {
  log_error("Name lost or failed to acquire: %s", name);
}

// Cleanup function
void cleanup_proxy_state() {
  if (!proxy_state)
    return;

  // Unregister secret agent
    if (proxy_state->config.nm_mode) {
    unregister_nm_secret_agent();
    if (proxy_state->client_sender_name) {
      g_free(proxy_state->client_sender_name);
      proxy_state->client_sender_name = nullptr;
    }
  }
  // Unregister objects
  if (proxy_state->registered_objects) {
    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, proxy_state->registered_objects);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
      g_dbus_connection_unregister_object(proxy_state->target_bus,
                                          GPOINTER_TO_UINT(key));
    }
    g_hash_table_destroy(proxy_state->registered_objects);
  }
  // Unregister interfaces and clean up
  if (proxy_state->node_info_cache) {
    g_hash_table_destroy(proxy_state->node_info_cache);
  }
  // Unsubscribe from catch-all signal
  if (proxy_state->catch_all_subscription_id && proxy_state->source_bus) {
    g_dbus_connection_signal_unsubscribe(
        proxy_state->source_bus, proxy_state->catch_all_subscription_id);
    proxy_state->catch_all_subscription_id = 0;
  }
  // Unsubscribe from InterfacesAdded signal
  if (proxy_state->catch_interfaces_added_subscription_id &&
      proxy_state->source_bus) {
    g_dbus_connection_signal_unsubscribe(
        proxy_state->source_bus,
        proxy_state->catch_interfaces_added_subscription_id);
    proxy_state->catch_interfaces_added_subscription_id = 0;
  }
  // Unsubscribe from InterfacesRemoved signal
  if (proxy_state->catch_interfaces_removed_subscription_id &&
      proxy_state->source_bus) {
    g_dbus_connection_signal_unsubscribe(
        proxy_state->source_bus,
        proxy_state->catch_interfaces_removed_subscription_id);
    proxy_state->catch_interfaces_removed_subscription_id = 0;
  }
  // Clean up individual signal subscriptions (like PropertiesChanged)
  if (proxy_state->signal_subscriptions) {
    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, proxy_state->signal_subscriptions);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
      g_dbus_connection_signal_unsubscribe(proxy_state->source_bus,
                                           GPOINTER_TO_UINT(key));
    }
    g_hash_table_destroy(proxy_state->signal_subscriptions);
  }
  if (proxy_state->proxied_objects) {
    g_hash_table_destroy(proxy_state->proxied_objects);
  }

  if (proxy_state->introspection_data) {
    g_dbus_node_info_unref(proxy_state->introspection_data);
  }

  g_dbus_connection_flush_sync(proxy_state->source_bus, NULL, NULL);
  g_dbus_connection_flush_sync(proxy_state->target_bus, NULL, NULL);

  g_dbus_connection_close_sync(proxy_state->source_bus, NULL, NULL);
  g_dbus_connection_close_sync(proxy_state->target_bus, NULL, NULL);

  if (proxy_state->source_bus) {
    g_object_unref(proxy_state->source_bus);
  }

  if (proxy_state->target_bus) {
    g_object_unref(proxy_state->target_bus);
  }

  g_free(proxy_state->config.source_bus_name);
  g_free(proxy_state->config.proxy_bus_name);
  g_free(proxy_state->config.source_object_path);
  if (proxy_state->name_owner_watch_id) {
    g_bus_unown_name(proxy_state->name_owner_watch_id);
    proxy_state->name_owner_watch_id = 0;
  }

  if (proxy_state->sigint_source_id) {
    g_source_remove(proxy_state->sigint_source_id);
    proxy_state->sigint_source_id = 0;
  }
  if (proxy_state->sigterm_source_id) {
    g_source_remove(proxy_state->sigterm_source_id);
    proxy_state->sigterm_source_id = 0;
  }
  g_rw_lock_clear(&proxy_state->rw_lock);
  g_free(proxy_state);
  proxy_state = nullptr;
}

// Parse bus type from string
GBusType parse_bus_type(const char *bus_str) {
  if (g_strcmp0(bus_str, "system") == 0) {
    return G_BUS_TYPE_SYSTEM;
  } else if (g_strcmp0(bus_str, "session") == 0) {
    return G_BUS_TYPE_SESSION;
  }
  return G_BUS_TYPE_SYSTEM; // Default
}

// Validate required proxy configuration parameters
void validateProxyConfigOrExit(const ProxyConfig *config) {
  if (!config->source_bus_name || config->source_bus_name[0] == '\0') {
    log_error("Error: source_bus_name is required!");
    exit(EXIT_FAILURE);
  }
  if (!config->source_object_path || config->source_object_path[0] == '\0') {
    log_error("Error: source_object_path is required!");
    exit(EXIT_FAILURE);
  }
  if (!config->proxy_bus_name || config->proxy_bus_name[0] == '\0') {
    log_error("Error: proxy_bus_name is required!");
    exit(EXIT_FAILURE);
  }
}
