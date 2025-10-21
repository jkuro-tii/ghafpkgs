/* Shared header for dbus-proxy split files */
#ifndef GHAF_DBUS_PROXY_H
#define GHAF_DBUS_PROXY_H

#include "./gdbusprivate.h"
#include <gio/gio.h>
#include <glib.h>

// Configuration structure
typedef struct {
  gchar *source_bus_name;
  gchar *source_object_path;
  gchar *proxy_bus_name;
  GBusType source_bus_type;
  GBusType target_bus_type;
  gboolean nm_mode;
  gboolean verbose;
  gboolean info;
} ProxyConfig;

// Forward declarations
typedef struct ProxiedObject ProxiedObject;
typedef struct {
  GDBusConnection *source_bus;
  GDBusConnection *target_bus;
  GDBusNodeInfo *introspection_data;
  GHashTable *registered_objects;
  GHashTable *signal_subscriptions;
  ProxyConfig config;
  guint secret_agent_reg_id;
  gchar *client_sender_name;
  guint name_owner_watch_id;
  guint source_service_watch_id;
  guint catch_all_subscription_id;
  guint catch_interfaces_added_subscription_id;
  guint catch_interfaces_removed_subscription_id;
  GHashTable *proxied_objects;
  GHashTable *node_info_cache;
  GRWLock rw_lock;
  guint sigint_source_id;
  guint sigterm_source_id;
  GMainLoop *main_loop;
} ProxyState;

struct ProxiedObject {
  char *object_path;
  GDBusNodeInfo *node_info;
  GHashTable *registration_ids;
};

extern ProxyState *proxy_state;

/* Logging */
void log_verbose(const char *format, ...) G_GNUC_PRINTF(1, 2);
void log_error(const char *format, ...) G_GNUC_PRINTF(1, 2);
void log_info(const char *format, ...) G_GNUC_PRINTF(1, 2);

/* Initialization / cleanup */
gboolean init_proxy_state(const ProxyConfig *config);
void cleanup_proxy_state(void);

/* Bus / introspection */
gboolean connect_to_buses(void);
gboolean fetch_introspection_data(void);

/* Discovery / proxying */
gboolean discover_and_proxy_object_tree(const char *base_path,
                                        gboolean need_lock);
gboolean proxy_single_object(const char *object_path, GDBusNodeInfo *node_info,
                             gboolean need_lock);
gboolean register_single_interface(const char *object_path,
                                   const char *interface_name,
                                   ProxiedObject *proxied_obj);
void update_object_with_new_interfaces(const char *object_path,
                                       GVariant *interfaces_dict);

/* Signal handlers and method/property handlers */
gboolean signal_handler(void *user_data);
void on_signal_received_catchall(GDBusConnection *connection,
                                 const char *sender_name,
                                 const char *object_path,
                                 const char *interface_name,
                                 const char *signal_name, GVariant *parameters,
                                 gpointer user_data);
void on_interfaces_added(GDBusConnection *connection, const char *sender_name,
                         const char *object_path, const char *interface_name,
                         const char *signal_name, GVariant *parameters,
                         gpointer user_data);
void on_interfaces_removed(GDBusConnection *connection, const char *sender_name,
                           const char *object_path, const char *interface_name,
                           const char *signal_name, GVariant *parameters,
                           gpointer user_data);

/* Other callbacks used across files */
void on_bus_acquired_for_owner(GDBusConnection *connection, const gchar *name,
                               gpointer user_data G_GNUC_UNUSED);
void on_name_acquired_log(GDBusConnection *conn, const gchar *name,
                          gpointer user_data G_GNUC_UNUSED);
void on_name_lost_log(GDBusConnection *conn, const gchar *name,
                      gpointer user_data G_GNUC_UNUSED);
void on_service_vanished(GDBusConnection *connection, const gchar *name,
                         gpointer user_data G_GNUC_UNUSED);

/* Standard D-Bus interfaces list (defined in one .cpp) */
extern const char *standard_interfaces[];

/* Method/property handlers used by vtables */
void handle_method_call_generic(GDBusConnection *connection, const char *sender,
                                const char *object_path,
                                const char *interface_name,
                                const char *method_name, GVariant *parameters,
                                GDBusMethodInvocation *invocation,
                                gpointer user_data);
GVariant *handle_get_property_generic(G_GNUC_UNUSED GDBusConnection *connection,
                                      const char *sender,
                                      const char *object_path,
                                      const char *interface_name,
                                      const char *property_name, GError **error,
                                      gpointer user_data);
gboolean handle_set_property_generic(G_GNUC_UNUSED GDBusConnection *connection,
                                     const char *sender,
                                     const char *object_path,
                                     const char *interface_name,
                                     const char *property_name, GVariant *value,
                                     GError **error, gpointer user_data);

/* NM secret agent registration */
gboolean register_nm_secret_agent(void);
void unregister_nm_secret_agent(void);

/* Utilities */
GBusType parse_bus_type(const char *bus_str);
void validateProxyConfigOrExit(const ProxyConfig *config);

#endif // GHAF_DBUS_PROXY_H
