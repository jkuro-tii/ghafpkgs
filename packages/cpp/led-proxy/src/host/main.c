/*
 Copyright 2026 TII (CRC) and the Ghaf contributors
 SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <getopt.h>
#include <linux/vm_sockets.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common/common.h"
#include "common/log.h"
#include "common/protocol.h"
#include "leds.h"

#define LED_SYS_CLASS_PATH "/sys/class/leds/"

int led_count = 0;
char **led_names = NULL;

int get_max_brightness(const char *led_name) {

  char path[256];

  snprintf(path, sizeof(path), LED_SYS_CLASS_PATH "%s/max_brightness",
           led_name);
  FILE *f = fopen(path, "r");
  if (!f) {
    LOG_ERROR("fopen: %s", strerror(errno));
    return 255;
  }
  int brightness;
  if (fscanf(f, "%d", &brightness) != 1) {
    LOG_ERROR("fscanf: %s", strerror(errno));
    fclose(f);
    return 255;
  }
  fclose(f);
  return brightness;
}

static int host_leds_send_list(const int socket_fd) {
  for (int i = 0; i < led_count; i++) {
    // Send each LED name over the socket here.
    LOG_DEBUG("Sending LED name: %s", led_names[i]);
    struct led_msg_hdr hdr;
    hdr.version = LED_PROXY_VERSION;
    hdr.type = LED_MSG_ADD_LED;
    hdr.length = strlen(led_names[i]) + 1; // Include null terminator
    hdr.max_brightness = get_max_brightness(led_names[i]);
    if (write(socket_fd, &hdr, sizeof(hdr)) < 0) {
      LOG_ERROR("write: %s", strerror(errno));
      return -1;
    }
    if (write(socket_fd, led_names[i], hdr.length) < 0) {
      LOG_ERROR("write: %s", strerror(errno));
      return -1;
    }
  }
  return 0;
}

static int host_leds_set(const struct led_msg_hdr *hdr) {
  static char buf[256] =
      LED_SYS_CLASS_PATH; // Buffer to hold the message payload
  size_t prefix_len = strlen(LED_SYS_CLASS_PATH);

  LOG_DEBUG("Handling LED_MSG_SET_BRIGHTNESS message");
  if (hdr->led_index >= led_count) {
    extern int led_count;
    extern char **led_names;

    if (hdr->led_index >= led_count) {
      LOG_ERROR("Invalid LED index: %u", hdr->led_index);
      return -1;
    }
  }

  sprintf(buf + prefix_len, "%s/brightness", led_names[hdr->led_index]);

  FILE *f = fopen(buf, "w");
  if (!f) {
    LOG_ERROR("fopen: %s", strerror(errno));
    return -1;
  }
  fprintf(f, "%d\n", hdr->brightness);
  fclose(f);

  return 0;
}

static void *host_leds_handle_client(void *arg) {
  struct led_msg_hdr hdr;
  ssize_t bytes_read;

  int client_fd = (int)(intptr_t)arg;
  for (;;) {
    do {
      bytes_read = read(client_fd, &hdr, sizeof(hdr));
    } while (bytes_read < 0 && errno == EINTR && !stop_requested);
    if (stop_requested) {
      LOG_DEBUG("Stop requested, exiting client handler");
      goto exit;
    }
    if (bytes_read <= 0) {
      if (bytes_read < 0) {
        LOG_ERROR("read: %s", strerror(errno));
      }
      LOG_DEBUG("Connection closed by client");
      goto exit;
    }
    // check protocol version
    if (hdr.version != LED_PROXY_VERSION) {
      LOG_ERROR("Unsupported protocol version: %u", hdr.version);
      goto exit;
    }

    switch (hdr.type) {
    case LED_MSG_HELLO:
      if (host_leds_send_list(client_fd) < 0) {
        LOG_ERROR("host_leds_send_list failed");
        goto exit;
      }
      break;

    case LED_MSG_SET_BRIGHTNESS:
      // Handle LED_MSG_SET_BRIGHTNESS message here.
      LOG_DEBUG("Received LED_MSG_SET_BRIGHTNESS message for LED index %u [%s] "
                "with brightness %d",
                hdr.led_index, led_names[hdr.led_index], hdr.brightness);
      if (host_leds_set(&hdr) < 0) {
        LOG_ERROR("host_leds_set failed");
        goto exit;
      }
      break;

    case LED_MSG_EXIT:
      LOG_DEBUG("Received LED_MSG_EXIT message");
      goto exit;

    default:
      LOG_ERROR("Unknown message type: %u", hdr.type);
      break;
    }
  }

exit:
  close(client_fd);
  return NULL;
}

static int host_leds_run(unsigned int vsock_port, unsigned int allowed_cid) {

  int listen_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
  if (listen_fd < 0) {
    LOG_ERROR("socket: %s", strerror(errno));
    return -1;
  }

  struct sockaddr_vm addr;
  memset(&addr, 0, sizeof(addr));
  addr.svm_family = AF_VSOCK;
  addr.svm_cid = VMADDR_CID_ANY;
  addr.svm_port = vsock_port;

  if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    LOG_ERROR("bind: %s", strerror(errno));
    close(listen_fd);
    return -1;
  }

  if (listen(listen_fd, SOMAXCONN) < 0) {
    LOG_ERROR("listen: %s", strerror(errno));
    close(listen_fd);
    return -1;
  }

  LOG_DEBUG("Listening for guest connections on vsock port %u", vsock_port);

  for (;;) {
    struct sockaddr_vm peer_addr;
    socklen_t peer_len = sizeof(peer_addr);
    int client_fd = accept(listen_fd, (struct sockaddr *)&peer_addr, &peer_len);
    if (stop_requested) {
      close(listen_fd);
      LOG_DEBUG("Stop requested, exiting accept loop");
      break;
    }
    if (client_fd < 0) {
      LOG_ERROR("accept: %s", strerror(errno));
      break;
    }

    if (allowed_cid != VMADDR_CID_ANY && peer_addr.svm_cid != allowed_cid) {
      LOG_ERROR("Rejecting connection from disallowed cid %u",
                peer_addr.svm_cid);
      close(client_fd);
      continue;
    }

    LOG_DEBUG("Accepted connection from cid %u", peer_addr.svm_cid);

    pthread_t thread;
    if (pthread_create(&thread, NULL, host_leds_handle_client,
                       (void *)(intptr_t)client_fd) != 0) {
      LOG_ERROR("pthread_create: %s", strerror(errno));
      close(client_fd);
      continue;
    }
    pthread_detach(thread);
  }

  close(listen_fd);

  return 0;
}

static void print_usage(const char *prog_name) {
  fprintf(stderr,
          "Usage: %s [--port PORT] [--cid CID] LED_NAME [LED_NAME ...]\n"
          "\n"
          "Options:\n"
          "  -p, --port PORT     vsock port to listen on "
          "(default: %d)\n"
          "  -c, --cid CID       Only accept connections from this guest "
          "cid (default: any)\n"
          "  -h, --help          Show this help message\n"
          "\n"
          "Example:\n"
          "  %s --port %d \\\n"
          "      tpacpi::kbd_backlight \\\n"
          "      platform::mute \\\n"
          "      platform::micmute\n",
          prog_name, LED_PROXY_VSOCK_PORT, prog_name, LED_PROXY_VSOCK_PORT);
}

int main(int argc, char *argv[]) {
  unsigned int vsock_port = LED_PROXY_VSOCK_PORT;
  unsigned int allowed_cid = VMADDR_CID_ANY;

  static const struct option long_options[] = {
      {"port", required_argument, NULL, 'p'},
      {"cid", required_argument, NULL, 'c'},
      {"help", no_argument, NULL, 'h'},
      {NULL, 0, NULL, 0}};

  int opt;
  while ((opt = getopt_long(argc, argv, "p:c:h", long_options, NULL)) != -1) {
    switch (opt) {
    case 'p':
      vsock_port = (unsigned int)strtoul(optarg, NULL, 10);
      break;
    case 'c':
      allowed_cid = (unsigned int)strtoul(optarg, NULL, 10);
      break;
    case 'h':
      print_usage(argv[0]);
      return 0;
    default:
      print_usage(argv[0]);
      return 1;
    }
  }

  led_count = argc - optind;
  if (led_count <= 0) {
    LOG_ERROR("at least one LED name must be specified");
    print_usage(argv[0]);
    return 1;
  }

  led_names = (char **)&argv[optind];

  LOG_DEBUG("Starting host-led-proxy on vsock port %u with %d LED(s):",
            vsock_port, led_count);
  for (int i = 0; i < led_count; i++) {
    LOG_DEBUG("  - %s", led_names[i]);
  }

  if (host_leds_check_exist() != 0) {
    LOG_ERROR("one or more LED interfaces do not exist under %s",
              LEDS_SYSFS_BASE);
    return 1;
  }

  install_signal_handlers();
  int ret = host_leds_run(vsock_port, allowed_cid);
  return ret;
}
