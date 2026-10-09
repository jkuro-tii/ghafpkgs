/*
 Copyright 2026 TII (CRC) and the Ghaf contributors
 SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/uleds.h>
#include <linux/vm_sockets.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common/log.h"
#include "common/protocol.h"

#define MAX_LEDS (16)
struct proxy_led {
  char *name;
  int max_brightness;
  int fd;
} leds[MAX_LEDS];
static int led_count = 0;
struct pollfd pollfds[MAX_LEDS + 1]; // zero element is fd to the host

// Read exactly len bytes from fd, retrying on EINTR and on short reads.
// Returns len on success, 0 on orderly shutdown before any data was read,
// or -1 on error/unexpected EOF.
static ssize_t read_all(int fd, void *buf, size_t len) {
  size_t total = 0;
  while (total < len) {
    ssize_t n = read(fd, (char *)buf + total, len - total);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (n == 0) {
      return total == 0 ? 0 : -1; // EOF, possibly mid-message
    }
    total += (size_t)n;
  }
  return (ssize_t)total;
}

// Write exactly len bytes to fd, retrying on EINTR and on short writes.
// Returns len on success, -1 on error.
static ssize_t write_all(int fd, const void *buf, size_t len) {
  size_t total = 0;
  while (total < len) {
    ssize_t n = write(fd, (const char *)buf + total, len - total);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    total += (size_t)n;
  }
  return (ssize_t)total;
}

static void cleanup(void) {
  for (int i = 0; i < led_count; i++) {
    if (leds[i].fd >= 0) {
      close(leds[i].fd);
      leds[i].fd = -1;
    }
    free(leds[i].name);
    leds[i].name = NULL;
  }
  close(pollfds[0].fd);
  led_count = 0;
  for (int i = 0; i < MAX_LEDS + 1; i++) {
    pollfds[i].fd = -1;
    pollfds[i].events = 0;
    pollfds[i].revents = 0;
  }
}
static int register_uled(struct proxy_led *led) {
  struct uleds_user_dev dev;
  ssize_t n;
  size_t name_len;

  memset(&dev, 0, sizeof(dev));
  name_len = strlen(led->name);
  memcpy(dev.name, led->name, name_len + 1);
  dev.max_brightness = led->max_brightness;

  led->fd = open("/dev/uleds", O_RDWR | O_CLOEXEC);
  if (led->fd < 0) {
    LOG_ERROR("%s: open(/dev/uleds): %s", led->name, strerror(errno));
    return -1;
  }

  n = write_all(led->fd, &dev, sizeof(dev));
  if (n < 0) {
    LOG_ERROR("%s: write registration: %s", led->name, strerror(errno));
    close(led->fd);
    led->fd = -1;
    return -1;
  }

  return 0;
}

static int guest_uleds_handle_add_led(const struct led_msg_hdr *hdr) {

  // Receive and handle the add LED request from the host.
  // hdr->length is attacker/peer-controlled, so it must be bounds-checked
  // before it is used to size or index a buffer.
  size_t len = hdr->length;
  char buf[LED_NAME_LEN];

  if (len == 0 || len > sizeof(buf)) {
    LOG_ERROR("Invalid LED name length: %zu (must be 1-%zu)", len,
              sizeof(buf));
    return -1;
  }

  if (read_all(pollfds[0].fd, buf, len) <= 0) {
    LOG_ERROR("read: %s", strerror(errno));
    return -1;
  }
  // Ensure buf is always NUL-terminated, regardless of what the peer sent.
  buf[len - 1] = '\0';

  LOG_DEBUG("Received LED name: %s max_brightness:%d", buf,
            hdr->max_brightness);
  if (led_count >= MAX_LEDS) {
    LOG_ERROR("Maximum number of LEDs reached");
    return -1;
  }

  leds[led_count].name = strdup(buf);
  if (leds[led_count].name == NULL) {
    LOG_ERROR("strdup: %s", strerror(errno));
    return -1;
  }
  if (strlen(leds[led_count].name) >= LED_MAX_NAME_SIZE) {
    LOG_ERROR("LED name is too long; maximum is %d characters",
              LED_MAX_NAME_SIZE - 1);
    free(leds[led_count].name);
    leds[led_count].name = NULL;
    return -1;
  }
  leds[led_count].max_brightness = hdr->max_brightness;
  leds[led_count].fd = -1; // Not yet opened
  led_count++;

  // Add LED to /dev/uleds here.
  if (register_uled(&leds[led_count - 1]) < 0) {
    LOG_ERROR("Failed to register LED %s", leds[led_count - 1].name);
    free(leds[led_count - 1].name);
    leds[led_count - 1].name = NULL;
    led_count--;
    return -1;
  }

  return 0;
}

static int read_brightness(int fd) {
  int brightness;
  ssize_t n = read_all(fd, &brightness, sizeof(brightness));

  if (n < 0) {
    LOG_ERROR("read_brightness: %s", strerror(errno));
    return -1;
  }

  if (n != (ssize_t)sizeof(brightness)) {
    LOG_ERROR("short read_brightness: %zd/%zu", n, sizeof(brightness));
    return -1;
  }

  return brightness;
}

static void set_brightness(int led_index, int brightness) {
  // Send brightness update to the host
  struct led_msg_hdr hdr;
  hdr.version = LED_PROXY_VERSION;
  hdr.type = LED_MSG_SET_BRIGHTNESS;
  hdr.led_index = led_index;
  hdr.brightness = brightness;
  if (write_all(pollfds[0].fd, &hdr, sizeof(hdr)) < 0) {
    LOG_ERROR("write brightness to host: %s", strerror(errno));
    return;
  }
  LOG_DEBUG("Sent brightness update for LED %d: %d", led_index, brightness);
}

int guest_uleds_run() {
  // send HELLO message to the host
  struct led_msg_hdr hdr;
  ssize_t bytes_read;

  hdr.version = LED_PROXY_VERSION;
  hdr.type = LED_MSG_HELLO;
  hdr.length = 0;
  if (write_all(pollfds[0].fd, &hdr, sizeof(hdr)) < 0) {
    LOG_ERROR("write to host: %s", strerror(errno));
    return -1;
  }

  // run the uleds event loop
  // wait for events on the pollfds array
  for (;;) {
    int ret =
        poll(pollfds, led_count + 1, -1); // zero element is the host connection

    if (ret < 0) {
      LOG_ERROR("poll: %s", strerror(errno));
      return -1;
    }

    // check for events from the host
    if (pollfds[0].revents & POLLIN) {
      // handle incoming messages from the host here
      bytes_read = read_all(pollfds[0].fd, &hdr, sizeof(hdr));
      if (bytes_read < 0) {
        LOG_ERROR("read: %s", strerror(errno));
        return -1;
      }
      if (bytes_read != (ssize_t)sizeof(hdr)) {
        if (!bytes_read) {
          LOG_DEBUG("Connection closed by host");
          return 0;
        }
        LOG_ERROR("short read: %zd/%zu", bytes_read, sizeof(hdr));
        return -1;
      }
      if (hdr.type == LED_MSG_ADD_LED) {
        if (guest_uleds_handle_add_led(&hdr) < 0) {
          LOG_ERROR("guest_uleds_handle_add_led failed");
          return -1;
        }
        pollfds[led_count].fd = leds[led_count - 1].fd;
        pollfds[led_count].events = POLLIN;
        pollfds[led_count].revents = 0;
      } else {
        LOG_ERROR("Unknown message type: %d", hdr.type);
      }
    }
    for (int i = 1; i < led_count + 1; i++) {
      if (pollfds[i].revents & POLLIN) {
        // handle writable event for LED i here
        int brightness = read_brightness(pollfds[i].fd);
        if (brightness < 0) {
          LOG_ERROR("Failed to read brightness for LED %d (%s)", i,
                    leds[i - 1].name);
        } else {
          LOG_DEBUG("Successfully read brightness for LED %d (%s): %d", i,
                    leds[i - 1].name, brightness);
          set_brightness(i - 1, brightness);
        }
        pollfds[i].revents = 0;
      }
    }
  }

  return 0;
}

int main(int argc, char *argv[]) {
  // get the --cid/--port options
  unsigned int host_cid = VMADDR_CID_HOST;
  unsigned int vsock_port = LED_PROXY_VSOCK_PORT;
  static const struct option long_options[] = {
      {"cid", required_argument, NULL, 'c'},
      {"port", required_argument, NULL, 'p'},
      {"help", no_argument, NULL, 'h'},
      {NULL, 0, NULL, 0}};

  int opt;
  while ((opt = getopt_long(argc, argv, "c:p:h", long_options, NULL)) != -1) {
    switch (opt) {
    case 'c':
      host_cid = (unsigned int)strtoul(optarg, NULL, 10);
      break;
    case 'p':
      vsock_port = (unsigned int)strtoul(optarg, NULL, 10);
      break;
    case 'h':
      fprintf(stderr, "Usage: %s [--cid CID] [--port PORT]\n", argv[0]);
      return 0;
    default:
      fprintf(stderr, "Usage: %s [--cid CID] [--port PORT]\n", argv[0]);
      return 1;
    }
  }

  // open a vsock socket to the host
  int socket_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
  if (socket_fd < 0) {
    LOG_ERROR("socket: %s", strerror(errno));
    return -1;
  }

  struct sockaddr_vm addr;
  memset(&addr, 0, sizeof(addr));
  addr.svm_family = AF_VSOCK;
  addr.svm_cid = host_cid;
  addr.svm_port = vsock_port;

  if (connect(socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    LOG_ERROR("connect: %s", strerror(errno));
    close(socket_fd);
    return -1;
  }

  pollfds[0].fd = socket_fd;
  pollfds[0].events = POLLIN;
  pollfds[0].revents = 0;

  int ret = guest_uleds_run();
  cleanup();
  return ret;
}
