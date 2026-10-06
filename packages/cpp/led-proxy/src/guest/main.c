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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_LEDS (16)
struct proxy_led {
    char *name;
    int max_brightness;
    int fd;
} leds[MAX_LEDS];

// jarekk: TODO: close everything on exit

static int led_count = 0;
struct pollfd pollfds[MAX_LEDS + 1];

#include "common/protocol.h"

static void cleanup() {
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
static int register_uled(struct proxy_led *led)
{
    struct uleds_user_dev dev;
    ssize_t n;
    size_t name_len;

    memset(&dev, 0, sizeof(dev));
    name_len = strlen(led->name);
    memcpy(dev.name, led->name, name_len + 1);
    dev.max_brightness = led->max_brightness;

    led->fd = open("/dev/uleds", O_RDWR | O_CLOEXEC);
    if (led->fd < 0) {
        fprintf(stderr,
                "%s: open(/dev/uleds): %s\n",
                led->name,
                strerror(errno));
        return -1;
    }

    do {
        n = write(led->fd, &dev, sizeof(dev));
    } while (n < 0 && errno == EINTR);

    if (n < 0) {
        fprintf(stderr,
                "%s: write registration: %s\n",
                led->name,
                strerror(errno));
        close(led->fd);
        led->fd = -1;
        return -1;
    }

    if (n != (ssize_t)sizeof(dev)) {
        fprintf(stderr,
                "%s: short registration write: %zd/%zu\n",
                led->name,
                n,
                sizeof(dev));
        close(led->fd);
        led->fd = -1;
        return -1;
    }

    return 0;
}

static int guest_uleds_handle_add_led(const struct led_msg_hdr *hdr) {

    // Receive and handle the add LED request from the host
    size_t len = hdr->length;
    char buf[len];  

    if (read(pollfds[0].fd, buf, len) < 0) {
        perror("read");
        return -1;
    }
    fprintf(stderr, "Received LED name: %s max_brightness:%d\n", buf, hdr->payload[0]);
    if (led_count >= MAX_LEDS) {
        fprintf(stderr, "Maximum number of LEDs reached\n");
        return -1;
    }

    leds[led_count].name = strdup(buf);
    if (strlen(leds[led_count].name) >= LED_MAX_NAME_SIZE ) {
        fprintf(stderr, "LED name is too long; maximum is %d characters\n", LED_MAX_NAME_SIZE - 1);
        free(leds[led_count].name);
        return -1;
    }
    leds[led_count].max_brightness = hdr->payload[0];
    leds[led_count].fd = -1; // Not yet opened
    led_count++;

    // Add LED to /dev/uleds here. This typically involves opening the corresponding device file and storing the file descriptor in leds[led_count].fd.
    if (register_uled(&leds[led_count - 1]) < 0) {
        fprintf(stderr, "Failed to register LED %s\n", leds[led_count - 1].name);
        free(leds[led_count - 1].name);
        led_count--;
        return -1;
    }

    return 0;
}

int guest_uleds_run() {
    // send HELLO message to the host
    struct led_msg_hdr hdr;
    hdr.version = LED_PROXY_VERSION;
    hdr.type = LED_MSG_HELLO;
    hdr.length = 0;
    if (write(pollfds[0].fd, &hdr, sizeof(hdr)) < 0) {
        perror("write to host");
        return -1;
    }

    // run the uleds event loop
    // wait for events on the pollfds array
    for (;;) {
        // handle incoming messages from the host here
        struct led_msg_hdr hdr;
        fprintf(stderr, "poll led_count: %d\n", led_count);
        int ret = poll(pollfds, led_count+1, -1);
        fprintf(stderr, "poll returned: %d\n", ret);
        if (ret < 0) {
            perror("poll");
            return -1;
        }

        for (int i = 0; i < led_count+1; i++) {
            // check for events from the host via the pollfds array
            if (pollfds[0].revents & POLLIN) {
                ssize_t bytes_read = read(pollfds[0].fd, &hdr, sizeof(hdr));
                if (bytes_read < 0) {
                    perror("read");
                    return -1;
                }            
                if (hdr.type == LED_MSG_ADD_LED) {
                    if (guest_uleds_handle_add_led(&hdr) < 0) {
                        perror("guest_uleds_handle_add_led");
                        return -1;
                    }
                    pollfds[led_count].fd = leds[led_count - 1].fd;
                    pollfds[led_count].events = POLLIN;
                    pollfds[led_count].revents = 0;
                } else  {   
                    fprintf(stderr, "Unknown message type: %d\n", hdr.type);
                }
            }

            if (pollfds[i].revents & POLLOUT) {
                // handle writable event for LED i here
                fprintf(stderr, "LED %d (%s) is being written to (fd=%d)\n", i, leds[i].name, pollfds[i].fd);
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
        {"cid",  required_argument, NULL, 'c'},
        {"port", required_argument, NULL, 'p'},
        {"help", no_argument,       NULL, 'h'},
        {NULL,   0,                 NULL, 0}
    };

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
        perror("socket");
        return -1;
    }

    struct sockaddr_vm addr;
    memset(&addr, 0, sizeof(addr));
    addr.svm_family = AF_VSOCK;
    addr.svm_cid = host_cid;
    addr.svm_port = vsock_port;

    if (connect(socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
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