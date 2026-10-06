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
    const char *name;
    int max_brightness;
    int fd;
} leds[MAX_LEDS];

static int led_count = 0;

#include "common/protocol.h"

static int guest_uleds_handle_add_led(const int socket_fd, const struct led_msg_hdr *hdr) {

    // Receive and handle the add LED request from the host
    if (led_count >= MAX_LEDS) {
        fprintf(stderr, "Maximum number of LEDs reached\n");
        return -1;
    }
    size_t len = hdr->length;
    char buf[len];  
    if (read(socket_fd, buf, len) < 0) {
        perror("read");
        return -1;
    }
    fprintf(stderr, "Received LED name: %s max_brightness:%d\n", buf, hdr->payload[0]);
    leds[led_count].name = strdup(buf);
    leds[led_count].max_brightness = 255; // Default max brightness
    leds[led_count].fd = -1; // Not yet opened
    led_count++;

    return 0;
}

int guest_uleds_run(const int socket_fd) {
    // send HELLO message to the host
    struct led_msg_hdr hdr;
    hdr.version = LED_PROXY_VERSION;
    hdr.type = LED_MSG_HELLO;
    hdr.length = 0;
    if (write(socket_fd, &hdr, sizeof(hdr)) < 0) {
        perror("write");
        return -1;
    }

    // run the uleds event loop
    for (;;) {
        // handle incoming messages from the host here
        struct led_msg_hdr hdr;
        ssize_t bytes_read = read(socket_fd, &hdr, sizeof(hdr));
        if (bytes_read < 0) {
            perror("read");
            return -1;
        }
        if (hdr.type == LED_MSG_ADD_LED) {
            // handle LED_MSG_ADD_LED message here
            if (guest_uleds_handle_add_led(socket_fd, &hdr) < 0) {
                perror("guest_uleds_handle_add_led");
                return -1;
            }
        }
        // jarekk: delete?
        // if (hdr.type == LED_MSG_SET) {
        //     // handle LED_MSG_SET message here
        //     if (guest_uleds_handle_set(socket_fd, &hdr) < 0) {
        //         perror("guest_uleds_handle_set");
        //         break;
        //     }
        // }
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

    return guest_uleds_run(socket_fd);
}