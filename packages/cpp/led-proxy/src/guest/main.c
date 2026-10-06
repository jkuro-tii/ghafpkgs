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

struct proxy_led {
    const char *name;
    int max_brightness;
    int fd;
};

#include "common/protocol.h"

static int guest_uleds_handle_list(const int socket_fd, const struct led_msg_hdr *hdr) {
    // Implement the handling of LED_MSG_LIST message here
    // For now, just return 0 to indicate success
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
        if (hdr.type == LED_MSG_LIST) {
            // handle LED_MSG_LIST message here
            if (guest_uleds_handle_list(socket_fd, &hdr) < 0) {
                perror("guest_uleds_handle_list");
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