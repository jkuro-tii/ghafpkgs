/*
 Copyright 2026 TII (CRC) and the Ghaf contributors
 SPDX-License-Identifier: Apache-2.0
 */

#include <getopt.h>
#include <linux/vm_sockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "leds.h"
#include "common/protocol.h"


#define LED_SYS_CLASS_PATH "/sys/class/leds/"

static int host_leds_send_list(const int socket_fd, const char **led_names, int led_count) {
    for (int i = 0; i < led_count; i++) {
        // Send each LED name over the socket here.
        fprintf(stderr, "Sending LED name: %s\n", led_names[i]);
        struct led_msg_hdr hdr;
        hdr.version = LED_PROXY_VERSION;
        hdr.type = LED_MSG_LIST;
        hdr.length = strlen(led_names[i]) + 1; // Include null terminator
        if (write(socket_fd, &hdr, sizeof(hdr)) < 0) {
            perror("write");
            return -1;
        }
        if (write(socket_fd, led_names[i], hdr.length) < 0) {
            perror("write");
            return -1;
        }
    }
    return 0;
}

static int host_leds_set(const int socket_fd, const struct led_msg_hdr *hdr) {
    static char buf[256] = LED_SYS_CLASS_PATH; // Buffer to hold the message payload
    size_t prefix_len = strlen(LED_SYS_CLASS_PATH);

    fprintf(stderr, "Handling LED_MSG_SET message\n");

    if (read(socket_fd, buf + prefix_len, sizeof(buf) - prefix_len) < 0) {
        perror("read");
        return -1;
    }


    // extract the LED name and value from the message payload here.
    

    return 0;
}

static int host_leds_handle_client(int client_fd, const char **led_names, int led_count) {
    for (;;)
    {
        struct led_msg_hdr hdr;
        ssize_t bytes_read = read(client_fd, &hdr, sizeof(hdr));
        if (bytes_read <= 0) {
            if (bytes_read < 0) {
                perror("read");
            }
            break;
        }
        if (hdr.type == LED_MSG_HELLO) {
            // send list of all LED interfaces
            if (host_leds_send_list(client_fd, led_names, led_count) < 0) {
                perror("host_leds_send_list");
                break;
            }
            continue;
        }
        if (hdr.type == LED_MSG_SET) {
            // Handle LED_MSG_SET message here.
            fprintf(stderr, "Received LED_MSG_SET message\n");
            if (host_leds_set(client_fd, &hdr) < 0) {
                perror("host_leds_set");
                break;
            }
        }
    }

    return 0;
}

static int host_leds_run(unsigned int vsock_port, unsigned int allowed_cid,
                          const char **led_names, int led_count) {

    int listen_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_vm addr;
    memset(&addr, 0, sizeof(addr));
    addr.svm_family = AF_VSOCK;
    addr.svm_cid = VMADDR_CID_ANY;
    addr.svm_port = vsock_port;

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(listen_fd);
        return -1;
    }

    if (listen(listen_fd, 1) < 0) {
        perror("listen");
        close(listen_fd);
        return -1;
    }

    fprintf(stderr, "Listening for guest connections on vsock port %u\n", vsock_port);

    for (;;) {
        struct sockaddr_vm peer_addr;
        socklen_t peer_len = sizeof(peer_addr);
        int client_fd = accept(listen_fd, (struct sockaddr *)&peer_addr, &peer_len);
        if (client_fd < 0) {
            perror("accept");
            break;
        }

        if (allowed_cid != VMADDR_CID_ANY && peer_addr.svm_cid != allowed_cid) {
            fprintf(stderr, "Rejecting connection from disallowed cid %u\n",
                    peer_addr.svm_cid);
            close(client_fd);
            continue;
        }

        fprintf(stderr, "Accepted connection from cid %u\n", peer_addr.svm_cid);

        host_leds_handle_client(client_fd, led_names, led_count);

        close(client_fd);
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
        {"cid",  required_argument, NULL, 'c'},
        {"help", no_argument,       NULL, 'h'},
        {NULL,   0,                 NULL, 0}
    };

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

    int led_count = argc - optind;
    if (led_count <= 0) {
        fprintf(stderr, "Error: at least one LED name must be specified.\n\n");
        print_usage(argv[0]);
        return 1;
    }

    const char **led_names = (const char **)&argv[optind];

    fprintf(stderr, "Starting host-led-proxy on vsock port %u with %d LED(s):\n",
            vsock_port, led_count);
    for (int i = 0; i < led_count; i++) {
        fprintf(stderr, "  - %s\n", led_names[i]);
    }

    if (host_leds_check_exist(led_names, led_count) != 0) {
        fprintf(stderr, "Error: one or more LED interfaces do not exist under "
                         "%s\n", LEDS_SYSFS_BASE);
        return 1;
    }

    return host_leds_run(vsock_port, allowed_cid, led_names, led_count);
}