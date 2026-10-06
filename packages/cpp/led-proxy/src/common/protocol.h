/*
 Copyright 2026 TII (CRC) and the Ghaf contributors
 SPDX-License-Identifier: Apache-2.0
 */

#ifndef COMMON_PROTOCOL_H
#define COMMON_PROTOCOL_H
#include <stdint.h>

#define LED_PROXY_VERSION 1
#define LED_NAME_LEN 64

/* Default vsock port the host-led-proxy listens on and the
 * guest-led-proxy connects to. */
#define LED_PROXY_VSOCK_PORT 9999

enum led_msg_type {
    LED_MSG_HELLO = 1,
    LED_MSG_ADD_LED,
    LED_MSG_SET_BRIGHTNESS,
    LED_MSG_UPDATE,
    LED_MSG_ERROR,
};

struct led_msg_hdr {
    uint16_t version;
    uint16_t type;
    union {
        struct {
            uint16_t length;
            uint8_t max_brightness;
        };
        struct {
            uint8_t led_index;
            uint8_t brightness;
        };
    };

};
#endif // COMMON_PROTOCOL_H