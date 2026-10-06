/*
 Copyright 2026 TII (CRC) and the Ghaf contributors
 SPDX-License-Identifier: Apache-2.0
 */

#ifndef HOST_LEDS_H
#define HOST_LEDS_H
#include <stdint.h>

#define LEDS_SYSFS_BASE "/sys/class/leds"
#define LED_NAME_MAX 128
struct proxy_led {
    uint32_t id;
    char name[LED_NAME_MAX];

    int brightness_fd;
    unsigned int brightness;
    unsigned int max_brightness;
};

/* Checks that /sys/class/leds/<led_name> exists and is a directory
 * for every entry in led_names.
 *
 * Returns 0 if all LEDs exist, non-zero if any are missing.
 */
int host_leds_check_exist(const char **led_names, int led_count);

#endif /* HOST_LEDS_H */