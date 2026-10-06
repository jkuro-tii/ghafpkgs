// SPDX-FileCopyrightText: 2022-2026 TII (CRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

#include "leds.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

int host_leds_check_exist(const char **led_names, int led_count) {
    int all_ok = 1;

    for (int i = 0; i < led_count; i++) {
        char path[512];
        int written = snprintf(path, sizeof(path), "%s/%s", LEDS_SYSFS_BASE,
                                led_names[i]);
        if (written < 0 || (size_t)written >= sizeof(path)) {
            fprintf(stderr, "Error: LED name too long: %s\n", led_names[i]);
            all_ok = 0;
            continue;
        }

        struct stat st;
        if (stat(path, &st) != 0) {
            fprintf(stderr, "Error: LED interface not found: %s\n", path);
            all_ok = 0;
            continue;
        }

        if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "Error: LED path is not a directory: %s\n", path);
            all_ok = 0;
            continue;
        }
    }

    return all_ok ? 0 : 1;
}
