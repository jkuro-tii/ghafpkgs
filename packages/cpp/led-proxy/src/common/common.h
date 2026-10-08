/*
 Copyright 2026 TII (CRC) and the Ghaf contributors
 SPDX-License-Identifier: Apache-2.0
 */
#ifndef COMMON_H
#define COMMON_H
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern volatile sig_atomic_t stop_requested;

void signal_handler(int signo);
int install_signal_handlers(void);

#endif // COMMON_H
