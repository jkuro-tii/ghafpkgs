/*
 Copyright 2026 TII (CRC) and the Ghaf contributors
 SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "common/log.h"

volatile sig_atomic_t stop_requested = 0;

void signal_handler(int signo) {
  (void)signo;
  LOG_DEBUG("Signal received, stopping...");
  stop_requested = 1;
}

int install_signal_handlers(void) {
  struct sigaction sa;

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = signal_handler;
  sigemptyset(&sa.sa_mask);

  if (sigaction(SIGINT, &sa, NULL) < 0) {
    perror("sigaction(SIGINT)");
    return -1;
  }

  if (sigaction(SIGTERM, &sa, NULL) < 0) {
    perror("sigaction(SIGTERM)");
    return -1;
  }

  return 0;
}
