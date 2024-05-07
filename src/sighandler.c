#include <signal.h>
#include <stdint.h>

#include "portsentry.h"

extern uint8_t g_isRunning;

void ExitSignalHandler(int signum);

int SetupSignalHandlers(void) {
  struct sigaction sa;
  signal(SIGPIPE, SIG_IGN);

  sa.sa_handler = ExitSignalHandler;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);

  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  return TRUE;
}

void ExitSignalHandler(int signum) {
  (void)signum;
  g_isRunning = FALSE;
}
