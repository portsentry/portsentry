#include "portsentry.h"
#include "stealth_sentry_pcap.h"
#include "listener.h"

int PortSentryStealthModePcap(void) {
  struct ListenerModule *lm = NULL;

  if ((lm = AllocListenerModule()) == NULL) {
    return FALSE;
  }

  InitListenerModule(lm);

  FreeListenerModule(lm);
  return TRUE;
}
