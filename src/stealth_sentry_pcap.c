#include <stdlib.h>
#include <poll.h>

#include "portsentry.h"
#include "stealth_sentry_pcap.h"
#include "listener.h"
#include "device.h"
#include "io.h"
#include "util.h"

#define POLL_TIMEOUT -1

int PortSentryStealthModePcap(void) {
  int status = TRUE, ret, nfds = 0, i;
  char err[ERRNOMAXBUF];
  struct ListenerModule *lm = NULL;
  struct pollfd *fds = NULL;
  struct Device *current = NULL;

  if ((lm = AllocListenerModule()) == NULL) {
    status = FALSE;
    goto exit;
  }

  if (InitListenerModule(lm) == FALSE) {
    status = FALSE;
    goto exit;
  }

  if ((fds = SetupPollFds(lm, &nfds)) == NULL) {
    Error("Unable to allocate memory for pollfd");
    status = FALSE;
    goto exit;
  }

  while (1) {
    ret = poll(fds, nfds, POLL_TIMEOUT);

    if (ret == -1) {
      Error("poll() failed %s", ErrnoString(err, sizeof(err)));
      status = FALSE;
      goto exit;
    } else if (ret == 0) {
      continue;
    }

    for (i = 0; i < nfds; i++) {
      if (fds[i].revents & POLLIN) {
        if ((current = GetDeviceByFd(lm, fds[i].fd)) == NULL) {
          Error("Unable to find device by fd %d", fds[i].fd);
          status = FALSE;
          goto exit;
        }
        Verbose("Packet received on %s", current->name);
        ret = pcap_dispatch(current->handle, -1, HandlePacket, NULL);
      }
    }
  }

  status = TRUE;

exit:
  if (fds)
    free(fds);
  if (lm)
    FreeListenerModule(lm);
  return status;
}
