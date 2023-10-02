#include <string.h>

#include "config.h"
#include "config_data.h"
#include "io.h"
#include "portsentry.h"
#include "state_machine.h"
#include "util.h"

static char gblScanDetectHost[MAXSTATE][IPMAXBUF];
static int gblScanDetectCount = 0;

/* our cheesy state engine to monitor who has connected here before */
int CheckStateEngine(char *target) {
  int count = 0, scanDetectTrigger = TRUE;
  int gotOne = 0;

  /* This is the rather basic scan state engine. It maintains     */
  /* an array of past hosts who triggered a connection on a port */
  /* when a new host arrives it is compared against the array */
  /* if it is found in the array it increments a state counter by */
  /* one and checks the remainder of the array. It does this until */
  /* the end is reached or the trigger value has been exceeded */
  /* This would probably be better as a linked list/hash table, */
  /* but for the number of hosts we are tracking this is just as good. */
  /* This will probably change in the future */

  gotOne = 1;               /* our flag counter if we get a match */
  scanDetectTrigger = TRUE; /* set to TRUE until set otherwise */

  if (configData.configTriggerCount > 0) {
    for (count = 0; count < MAXSTATE; count++) {
      /* if the array has the IP address then increment the gotOne counter and
       */
      /* check the trigger value. If it is exceeded break out of the loop and */
      /* set the detecttrigger to TRUE */
      if (strcmp(gblScanDetectHost[count], target) == 0) {
        /* compare the number of matches to the configured trigger value */
        /* if we've exceeded we can stop this noise */
        if (++gotOne >= configData.configTriggerCount) {
          scanDetectTrigger = TRUE;
          Debug("CheckStateEngine: host: %s has exceeded trigger value: %d", gblScanDetectHost[count], configData.configTriggerCount);
          break;
        }
      } else {
        scanDetectTrigger = FALSE;
      }
    }

    /* now add the fresh meat into the state engine */
    /* if our array is still less than MAXSTATE large add it to the end */
    if (gblScanDetectCount < MAXSTATE) {
      SafeStrncpy(gblScanDetectHost[gblScanDetectCount], target, IPMAXBUF);
      gblScanDetectCount++;
    } else {
      /* otherwise tack it to the beginning and start overwriting older ones */
      gblScanDetectCount = 0;
      SafeStrncpy(gblScanDetectHost[gblScanDetectCount], target, IPMAXBUF);
      gblScanDetectCount++;
    }

    for (count = 0; count < MAXSTATE; count++)
      Debug("CheckStateEngine: state engine host: %s -> position: %d Detected: %d", gblScanDetectHost[count], count, scanDetectTrigger);
    /* end catch to set state if configData.configTriggerCount == 0 */
    if (gotOne >= configData.configTriggerCount)
      scanDetectTrigger = TRUE;
  }

  if (configData.configTriggerCount > MAXSTATE) {
    Log("securityalert: WARNING: Trigger value %d is larger than state engine capacity of %d.", configData.configTriggerCount, MAXSTATE);
    Log("Adjust the value lower or recompile with a larger state engine value.", MAXSTATE);
    Log("securityalert: Blocking host anyway because of invalid trigger value");
    scanDetectTrigger = TRUE;
  }
  return (scanDetectTrigger);
}
