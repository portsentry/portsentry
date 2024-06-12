#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netdb.h>

#include "portsentry.h"
#include "listener.h"
#include "config_data.h"
#include "io.h"
#include "util.h"
#include "device.h"

#define BUFFER_TIMEOUT 2000

pcap_t *PcapOpenLiveImmediate(const char *source, int snaplen, int promisc, int to_ms, char *errbuf);
static uint8_t CreateAndAddDevice(struct ListenerModule *lm, const char *name);
static int AutoPrepDevices(struct ListenerModule *lm, uint8_t includeLo);
static int PrepDevices(struct ListenerModule *lm);
// static void PrintPacket(const u_char *interface, const struct pcap_pkthdr *header, const u_char *packet);
static int SetupFilter(struct Device *device);
static char *ReallocFilter(char *filter, int newLen);
static char *ReallocAndAppend(char *filter, int *filterLen, const char *append, ...);
static char *AllocAndBuildPcapFilter(struct Device *device);
static void PrintDevices(const struct ListenerModule *lm);

/* Heavily inspired by src/lib/libpcap/pcap-bpf.c from OpenBSD's pcap implementation.
 * We must use pcap_create() and pcap_activate() instead of pcap_open_live() because
 * we need to set the immediate mode flag, which can only be done on an unactivated
 * pcap_t.
 *
 * OpenBSD's libpcap implementation require immediate mode and non-blocking socket
 * in order for poll() (and select()/kevent()) to work properly. This approach works
 * for other Unixes as well, so it's no harm in doing it this way. Using immediate mode
 * with a non-blocking fd makes pcap a bit snappier anyway so it's a win-win.
 * See: https://marc.info/?l=openbsd-tech&m=169878430118943&w=2 for more information.
 * */
pcap_t *PcapOpenLiveImmediate(const char *source, int snaplen, int promisc, int to_ms, char *errbuf) {
  pcap_t *p;
  int status;

  if ((p = pcap_create(source, errbuf)) == NULL)
    return (NULL);
  if ((status = pcap_set_snaplen(p, snaplen)) < 0)
    goto fail;
  if ((status = pcap_set_promisc(p, promisc)) < 0)
    goto fail;
  if ((status = pcap_set_timeout(p, to_ms)) < 0)
    goto fail;
  if ((status = pcap_set_immediate_mode(p, 1)) < 0)
    goto fail;

  if ((status = pcap_activate(p)) < 0)
    goto fail;
  return (p);
fail:
  SafeStrncpy(errbuf, pcap_geterr(p), PCAP_ERRBUF_SIZE);
  pcap_close(p);
  return (NULL);
}

static uint8_t CreateAndAddDevice(struct ListenerModule *lm, const char *name) {
  struct Device *dev;

  assert(lm != NULL);

  if (FindDeviceByName(lm, name) == TRUE) {
    Error("Device %s appears twice", name);
    return FALSE;
  }

  if ((dev = CreateDevice(name)) == NULL) {
    return FALSE;
  }

  if (AddDevice(lm, dev) == FALSE) {
    Error("Unable to add device %s", name);
    FreeDevice(dev);
    return FALSE;
  }

  return TRUE;
}

static int AutoPrepDevices(struct ListenerModule *lm, uint8_t includeLo) {
  pcap_if_t *alldevs, *d;
  char errbuf[PCAP_ERRBUF_SIZE];

  if (pcap_findalldevs(&alldevs, errbuf) == PCAP_ERROR) {
    Error("Unable to retrieve network interfaces: %s", errbuf);
    return FALSE;
  }

  for (d = alldevs; d != NULL; d = d->next) {
    if (includeLo == FALSE && ((d->flags & PCAP_IF_LOOPBACK) != 0)) {
      continue;
    }

    // When using ALL or ALL_NLO (and thus use pcap_findalldevs()), don't include the "any" device
    if ((strncmp(d->name, "any", 3) == 0) && strlen(d->name) == 3) {
      continue;
    }

    Verbose("Adding device %s", d->name);
    if (CreateAndAddDevice(lm, d->name) == FALSE) {
      Error("Unable to add device %s, skipping", d->name);
    }
  }

  pcap_freealldevs(alldevs);
  return TRUE;
}

static int PrepDevices(struct ListenerModule *lm) {
  int i;

  assert(lm != NULL);
  assert(strlen(configData.interfaces[0]) > 0);

  if (strncmp(configData.interfaces[0], "ALL_NLO", (IF_NAMESIZE - 1)) == 0) {
    if (AutoPrepDevices(lm, FALSE) == FALSE) {
      return FALSE;
    }
  } else if (strncmp(configData.interfaces[0], "ALL", (IF_NAMESIZE - 1)) == 0) {
    if (AutoPrepDevices(lm, TRUE) == FALSE) {
      return FALSE;
    }
  } else {
    i = 0;
    while (strlen(configData.interfaces[i]) > 0) {
      if (CreateAndAddDevice(lm, configData.interfaces[i]) == FALSE) {
        Error("Unable to add device %s, skipping", configData.interfaces[i]);
      }
      i++;
    }
  }

  if (lm->root == NULL) {
    Error("No network devices could be added");
    return FALSE;
  }

  return TRUE;
}

static int RetrieveAddresses(struct ListenerModule *lm) {
  int status = TRUE;
  struct ifaddrs *ifaddrs = NULL, *ifa = NULL;
  struct Device *dev;
  char err[ERRNOMAXBUF];
  char host[NI_MAXHOST];

  if (getifaddrs(&ifaddrs) == -1) {
    Error("Unable to retrieve network addresses: %s", ErrnoString(err, ERRNOMAXBUF));
    status = FALSE;
    goto cleanup;
  }

  for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL) {
      continue;
    }

    if (ifa->ifa_addr->sa_family != AF_INET && ifa->ifa_addr->sa_family != AF_INET6) {
      continue;
    }

    for (dev = lm->root; dev != NULL; dev = dev->next) {
      if (strncmp(dev->name, ifa->ifa_name, strlen(dev->name)) == 0) {
        if (getnameinfo(ifa->ifa_addr, (ifa->ifa_addr->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) == -1) {
          Crash(1, "Unable to retrieve network addresses for device %s: %s", dev->name, ErrnoString(err, ERRNOMAXBUF));
        }

        // FIXME: Verify that we don't filter on link-local addresses?
        if (strncmp(host, "fe80", 4) == 0) {
          continue;
        } else if (strncmp(host, "169.254", 7) == 0) {
          continue;
        }

        Debug("Found address %s for device %s: %s", ifa->ifa_name, dev->name, host);

        if (ifa->ifa_addr->sa_family == AF_INET) {
          AddAddress(dev, host, AF_INET);
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
          AddAddress(dev, host, AF_INET6);
        } else {
          Error("Unknown address family %d for address %s, ignoring", ifa->ifa_addr->sa_family, host);
        }
      }
    }
  }

cleanup:
  if (ifaddrs != NULL) {
    freeifaddrs(ifaddrs);
  }

  return status;
}

static char *ReallocFilter(char *filter, int newLen) {
  char *newFilter = NULL;

  if ((newFilter = realloc(filter, newLen)) == NULL) {
    Error("Unable to reallocate %d bytes of memory for pcap filter", newLen);
    Exit(EXIT_FAILURE);
  }

  return newFilter;
}

static char *ReallocAndAppend(char *filter, int *filterLen, const char *append, ...) {
  int neededBufferLen;
  char *p;
  va_list args;

  // Calculate the length of the buffer needed (excluding the null terminator)
  va_start(args, append);
  neededBufferLen = vsnprintf(NULL, 0, append, args);
  va_end(args);

  // First time we're called, make sure we alloc room for the null terminator since *snprintf auto adds it and force truncate if it doesn't fit
  if (filter == NULL)
    neededBufferLen += 1;

  filter = ReallocFilter(filter, *filterLen + neededBufferLen);

  // First time we're called, start at the beginning of the buffer. Otherwise, go to end of buffer - the null terminator
  if (*filterLen == 0)
    p = filter;
  else
    p = filter + *filterLen - 1;

  // store the new length of the buffer
  *filterLen += neededBufferLen;

  // Append the new string to the buffer, *snprintf will add the null terminator
  va_start(args, append);
  vsnprintf(p, (p == filter) ? neededBufferLen : neededBufferLen + 1, append, args);
  va_end(args);

  return filter;
}

static char *AllocAndBuildPcapFilter(struct Device *device) {
  int i;
  int filterLen = 0;
  char *filter = NULL;

  assert(device != NULL);

  if (device->inet4_addrs_count > 0 || device->inet6_addrs_count > 0) {
    filter = ReallocAndAppend(filter, &filterLen, "(");
  }

  for (i = 0; i < device->inet4_addrs_count; i++) {
    if (i > 0) {
      filter = ReallocAndAppend(filter, &filterLen, " or ");
    }
    filter = ReallocAndAppend(filter, &filterLen, "ip dst host %s", device->inet4_addrs[i]);
  }

  if (device->inet4_addrs_count > 0 && device->inet6_addrs_count > 0) {
    filter = ReallocAndAppend(filter, &filterLen, " or ");
  }

  for (i = 0; i < device->inet6_addrs_count; i++) {
    if (i > 0) {
      filter = ReallocAndAppend(filter, &filterLen, " or ");
    }
    filter = ReallocAndAppend(filter, &filterLen, "ip6 dst host %s", device->inet6_addrs[i]);
  }

  if (device->inet4_addrs_count > 0 || device->inet6_addrs_count > 0) {
    filter = ReallocAndAppend(filter, &filterLen, ")");
  }

  filter = ReallocAndAppend(filter, &filterLen, " and (");

  if (configData.sentryMode == SENTRY_MODE_STCP) {
    for (i = 0; i < configData.tcpPortsLength; i++) {
      if (i > 0) {
        filter = ReallocAndAppend(filter, &filterLen, " or ");
      }
      filter = ReallocAndAppend(filter, &filterLen, "tcp dst port %d", configData.tcpPorts[i]);
    }
  } else if (configData.sentryMode == SENTRY_MODE_SUDP) {
    for (i = 0; i < configData.udpPortsLength; i++) {
      if (i > 0) {
        filter = ReallocAndAppend(filter, &filterLen, " or ");
      }
      filter = ReallocAndAppend(filter, &filterLen, "udp dst port %d", configData.udpPorts[i]);
    }
  } else if (configData.sentryMode == SENTRY_MODE_ATCP) {
    filter = ReallocAndAppend(filter, &filterLen, "tcp[2:2] >= 0 and tcp[2:2] <= %d", configData.tcpAdvancedPort);

    for (i = 0; i < configData.tcpAdvancedExcludePortsLength; i++) {
      filter = ReallocAndAppend(filter, &filterLen, " and not port %d", configData.tcpAdvancedExcludePorts[i]);
    }
  } else if (configData.sentryMode == SENTRY_MODE_AUDP) {
    filter = ReallocAndAppend(filter, &filterLen, "udp[2:2] >= 0 and udp[2:2] <= %d", configData.udpAdvancedPort);

    for (i = 0; i < configData.udpAdvancedExcludePortsLength; i++) {
      filter = ReallocAndAppend(filter, &filterLen, " and not port %d", configData.udpAdvancedExcludePorts[i]);
    }
  } else {
    Error("Unknown sentry mode %d", configData.sentryMode);
    return NULL;
  }

  filter = ReallocAndAppend(filter, &filterLen, ")");

  Debug("Device: %s pcap filter len %d: [%s]", device->name, filterLen, filter);

  return filter;
}

int GetNoDevices(const struct ListenerModule *lm) {
  int count;
  struct Device *current;

  assert(lm != NULL);

  count = 0;
  current = lm->root;
  while (current != NULL) {
    count++;
    current = current->next;
  }

  return count;
}

struct ListenerModule *AllocListenerModule(void) {
  struct ListenerModule *lm;

  if ((lm = malloc(sizeof(struct ListenerModule))) == NULL) {
    Error("Unable to allocate memory for listener module");
    return NULL;
  }

  memset(lm, 0, sizeof(struct ListenerModule));

  return lm;
}

void FreeListenerModule(struct ListenerModule *lm) {
  struct Device *current;

  if (lm == NULL) {
    return;
  }

  current = lm->root;
  while (current != NULL) {
    current = current->next;
    FreeDevice(current);
  }

  free(lm);
}

int InitListenerModule(struct ListenerModule *lm) {
  char errbuf[PCAP_ERRBUF_SIZE];
  struct Device *current, *next;

  if (PrepDevices(lm) == FALSE) {
    return FALSE;
  }

  RetrieveAddresses(lm);

  current = lm->root;
  while (current != NULL) {
    next = current->next;

    if (pcap_lookupnet(current->name, &current->net, &current->mask, errbuf) < 0) {
      Error("Unable to retrieve network/netmask for device %s: %s, skipping", current->name, errbuf);
      RemoveDevice(lm, current);
      goto next;
    }

    if ((current->handle = PcapOpenLiveImmediate(current->name, BUFSIZ, 0, BUFFER_TIMEOUT, errbuf)) == NULL) {
      Error("Couldn't open device %s: %s", current->name, errbuf);
      RemoveDevice(lm, current);
      goto next;
    }

    if (pcap_setnonblock(current->handle, 1, errbuf) < 0) {
      Error("Unable to set pcap_setnonblock on %s: %s", current->name, errbuf);
      RemoveDevice(lm, current);
      goto next;
    }

    /*
     * OpenBSD and NetBSD has some quirks with pcap_setdirection(). Neither one of them will detect packets on the loopback interface
     * if direction is set to PCAP_D_IN for example. There are some other inconsistencies as well and I might not have found all of them.
     * By setting direction to PCAP_D_INOUT we make sure to capture as much as possible. The BPF filter will take care of most unwanted packets
     * anyway so atleast for now, we set this to PCAP_D_INOUT on all platforms in order to avoid any potential missed packets.
     */
    if (pcap_setdirection(current->handle, PCAP_D_INOUT) < 0) {
      Error("Couldn't set direction on %s: %s", current->name, pcap_geterr(current->handle));
      RemoveDevice(lm, current);
      goto next;
    }

    // We assume that since pcap_lookupnet() succeeded, we have a valid link type
    if (pcap_datalink(current->handle) != DLT_EN10MB &&
        pcap_datalink(current->handle) != DLT_RAW &&
        pcap_datalink(current->handle) != DLT_NULL
#ifdef __linux__
        && pcap_datalink(current->handle) != DLT_LINUX_SLL
#elif __OpenBSD__
        && pcap_datalink(current->handle) != DLT_LOOP
#endif
    ) {
      Error("Device %s is unsupported (linktype: %d), skipping this device", current->name, pcap_datalink(current->handle));
      RemoveDevice(lm, current);
      goto next;
    }

    if ((current->fd = pcap_get_selectable_fd(current->handle)) < 0) {
      Error("Couldn't get file descriptor on device %s: %s", current->name, pcap_geterr(current->handle));
      RemoveDevice(lm, current);
      goto next;
    }

    if (SetupFilter(current) == FALSE) {
      Error("Unable to setup filter for device %s, skipping", current->name);
      RemoveDevice(lm, current);
      goto next;
    }

  next:
    current = next;
  }

  if (lm->root == NULL) {
    Error("No network devices could be initiated, stopping");
    return FALSE;
  }

  if ((configData.logFlags & LOGFLAG_VERBOSE) != 0) {
    PrintDevices(lm);
  }

  return TRUE;
}

uint8_t AddDevice(struct ListenerModule *lm, struct Device *add) {
  struct Device *current;

  if (lm == NULL || add == NULL) {
    return FALSE;
  }

  if (FindDeviceByName(lm, add->name) == TRUE) {
    Verbose("Device %s already specified", add->name);
    return FALSE;
  }

  if (lm->root == NULL) {
    lm->root = add;
  } else {
    current = lm->root;
    while (current->next != NULL) {
      current = current->next;
    }

    current->next = add;
  }

  return TRUE;
}

uint8_t RemoveDevice(struct ListenerModule *lm, struct Device *remove) {
  struct Device *current, *previous;

  if (lm == NULL || remove == NULL) {
    return FALSE;
  }

  current = lm->root;
  previous = NULL;
  while (current != NULL) {
    if (current == remove) {
      if (previous == NULL) {
        lm->root = current->next;
      } else {
        previous->next = current->next;
      }

      FreeDevice(current);
      return TRUE;
    }

    previous = current;
    current = current->next;
  }

  return FALSE;
}

uint8_t FindDeviceByName(struct ListenerModule *lm, const char *name) {
  struct Device *current;

  if (lm == NULL) {
    return FALSE;
  }

  if (strlen(name) > (IF_NAMESIZE - 1)) {
    return FALSE;
  }

  current = lm->root;
  while (current != NULL) {
    if (strncmp(current->name, name, (IF_NAMESIZE - 1)) == 0) {
      return TRUE;
    }

    current = current->next;
  }

  return FALSE;
}

struct pollfd *SetupPollFds(const struct ListenerModule *lm, int *nfds) {
  struct pollfd *fds = NULL;
  struct Device *current = NULL;
  int i = 0;

  if ((fds = malloc(sizeof(struct pollfd) * GetNoDevices(lm))) == NULL) {
    Error("Unable to allocate memory for pollfd");
    return NULL;
  }

  current = lm->root;
  while (current != NULL) {
    fds[i].fd = current->fd;
    fds[i].events = POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI;
    fds[i].revents = 0;
    current = current->next;
    i++;
  }

  *nfds = i;

  return fds;
}

struct Device *GetDeviceByFd(const struct ListenerModule *lm, const int fd) {
  for (struct Device *current = lm->root; current != NULL; current = current->next) {
    if (current->fd == fd) {
      return current;
    }
  }

  return NULL;
}
/*
void HandlePacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  PrintPacket(args, header, packet);
}

static void PrintPacket(const u_char *interface, const struct pcap_pkthdr *header, const u_char *packet) {
  int iplen;
  uint8_t protocol, ipVersion, hl;
  char saddr[16], daddr[16];
  struct tcphdr *tcphdr;
  struct udphdr *udphdr;
#ifdef BSD
  struct ip *iphdr;
  iphdr = (struct ip *)(packet + sizeof(struct ether_header));
  ntohstr(saddr, sizeof(saddr), iphdr->ip_src.s_addr);
  ntohstr(daddr, sizeof(daddr), iphdr->ip_dst.s_addr);
  iplen = iphdr->ip_hl * 4;
  protocol = iphdr->ip_p;
  ipVersion = iphdr->ip_v;
  hl = iphdr->ip_hl;
#else
  struct iphdr *iphdr;
  iphdr = (struct iphdr *)(packet + sizeof(struct ether_header));
  ntohstr(saddr, sizeof(saddr), iphdr->saddr);
  ntohstr(daddr, sizeof(daddr), iphdr->daddr);
  iplen = iphdr->ihl * 4;
  protocol = iphdr->protocol;
  ipVersion = iphdr->version;
  hl = iphdr->ihl;
#endif

  printf("%s: %d [%d] ", interface, header->caplen, header->len);
  printf("ihl: %d IP len: %d proto: %s ver: %d saddr: %s daddr: %s ", hl, iplen,
         protocol == IPPROTO_TCP   ? "tcp"
         : protocol == IPPROTO_UDP ? "udp"
                                   : "other",
         ipVersion, saddr, daddr);

  if (protocol == IPPROTO_TCP) {
    tcphdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + iplen);
    printf("sport: %d dport: %d", ntohs(tcphdr->th_sport), ntohs(tcphdr->th_dport));
  } else if (protocol == IPPROTO_UDP) {
    udphdr = (struct udphdr *)(packet + sizeof(struct ether_header) + iplen);
    printf("sport: %d dport: %d", ntohs(udphdr->uh_sport), ntohs(udphdr->uh_dport));
  }
  printf("\n");
}
*/
static int SetupFilter(struct Device *device) {
  struct bpf_program fp;
  char *filter = NULL;
  int status = FALSE;

  assert(device != NULL);
  assert(device->handle != NULL);

  if ((filter = AllocAndBuildPcapFilter(device)) == NULL) {
    goto exit;
  }

  if (pcap_compile(device->handle, &fp, filter, 0, device->net) == PCAP_ERROR) {
    Error("Unable to compile pcap filter %s: %s", filter, pcap_geterr(device->handle));
    goto exit;
  }

  if (pcap_setfilter(device->handle, &fp) == PCAP_ERROR) {
    Error("Unable to set filter %s: %s", filter, pcap_geterr(device->handle));
    goto exit;
  }

  status = TRUE;

exit:
  if (filter != NULL) {
    free(filter);
    filter = NULL;
  }

  return status;
}

static void PrintDevices(const struct ListenerModule *lm) {
  int i;
  struct Device *current;

  if (lm == NULL) {
    return;
  }

  current = lm->root;
  while (current != NULL) {
    Verbose("Ready Device: %s pcap handle: %p, fd: %d pcap net: %d, mask: %d", current->name, current->handle, current->fd, current->net, current->mask);

    for (i = 0; i < current->inet4_addrs_count; i++) {
      Verbose("  inet4 addr: %s", current->inet4_addrs[i]);
    }

    for (i = 0; i < current->inet6_addrs_count; i++) {
      Verbose("  inet6 addr: %s", current->inet6_addrs[i]);
    }

    current = current->next;
  }
}
