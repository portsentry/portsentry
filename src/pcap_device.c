// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <ifaddrs.h>

#include "portsentry.h"
#include "pcap_device.h"
#include "util.h"
#include "io.h"
#include "config_data.h"

#define BUFFER_TIMEOUT 2000

static pcap_t *PcapOpenLiveImmediate(const char *source, const int snaplen, const int promisc, const int to_ms, char *errbuf);
static char **RemoveElementFromArray(char **array, const int index, int *count);
static char *AllocAndBuildPcapFilter(const struct Device *device);

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
static pcap_t *PcapOpenLiveImmediate(const char *source, const int snaplen, const int promisc, const int to_ms, char *errbuf) {
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

static char **RemoveElementFromArray(char **array, const int index, int *count) {
  char **tmp = array;

  assert(array != NULL);
  assert(count != NULL);
  assert(index >= 0);
  assert(index < *count);
  assert(*count > 0);

  free(array[index]);

  (*count)--;

  for (int i = index; i < *count; i++) {
    array[i] = array[i + 1];
  }

  if (*count > 0) {
    if ((tmp = realloc(array, sizeof(char *) * *count)) == NULL) {
      Crash(1, "Unable to reallocate IP address memory");
    }
  } else {
    free(array);
    tmp = NULL;
  }

  return tmp;
}

static char *AllocAndBuildPcapFilter(const struct Device *device) {
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

  if (configData.tcpPortsLength > 0) {
    if (configData.tcpPortsLength > 0 && configData.udpPortsLength > 0) {
      filter = ReallocAndAppend(filter, &filterLen, "(");
    }

    for (i = 0; i < configData.tcpPortsLength; i++) {
      if (i > 0) {
        filter = ReallocAndAppend(filter, &filterLen, " or ");
      }

      if (IsPortSingle(&configData.tcpPorts[i])) {
        filter = ReallocAndAppend(filter, &filterLen, "tcp dst port %d", configData.tcpPorts[i].single);
      } else {
        /* OpenBSD's libpcap doesn't support portrange */
#ifdef __OpenBSD__
        for (int j = configData.tcpPorts[i].range.start; j <= configData.tcpPorts[i].range.end; j++) {
          filter = ReallocAndAppend(filter, &filterLen, "tcp dst port %d", j);
          if (j < configData.tcpPorts[i].range.end) {
            filter = ReallocAndAppend(filter, &filterLen, " or ");
          }
        }
#else
        filter = ReallocAndAppend(filter, &filterLen, "tcp dst portrange %d-%d", configData.tcpPorts[i].range.start, configData.tcpPorts[i].range.end);
#endif
      }
    }

    if (configData.tcpPortsLength > 0 && configData.udpPortsLength > 0) {
      filter = ReallocAndAppend(filter, &filterLen, ")");
    }
  }

  if (configData.udpPortsLength > 0) {
    if (configData.tcpPortsLength > 0 && configData.udpPortsLength > 0) {
      filter = ReallocAndAppend(filter, &filterLen, " or (");
    }

    for (i = 0; i < configData.udpPortsLength; i++) {
      if (i > 0) {
        filter = ReallocAndAppend(filter, &filterLen, " or ");
      }

      if (IsPortSingle(&configData.udpPorts[i])) {
        filter = ReallocAndAppend(filter, &filterLen, "udp dst port %d", configData.udpPorts[i].single);
      } else {
        /* OpenBSD's libpcap doesn't support portrange */
#ifdef __OpenBSD__
        for (int j = configData.udpPorts[i].range.start; j <= configData.udpPorts[i].range.end; j++) {
          filter = ReallocAndAppend(filter, &filterLen, "udp dst port %d", j);
          if (j < configData.udpPorts[i].range.end) {
            filter = ReallocAndAppend(filter, &filterLen, " or ");
          }
        }
#else
        filter = ReallocAndAppend(filter, &filterLen, "udp dst portrange %d-%d", configData.udpPorts[i].range.start, configData.udpPorts[i].range.end);
#endif
      }
    }

    if (configData.tcpPortsLength > 0 && configData.udpPortsLength > 0) {
      filter = ReallocAndAppend(filter, &filterLen, ")");
    }
  }

  filter = ReallocAndAppend(filter, &filterLen, ")");

  Debug("Device: %s pcap filter len %d: [%s]", device->name, filterLen, filter);

  return filter;
}

struct Device *CreateDevice(const char *name) {
  struct Device *new;

  if (name == NULL) {
    Error("Device name cannot be NULL");
    return NULL;
  }

  if (strlen(name) > (IF_NAMESIZE - 1)) {
    Error("Device name %s is too long", name);
    return NULL;
  }

  if ((new = calloc(1, sizeof(struct Device))) == NULL) {
    Error("Unable to allocate memory for device %s", name);
    return NULL;
  }

  SafeStrncpy(new->name, name, IF_NAMESIZE);

  return new;
}

int AddAddress(struct Device *device, const char *address, const int type) {
  char **addresses = NULL;
  int addresses_count = 0;

  assert(device != NULL);
  assert(address != NULL);
  assert(type == AF_INET || type == AF_INET6);

  if (AddressExists(device, address, type) == TRUE) {
    Debug("AddAddress: Address %s already exists on %s, skipping", address, device->name);
    return FALSE;
  }

  if (type == AF_INET) {
    struct sockaddr_in addr4;
    if (inet_pton(AF_INET, address, &addr4.sin_addr) != 1) {
      Error("Invalid IPv4 address format: %s", address);
      return ERROR;
    }
    // Check for IPv4 link-local (169.254.0.0/16)
    uint32_t addr = ntohl(addr4.sin_addr.s_addr);
    if ((addr & 0xFFFF0000) == 0xA9FE0000) {
      Debug("Ignoring IPv4 link-local address %s on %s", address, device->name);
      return FALSE;
    }
  } else if (type == AF_INET6) {
    struct sockaddr_in6 addr6;
    if (inet_pton(AF_INET6, address, &addr6.sin6_addr) != 1) {
      Error("Invalid IPv6 address format: %s", address);
      return ERROR;
    }
    if (IN6_IS_ADDR_LINKLOCAL(&addr6.sin6_addr)) {
      Debug("Ignoring IPv6 link-local address %s on %s", address, device->name);
      return FALSE;
    }
  }

  if (type == AF_INET) {
    addresses = device->inet4_addrs;
    addresses_count = device->inet4_addrs_count;
  } else if (type == AF_INET6) {
    addresses = device->inet6_addrs;
    addresses_count = device->inet6_addrs_count;
  } else {
    Crash(1, "Invalid address type");
  }

  if ((addresses = realloc(addresses, sizeof(char *) * (addresses_count + 1))) == NULL) {
    Crash(1, "Unable to reallocate IP address memory");
  }

  if ((addresses[addresses_count] = strdup(address)) == NULL) {
    Crash(1, "Unable to allocate memory for address %s", address);
  }

  addresses_count++;

  if (type == AF_INET) {
    device->inet4_addrs = addresses;
    device->inet4_addrs_count = addresses_count;
  } else if (type == AF_INET6) {
    device->inet6_addrs = addresses;
    device->inet6_addrs_count = addresses_count;
  } else {
    Crash(1, "Invalid address type");
  }

  return TRUE;
}

int AddressExists(const struct Device *device, const char *address, const int type) {
  int i;
  char **addresses = NULL;
  int addresses_count = 0;

  assert(device != NULL);
  assert(address != NULL);
  assert(type == AF_INET || type == AF_INET6);

  if (type == AF_INET) {
    addresses = device->inet4_addrs;
    addresses_count = device->inet4_addrs_count;
  } else if (type == AF_INET6) {
    addresses = device->inet6_addrs;
    addresses_count = device->inet6_addrs_count;
  } else {
    Crash(1, "Invalid address type");
  }

  for (i = 0; i < addresses_count; i++) {
    if (strncmp(addresses[i], address, strlen(addresses[i])) == 0) {
      return TRUE;
    }
  }

  return FALSE;
}

int GetNoAddresses(const struct Device *device) {
  assert(device != NULL);
  return device->inet4_addrs_count + device->inet6_addrs_count;
}

int RemoveAddress(struct Device *device, const char *address) {
  assert(device != NULL);
  assert(address != NULL);

  for (int i = 0; i < device->inet4_addrs_count; i++) {
    if (strcmp(device->inet4_addrs[i], address) == 0) {
      device->inet4_addrs = RemoveElementFromArray(device->inet4_addrs, i, &device->inet4_addrs_count);
      return TRUE;
    }
  }

  for (int i = 0; i < device->inet6_addrs_count; i++) {
    if (strcmp(device->inet6_addrs[i], address) == 0) {
      device->inet6_addrs = RemoveElementFromArray(device->inet6_addrs, i, &device->inet6_addrs_count);
      return TRUE;
    }
  }

  return FALSE;
}

void RemoveAllAddresses(struct Device *device) {
  assert(device != NULL);

  if (device->inet4_addrs != NULL) {
    for (int i = 0; i < device->inet4_addrs_count; i++) {
      free(device->inet4_addrs[i]);
    }
    free(device->inet4_addrs);
    device->inet4_addrs = NULL;
    device->inet4_addrs_count = 0;
  }

  if (device->inet6_addrs != NULL) {
    for (int i = 0; i < device->inet6_addrs_count; i++) {
      free(device->inet6_addrs[i]);
    }
    free(device->inet6_addrs);
    device->inet6_addrs = NULL;
    device->inet6_addrs_count = 0;
  }
}

int SetAllAddresses(struct Device *device) {
  int status = TRUE;
  struct ifaddrs *ifaddrs = NULL, *ifa = NULL;
  char err[ERRNOMAXBUF];
  char host[NI_MAXHOST];

  if (getifaddrs(&ifaddrs) == -1) {
    Error("Unable to retrieve network addresses: %s", ErrnoString(err, ERRNOMAXBUF));
    status = ERROR;
    goto cleanup;
  }

  for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL) {
      continue;
    }

    if (ifa->ifa_addr->sa_family != AF_INET && ifa->ifa_addr->sa_family != AF_INET6) {
      continue;
    }

    if (strncmp(device->name, ifa->ifa_name, strlen(device->name)) != 0) {
      continue;
    }

    // Ignore link-local addresses before calling getnameinfo() since Linux and BSD have different link-local address formats. Linux includes the scope id, BSD doesn't
    if (ifa->ifa_addr->sa_family == AF_INET6) {
      struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)ifa->ifa_addr;
      if (IN6_IS_ADDR_LINKLOCAL(&addr6->sin6_addr)) {
        continue;
      }
    } else if (ifa->ifa_addr->sa_family == AF_INET) {
      struct sockaddr_in *addr4 = (struct sockaddr_in *)ifa->ifa_addr;
      uint32_t addr = ntohl(addr4->sin_addr.s_addr);
      if ((addr & 0xFFFF0000) == 0xA9FE0000) {
        continue;
      }
    }

    if (getnameinfo(ifa->ifa_addr, (ifa->ifa_addr->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) == -1) {
      Crash(1, "Unable to retrieve network addresses for device %s: %s", device->name, ErrnoString(err, ERRNOMAXBUF));
    }

    Debug("Found address %s for device %s", host, device->name);

    if (ifa->ifa_addr->sa_family == AF_INET) {
      AddAddress(device, host, AF_INET);
    } else if (ifa->ifa_addr->sa_family == AF_INET6) {
      AddAddress(device, host, AF_INET6);
    } else {
      Error("Unknown address family %d for address %s, ignoring", ifa->ifa_addr->sa_family, host);
    }
  }

cleanup:
  if (ifaddrs != NULL) {
    freeifaddrs(ifaddrs);
  }

  return status;
}

uint8_t FreeDevice(struct Device *device) {
  int i;

  if (device == NULL) {
    return FALSE;
  }

  StopDevice(device);

  if (device->inet4_addrs != NULL) {
    for (i = 0; i < device->inet4_addrs_count; i++) {
      free(device->inet4_addrs[i]);
    }
    free(device->inet4_addrs);
    device->inet4_addrs = NULL;
  }

  if (device->inet6_addrs != NULL) {
    for (i = 0; i < device->inet6_addrs_count; i++) {
      free(device->inet6_addrs[i]);
    }
    free(device->inet6_addrs);
    device->inet6_addrs = NULL;
  }

  free(device);

  return TRUE;
}

uint8_t StopDevice(struct Device *device) {
  assert(device != NULL);

  if (device->state == DEVICE_STATE_STOPPED) {
    Debug("StopDevice: Device %s is already stopped, skipping", device->name);
    return TRUE;
  }

  if (device->state == DEVICE_STATE_ERROR) {
    Error("StopDevice: Device %s is in error state, skipping", device->name);
    return FALSE;
  }

  pcap_close(device->handle);
  device->handle = NULL;
  device->state = DEVICE_STATE_STOPPED;
  device->fd = -1;

  Debug("StopDevice: Device %s stopped", device->name);

  return TRUE;
}

uint8_t StartDevice(struct Device *device) {
  int status = ERROR;
  char errbuf[PCAP_ERRBUF_SIZE];

  assert(device != NULL);

  if (device->state == DEVICE_STATE_RUNNING) {
    Debug("StartDevice: Device %s is already running, skipping", device->name);
    status = TRUE;
    goto exit;
  }

  RemoveAllAddresses(device);

  if (SetAllAddresses(device) == ERROR) {
    Error("StartDevice: Unable to set all addresses for device %s, skipping", device->name);
    status = ERROR;
    goto exit;
  }

  if (GetNoAddresses(device) == 0) {
    Error("StartDevice: Device %s has no addresses, skipping", device->name);
    status = FALSE;
    goto exit;
  }

  if ((device->handle = PcapOpenLiveImmediate(device->name, BUFSIZ, 0, BUFFER_TIMEOUT, errbuf)) == NULL) {
    Error("StartDevice: Couldn't open device %s: %s", device->name, errbuf);
    status = ERROR;
    goto exit;
  }

  if (pcap_setnonblock(device->handle, 1, errbuf) < 0) {
    Error("StartDevice: Unable to set pcap_setnonblock on %s: %s", device->name, errbuf);
    status = ERROR;
    goto exit;
  }

  /*
   * OpenBSD and NetBSD has some quirks with pcap_setdirection(). Neither one of them will detect packets on the loopback interface
   * if direction is set to PCAP_D_IN for example. There are some other inconsistencies as well and I might not have found all of them.
   * By setting direction to PCAP_D_INOUT we make sure to capture as much as possible. The BPF filter will take care of most unwanted packets
   * anyway so atleast for now, we set this to PCAP_D_INOUT on all platforms in order to avoid any potential missed packets.
   */
  if (pcap_setdirection(device->handle, PCAP_D_INOUT) < 0) {
    Error("StartDevice: Couldn't set direction on %s: %s", device->name, pcap_geterr(device->handle));
    status = ERROR;
    goto exit;
  }

  // We assume that since pcap_lookupnet() succeeded, we have a valid link type
  if (pcap_datalink(device->handle) != DLT_EN10MB &&
      pcap_datalink(device->handle) != DLT_RAW &&
      pcap_datalink(device->handle) != DLT_NULL
#ifdef __linux__
      && pcap_datalink(device->handle) != DLT_LINUX_SLL
#elif __OpenBSD__
      && pcap_datalink(device->handle) != DLT_LOOP
#endif
  ) {
    Error("StartDevice: Device %s is unsupported (linktype: %d), skipping this device", device->name, pcap_datalink(device->handle));
    status = ERROR;
    goto exit;
  }

  if ((device->fd = pcap_get_selectable_fd(device->handle)) < 0) {
    Error("StartDevice: Couldn't get file descriptor on device %s: %s", device->name, pcap_geterr(device->handle));
    status = ERROR;
    goto exit;
  }

  if (SetupFilter(device) == ERROR) {
    Error("StartDevice: Unable to setup filter for device %s, skipping", device->name);
    status = ERROR;
    goto exit;
  }

  status = TRUE;

exit:
  if (status == ERROR || status == FALSE) {
    if (device->handle != NULL) {
      pcap_close(device->handle);
      device->handle = NULL;
    }

    device->fd = -1;

    if (status == ERROR) {
      device->state = DEVICE_STATE_ERROR;
    } else {
      device->state = DEVICE_STATE_STOPPED;
    }
  } else {
    device->state = DEVICE_STATE_RUNNING;
  }

  return status;
}

int SetupFilter(const struct Device *device) {
  struct bpf_program fp;
  char *filter = NULL;
  int status = ERROR;
  uint8_t isCompiled = FALSE;

  assert(device != NULL);
  assert(device->handle != NULL);

  if ((filter = AllocAndBuildPcapFilter(device)) == NULL) {
    goto exit;
  }

  // Using PCAP_NETMASK_UNKNOWN because we might use IPv6 and mask is only used for broadcast packets which we don't care about
  if (pcap_compile(device->handle, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR) {
    Error("SetupFilter: Unable to compile pcap filter %s: %s", filter, pcap_geterr(device->handle));
    goto exit;
  }

  isCompiled = TRUE;

  if (pcap_setfilter(device->handle, &fp) == PCAP_ERROR) {
    Error("SetupFilter: Unable to set filter %s: %s", filter, pcap_geterr(device->handle));
    goto exit;
  }

  status = TRUE;

exit:
  if (filter != NULL) {
    free(filter);
    filter = NULL;
  }

  if (isCompiled) {
    pcap_freecode(&fp);
  }

  return status;
}
