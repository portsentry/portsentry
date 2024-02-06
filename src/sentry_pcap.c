#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

#include "portsentry.h"
#include "sentry_pcap.h"
#include "listener.h"
#include "device.h"
#include "io.h"
#include "util.h"

#define POLL_TIMEOUT 500

static void HandlePacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#ifdef BSD
static int PrepPacket(const u_char *interface, const struct pcap_pkthdr *header, const u_char *packet, struct ip **ip, struct tcphdr **tcp, struct udphdr **udp);
static int SetSockaddrByPacket(struct sockaddr_in *client, const struct ip *ip, const struct tcphdr *tcp, const struct udphdr *udp);
static int SetPcapConnectionData(struct ConnectionData *cd, const struct ip *ip, const struct tcphdr *tcp, const struct udphdr *udp);
#else
static int PrepPacket(const u_char *interface, const struct pcap_pkthdr *header, const u_char *packet, struct iphdr **ip, struct tcphdr **tcp, struct udphdr **udp);
static int SetSockaddrByPacket(struct sockaddr_in *client, const struct iphdr *ip, const struct tcphdr *tcp, const struct udphdr *udp);
static int SetPcapConnectionData(struct ConnectionData *cd, const struct iphdr *ip, const struct tcphdr *tcp, const struct udphdr *udp);
#endif

int PortSentryPcap(void) {
  int status = FALSE, ret, nfds = 0, i;
  char err[ERRNOMAXBUF];
  struct ListenerModule *lm = NULL;
  struct pollfd *fds = NULL;
  struct Device *current = NULL;

  if ((lm = AllocListenerModule()) == NULL) {
    goto exit;
  }

  if (InitListenerModule(lm) == FALSE) {
    goto exit;
  }

  if ((fds = SetupPollFds(lm, &nfds)) == NULL) {
    Error("Unable to allocate memory for pollfd");
    goto exit;
  }

  Log("adminalert: PortSentry is now active and listening.");

  while (1) {
    ret = poll(fds, nfds, POLL_TIMEOUT);

    if (ret == -1) {
      Error("poll() failed %s", ErrnoString(err, sizeof(err)));
      goto exit;
    } else if (ret == 0) {
      continue;
    }

    for (i = 0; i < nfds; i++) {
      if (fds[i].revents & POLLIN) {
        if ((current = GetDeviceByFd(lm, fds[i].fd)) == NULL) {
          Error("Unable to find device by fd %d", fds[i].fd);
          goto exit;
        }

        do {
          ret = pcap_dispatch(current->handle, -1, HandlePacket, (u_char *)current->name);

          if (ret == PCAP_ERROR) {
            Error("pcap_dispatch() failed %s, ignoring", pcap_geterr(current->handle));
          } else if (ret == PCAP_ERROR_BREAK) {
            Error("Got PCAP_ERROR_BREAK, ignoring");
          }
        } while (ret > 0);
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

static void HandlePacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  struct ConnectionData cd;
  struct sockaddr_in client;
#ifdef BSD
  struct ip *ip;
#else
  struct iphdr *ip;
#endif
  struct tcphdr *tcp;
  struct udphdr *udp;

  if (PrepPacket(args, header, packet, &ip, &tcp, &udp) == FALSE) {
    return;
  }

  if (SetSockaddrByPacket(&client, ip, tcp, udp) == FALSE) {
    return;
  }

  if (SetPcapConnectionData(&cd, ip, tcp, udp) == FALSE) {
    return;
  }

  if (cd.protocol == IPPROTO_TCP && (((tcp->th_flags & TH_ACK) != 0) || ((tcp->th_flags & TH_RST) != 0))) {
    return;
  }

  // FIXME: In pcap we need to consider the interface
  if (IsPortInUse(cd.port, cd.protocol) != FALSE) {
    return;
  }

  RunSentry(&cd, &client, ip, tcp, NULL);
}

#ifdef BSD
static int PrepPacket(const u_char *interface, const struct pcap_pkthdr *header, const u_char *packet, struct ip **ip, struct tcphdr **tcp, struct udphdr **udp) {
#else
static int PrepPacket(const u_char *interface, const struct pcap_pkthdr *header, const u_char *packet, struct iphdr **ip, struct tcphdr **tcp, struct udphdr **udp) {
#endif
  int iplen;
  uint8_t protocol;
  *ip = NULL;
  *tcp = NULL;
  *udp = NULL;
  (void)interface;
  (void)header;

#ifdef BSD
  *ip = (struct ip *)(packet + sizeof(struct ether_header));
  iplen = ip->ip_hl * 4;
  protocol = ip->ip_p;
#else
  *ip = (struct iphdr *)(packet + sizeof(struct ether_header));
  iplen = (*ip)->ihl * 4;
  protocol = (*ip)->protocol;
#endif

  if (protocol == IPPROTO_TCP) {
    *tcp = (struct tcphdr *)(packet + sizeof(struct ether_header) + iplen);
  } else if (protocol == IPPROTO_UDP) {
    *udp = (struct udphdr *)(packet + sizeof(struct ether_header) + iplen);
  } else {
    Error("adminalert: Unknown protocol %d while processing packet", protocol);
    return FALSE;
  }
  return TRUE;
}

#ifdef BSD
static int SetSockaddrByPacket(struct sockaddr_in *client, const struct ip *ip, const struct tcphdr *tcp, const struct udphdr *udp) {
#else
static int SetSockaddrByPacket(struct sockaddr_in *client, const struct iphdr *ip, const struct tcphdr *tcp, const struct udphdr *udp) {
#endif
  uint8_t protocol;

  memset(client, 0, sizeof(struct sockaddr_in));
#ifdef BSD
  protocol = ip->ip_p;
  client->sin_addr.s_addr = ip->ip_src.s_addr;
#else
  protocol = ip->protocol;
  client->sin_addr.s_addr = ip->saddr;
#endif

  client->sin_family = AF_INET;
  if (protocol == IPPROTO_TCP) {
    client->sin_port = tcp->th_dport;
  } else if (protocol == IPPROTO_UDP) {
    client->sin_port = udp->uh_dport;
  } else {
    Error("adminalert: Unknown protocol %d detected during sockaddr resolution. Attempting to continue.", protocol);
    return FALSE;
  }

  return TRUE;
}

#ifdef BSD
static int SetPcapConnectionData(struct ConnectionData *cd, const struct ip *ip, const struct tcphdr *tcp, const struct udphdr *udp) {
#else
static int SetPcapConnectionData(struct ConnectionData *cd, const struct iphdr *ip, const struct tcphdr *tcp, const struct udphdr *udp) {
#endif
  cd->protocol = ip->protocol;
  cd->sockfd = -1;
  cd->portInUse = FALSE;

  if (cd->protocol == IPPROTO_TCP) {
    cd->port = ntohs(tcp->dest);
  } else if (cd->protocol == IPPROTO_UDP) {
    cd->port = ntohs(udp->dest);
  } else {
    Error("adminalert: Unknown protocol %d detected while setting connection data", cd->protocol);
    return FALSE;
  }
  return TRUE;
}
