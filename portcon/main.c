// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: BSD-2-Clause

/* This is a simple program used in the system testing framework (see the system_test directory) */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>

#define BUF_SIZE 1024

int main(int argc, char **argv) {
  int protocol, sock, result;
  uint16_t port;
  char buf[BUF_SIZE];
  struct sockaddr_in addr;
  socklen_t addr_len = sizeof(addr);
  struct pollfd fds;

  if (argc < 3) {
    printf("Usage: %s <port> <protocol>\n", argv[0]);
    return 1;
  }

  port = atoi(argv[1]);

  if (strncmp("tcp", argv[2], 3) == 0) {
    protocol = IPPROTO_TCP;
  } else if (strncmp("udp", argv[2], 3) == 0) {
    protocol = IPPROTO_UDP;
  } else {
    printf("Invalid protocol: %s\n", argv[2]);
    return 1;
  }

  if ((sock = socket(AF_INET, (protocol == IPPROTO_TCP) ? SOCK_STREAM : SOCK_DGRAM, 0)) == -1) {
    perror("socket");
    return 1;
  }

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = inet_addr("127.0.0.1");

  if (protocol == IPPROTO_TCP) {
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
      perror("connect");
      return 1;
    }

    fds.fd = sock;
    fds.events = POLLIN;
    fds.revents = 0;
    result = poll(&fds, 1, 5000);

    if (result == -1) {
      perror("poll");
      return 1;
    } else if (result == 0) {
      printf("Timeout\n");
      return 1;
    }

    if (fds.revents & POLLIN) {
      if ((result = read(sock, buf, BUF_SIZE)) == -1) {
        perror("read");
        return 1;
      }
    } else {
      printf("No POLLIN event\n");
      return 1;
    }
  } else {
    sendto(sock, "Hello", 5, 0, (struct sockaddr *)&addr, sizeof(addr));

    fds.fd = sock;
    fds.events = POLLIN;
    fds.revents = 0;
    result = poll(&fds, 1, 5000);

    if (result == -1) {
      perror("poll");
      return 1;
    } else if (result == 0) {
      printf("Timeout\n");
      return 1;
    }

    if (fds.revents & POLLIN) {
      if ((result = recvfrom(sock, buf, BUF_SIZE, 0, (struct sockaddr *)&addr, &addr_len)) == -1) {
        perror("recvfrom");
        return 1;
      }
    } else {
      printf("No POLLIN event\n");
      return 1;
    }
  }

  buf[result] = '\0';
  printf("%s\n", buf);

  return 0;
}
