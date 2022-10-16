#ifndef DEFINES_H
# define DEFINES_H

#include <stdint.h>

#include <sys/un.h>

#include <arpa/inet.h>

#include <poll.h>

typedef int SOCKET;
typedef struct sockaddr_in SOCKADDRV4;
typedef uint32_t ipv4_t;
typedef uint16_t port_t;
typedef struct sockaddr_un SOCKADDRUN;
typedef struct sockaddr_in SOCKADDRIN;
typedef struct pollfd POLLFD;

#define POSSIBLE_PORTS_SIZE (1<<5)

#define INET_ADDR(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))

#define GET_PORT(ip, port, key) ((ip^port^key)&(POSSIBLE_PORTS_SIZE-1))

#define GEN_SEQ(ip, port, key) (ip^port^key)

#define FLAG_UNIX 1
#define FLAG_IPV4 2
#define FLAG_IPV6 4

#endif