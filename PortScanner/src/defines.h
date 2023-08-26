#ifndef DEFINES_H
# define DEFINES_H

#include <stdint.h>

#include <sys/un.h>

#include <arpa/inet.h>

#include <poll.h>

typedef int					socket_t;
typedef struct sockaddr_in	sockaddr_in4_t;
typedef struct sockaddr_in6	sockaddr_in6_t;
typedef struct sockaddr_in	sockaddr_in_t;
typedef uint32_t			ipv4_t;
typedef struct in6_addr		ipv6_t;
typedef uint16_t			port_t;
typedef struct sockaddr_un	sockaddr_un_t;
typedef struct pollfd		pollfd_t;
typedef __uint128_t			uint128_t;


/* utils */
#define INET_ADDR(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))
#define GET_PORT(ip, port, key) ((ip^port^key)&(POSSIBLE_PORTS_SIZE-1))
#define GEN_SEQ(ip, port, key) (ip^port^key)

/* flags */
#define FLAG_UNIX 1
#define FLAG_IPV4 2

/* utils */
#define TIMEOUT 20
#define RANDOM() (random() << 8 | (random() & 0xFF))
#define ONE_SECONDE 1000000
#define DEBIT_OpS(DEBIT) (ONE_SECONDE/DEBIT/(sizeof(packet_t)))

/* advanced config */
#define POSSIBLE_PORTS_SIZE 16

/* errors */
#define	CRITICAL_ERROR		-0x999
#define	INVALID_REQUEST		-0x1000
#define	INVALID_PASSWORD	-0x1001
#define	INVALID_PORT		-0x1002
#define	INVALID_IP			-0x1003
#define	INVALID_MASK		-0x1004

#endif
