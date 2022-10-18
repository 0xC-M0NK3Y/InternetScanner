#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "defines.h"
#include "structs.h"
/*
// FUNCTION TOOK FROM MIRAI
// https://github.com/jgamblin/Mirai-Source-Code/blob/master/mirai/bot/scanner.c
ipv4_t get_random_ip(void) {
    uint32_t tmp;
    uint8_t o1, o2, o3, o4;

    do
    {
        tmp = rand();

        o1 = tmp & 0xff;
        o2 = (tmp >> 8) & 0xff;
        o3 = (tmp >> 16) & 0xff;
        o4 = (tmp >> 24) & 0xff;
    }
    while (o1 == 127 ||                             // 127.0.0.0/8      - Loopback
          (o1 == 0) ||                              // 0.0.0.0/8        - Invalid address space
          (o1 == 3) ||                              // 3.0.0.0/8        - General Electric Company
          (o1 == 15 || o1 == 16) ||                 // 15.0.0.0/7       - Hewlett-Packard Company
          (o1 == 56) ||                             // 56.0.0.0/8       - US Postal Service
          (o1 == 10) ||                             // 10.0.0.0/8       - Internal network
          (o1 == 192 && o2 == 168) ||               // 192.168.0.0/16   - Internal network
          (o1 == 172 && o2 >= 16 && o2 < 32) ||     // 172.16.0.0/14    - Internal network
          (o1 == 100 && o2 >= 64 && o2 < 127) ||    // 100.64.0.0/10    - IANA NAT reserved
          (o1 == 169 && o2 > 254) ||                // 169.254.0.0/16   - IANA NAT reserved
          (o1 == 198 && o2 >= 18 && o2 < 20) ||     // 198.18.0.0/15    - IANA Special use
          (o1 >= 224) ||                            // 224.*.*.*+       - Multicast
          (o1 == 6 || o1 == 7 || o1 == 11 || o1 == 21 || o1 == 22 || o1 == 26 || o1 == 28 || o1 == 29 || o1 == 30 || o1 == 33 || o1 == 55 || o1 == 214 || o1 == 215) // Department of Defense
    );

    return INET_ADDR(o1,o2,o3,o4);
}
*/

/*
 * in_cksum --
 * Checksum routine for Internet Protocol
 * family headers (C Version)
 */
unsigned short in_cksum(unsigned short *addr, int len)
{
    register int sum = 0;
    unsigned short answer = 0;
    register unsigned short *w = addr;
    register int nleft = len;
    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)
    {
      sum += *w++;
      nleft -= 2;
    }
    /* mop up an odd byte, if necessary */
    if (nleft == 1)
    {
      *(unsigned char *) (&answer) = *(unsigned char *) w;
      sum += answer;
    }
    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);       /* add hi 16 to low 16 */
    sum += (sum >> 16);               /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return (answer);
}

int is_possible_port(port_t port, port_t *ports, int size) {

    for (int i = 0; i < size; i++) {
        if (port == ports[i])
            return 1;
    }
    return 0;
}

int parse_arg(char *arg, analyse_t *reader) {

    int ret = 0;
    char *tmp;
    char ipv4[16];

    memset(ipv4, 0, 16);
    memset(reader, 0, sizeof(analyse_t));

    while (arg)
    {
        if (strncmp(arg, "unix", 4) == 0) {
            ret |= FLAG_UNIX;
            arg = strchr(arg, ':');
            if (arg == NULL)
                return -1;
            arg++;
            tmp = strchr(arg, ';');
            if (tmp == NULL)
                memcpy(reader->unix_path, arg, strlen(arg));
            else
                memcpy(reader->unix_path, arg, tmp - arg);
            arg = tmp;
            if (arg != NULL)
                arg++;
        }
        else if (strncmp(arg, "ipv4", 4) == 0) {
            ret |= FLAG_IPV4;
            arg = strchr(arg, ':');
            if (arg == NULL)
                return -1;
            arg++;
            tmp = strchr(arg, ':');
            if (tmp == NULL)
                return -1;
            memcpy(ipv4, arg, tmp - arg);
            reader->listen_ipv4 = inet_addr(ipv4);
            arg = tmp;
            arg++;
            reader->listen_portv4 = htons(atoi(arg));
            arg = strchr(arg, ';');
            if (arg != NULL)
                arg++;
        }
        else
            return -1;
    }

    return ret;
}
