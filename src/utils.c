#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "defines.h"
#include "structs.h"

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

void free_request(request_t *req) {
    if (req->ipv4)
        free(req->ipv4);
    if (req->ipv4_mask)
        free(req->ipv4_mask);
    if (req->port)
        free(req->port);
}

static int check_ipv4(char *msg) {
    int i = 0;

    while (msg)
    {
        if (*msg == '.')
            i++;
        if (*msg == ':' || *msg == ' ' || *msg == ',' || *msg == '\n')
            return 0;
        if (*msg == '/')
            break;
        msg++;
    }
    if (i == 3)
        return 1;
    return 0;
}

static int check_ipv4_validity(char *ipv4) {
    int tmp;

    for (int i = 0; ipv4[i] && i < 16; i++) {
        if (!isdigit(ipv4[i]) && ipv4[i] != '.')
            return 0;
    }

    tmp = atoi(ipv4);
    if (tmp < 0 || tmp > 255)
        return 0;
    ipv4 = strchr(ipv4, '.');
    if (ipv4 == NULL)
        return 0;
    ipv4++;
    tmp = atoi(ipv4);
    if (tmp < 0 || tmp > 255)
        return 0;
    ipv4 = strchr(ipv4, '.');
    if (ipv4 == NULL)
        return 0;
    ipv4++;
    tmp = atoi(ipv4);
    if (tmp < 0 || tmp > 255)
        return 0;
    ipv4 = strchr(ipv4, '.');
    if (ipv4 == NULL)
        return 0;
    ipv4++;
    tmp = atoi(ipv4);
    if (tmp < 0 || tmp > 255)
        return 0;
    ipv4 = strchr(ipv4, '.');
    if (ipv4 != NULL)
        return 0;
    return 1;
}

// groume 0.0.0.0/0 80 500
// groume 192.168.0.0/16 443 80 500

int create_request(request_t *req, char *msg) {

    char ipv4[16];
    int i = 0;
    int ipv4nb = 0;
    //int ipv6nb = 0;
    int portnb = 0;
    int tmp;
    int tmp2;

    if (strncmp(msg, "groume", 6) != 0)
        return -1;
    else
        msg += 7;
    // Parsing ips to scan
    while (msg && *msg != ' ')
    {
        if (check_ipv4(msg)) {
            printf("is ipv4 : %s\n", msg);
            memset(ipv4, 0, 16);
            i = 0;
            while (*msg != '/' && msg && i < 16)
            {
                ipv4[i] = *msg;
                i++;
                msg++;
            }
            if (!check_ipv4_validity(ipv4))
                return printf("Bad ipv4\n"), free_request(req), -1;
            ipv4nb++;
            if (ipv4nb == 1) {
                req->ipv4 = malloc(sizeof(ipv4_t));
                req->ipv4_mask = malloc(sizeof(int));
                if (req->ipv4 == NULL || req->ipv4_mask == NULL)
                    return printf("Critical error\n"), free_request(req), -1;
            }
            else {
                req->ipv4 = realloc(req->ipv4, ipv4nb * sizeof(ipv4_t));
                req->ipv4_mask = realloc(req->ipv4_mask, ipv4nb * sizeof(int));
                if (req->ipv4 == NULL || req->ipv4_mask == NULL)
                    return printf("Critical error\n"), free_request(req), -1;
            }
            req->ipv4[ipv4nb-1] = inet_addr(ipv4);
            if (*msg != '/')
                return printf("Bad request\n"), free_request(req), -1;
            msg++;
            if (!isdigit(*msg))
                return printf("Bad request\n"), free_request(req), -1;
            tmp = atoi(msg);
            if (tmp < 0 || tmp > 32)
                return printf("Bad request\n"), free_request(req), -1;
            req->ipv4_mask[ipv4nb-1] = tmp;
            while (isdigit(*msg))
                msg++;
        } // else if (check_ipv6)
        if (*msg == ',')
            msg++;
        else if (*msg != ' ')
            return printf("missing or bad ip to scan 1\n"), free_request(req), -1;
    }
    if (ipv4nb == 0 /*|| ipv6nb == 0*/)
        return printf("missing or bad ip to scan 2\n"), free_request(req), -1;
    req->ipv4nb = ipv4nb;
    msg++; // passing space
    i = 0;
    // parsing port number to scan
    while (msg && *msg != ' ')
    {
        tmp = atoi(msg);
        if (tmp <= 0 || tmp > UINT16_MAX)
            return printf("Bad port number\n"), free_request(req), -1;
        portnb++;
        while (*msg != ' ' && *msg != ',' && *msg != '-' && msg)
            msg++;
        if (*msg == '-') {
            msg++;
            tmp2 = atoi(msg);
            if (tmp2 <= 0 || tmp2 > UINT16_MAX || tmp2 <= tmp)
                return printf("Bad port number\n"), free_request(req), -1;
            if (portnb == 1) {
                portnb += tmp2 - tmp;
                req->port = malloc(portnb * sizeof(port_t));
                if (req->port == NULL)
                    return printf("Critical error\n"), free_request(req), -1;
                while (i < portnb)
                {
                    req->port[i] = tmp + i;
                    i++;
                }
            }
            else {
                portnb += tmp2 - tmp;
                req->port = realloc(req->port, portnb * sizeof(port_t));
                if (req->port == NULL)
                    return printf("Critical error\n"), free_request(req), -1;
                while (i < portnb)
                {
                    req->port[i] = tmp + i;
                    i++;
                }
            }
            while (isdigit(*msg))
                msg++;
        }
        else {
            if (portnb == 1) {
                req->port = malloc(sizeof(port_t));
                if (req->port == NULL)
                    return printf("Critical error\n"), free_request(req), -1;
                req->port[portnb-1] = tmp;
            }
            else {
                req->port = realloc(req->port, portnb * sizeof(port_t));
                if (req->port == NULL)
                   return printf("Critical error\n"), free_request(req), -1;
                req->port[portnb-1] = tmp;
            }
        }
        if (*msg == ',')
            msg++;
    }
    if (portnb == 0)
        return printf("missing or bad port to scan\n"), free_request(req), -1;
    req->portnb = portnb;
    msg++; // passing space;
    req->nb = atoi(msg);
    if (req->nb <= 0)
        return printf("missing or bad number to scan\n"), free_request(req), -1;
    return 1;
}


// tmp function
void print_request(request_t req) {

    struct in_addr tmp;

    printf("number to scan = %d\n", req.nb);

    for (int i = 0; i < req.ipv4nb; i++) {
        tmp.s_addr = req.ipv4[i];
        printf("addr %s mask %d\n", inet_ntoa(tmp), req.ipv4_mask[i]);
    }
    printf("portnb = %d\n", req.portnb);
    for (int i = 0; i < req.portnb; i++) {
        printf("port to scan = %d\n", req.port[i]);
    }
}