#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <time.h>

#include <pthread.h>

#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "defines.h"
#include "packet.h"
#include "utils.h"

#include "listenner.h"


static inline void send_to_ipv4_mask(SOCKET sock, ipv4_t first_ip, uint8_t mask, port_t dest_port, port_t *ports_possible,  ipv4_t source_ip, SOCKADDRIN dest_addr, uint32_t *key) {
    port_t source_port;
    packet_t packet;
    struct in_addr tmp;
    uint32_t bit_mask = ~((1 << (32 - mask)) - 1);

    for (ipv4_t ip = first_ip & (bit_mask >> (32 - mask)); ip <= (first_ip | (~bit_mask << mask)); ip++) {
        source_port = htons(ports_possible[GET_PORT(ip, 80, key[(time(NULL)/10)%2])]);
        create_packet4(&packet, source_ip, ip, dest_port, source_port);
        if (sendto(sock, &packet, PACKET_SIZE, 0, (struct sockaddr *)&dest_addr, sizeof(SOCKADDRIN)) < 0) {
            tmp.s_addr = ip;
            perror("sendto");
            printf("On %s:%d from %d\n", inet_ntoa(tmp), ntohs(dest_port), ntohs(source_port));
        }
    }
}

static inline int  quit_cond(uint128_t *elem, size_t nb) {
  uint128_t space = 0xFFFFFFFF;

  for (size_t i = 0; i < nb; i++) {
      if (elem[i] > space)
        return 1;
    space -= elem[i];
  }
  return 0;
}

static uint32_t *create_ratio(uint128_t *ratio, request_t req) {
    uint128_t min;
    size_t    index;
    uint32_t *ret;

    ret = malloc(req.addr_count * sizeof(uint32_t));
    if (ret == NULL)
        return perror("malloc ratio"), NULL;

    // On stock le nombre de possibilité de chaque target, mask
    for (size_t i = 0; i < req.addr_count; i++) {
        if (req.addresses[i].type == 4) {
            ratio[i] = ((uint128_t) 1 << (32 - req.addresses[i].CDIR));
        }
        else if (req.addresses[i].type == 6) {
            if (req.addresses[i].CDIR == 0)
                ratio[i] = ((uint128_t)1 << (128 - req.addresses[i].CDIR)) - 1;
            else
                ratio[i] = ((uint128_t)1 << (128 - req.addresses[i].CDIR));
        }
    }
    min = ratio[0];
    index = 0;
    // On cherche le plus petit
    for (size_t i = 1; i < req.addr_count; i++) {
        if (ratio[i] < min) {
            min = ratio[i];
            index = i;
        }
    }
    // On créer les ratios
    for (size_t i = 0; i < req.addr_count; i++) {
        if (i != index)
            ratio[i] = min / ratio[i];
    }
    ratio[index] = ratio[index] / ratio[index]; // = 1;

    while (quit_cond(ratio, req.addr_count))
    {
        for (size_t i = 0; i < req.addr_count; i++) {
            if (ratio[i] > 1)
                ratio[i] >>= 1;
        }
    }

    for (size_t i = 0; i < req.addr_count; i++)
        ret[i] = (uint32_t)ratio[i];

    free(ratio);
    return ret;
}

static uint32_t somme_ratio(uint32_t *ratio, size_t nb) {
    uint32_t ret = 0;

    for (size_t i = 0; i < nb; i++)
        ret += ratio[i];
    return ret;
}

uint32_t get_index(uint32_t rand, uint32_t *ratio, size_t nb) {
    for (size_t i = 0; i < nb; i++) {
        if (rand - ratio[i] <= 0)
            return i;
    }
    return nb - 1;
}

ipv4_t get_random_ipv4(ipv4_t addr, uint8_t mask) {
    uint32_t bit_mask = ~((1 << (32 - mask)) - 1);
    ipv4_t ip = addr & (bit_mask >> (32 - mask)); 
    uint64_t rand = random() % (uint64_t)((uint64_t) 1 << (32 - mask));

    ip = ntohl(ip);
    ip += (uint32_t)rand;
    ip = htonl(ip);

    return ip;
}

port_t get_random_port(port_t *ports, size_t nb) {
    uint32_t rand = random() % nb;
    return *(ports + rand);
}

void *scanner(void *bridge) {
    communicator_t *brd = bridge;
    request_t *req = brd->request;
    uint8_t *stop = brd->stop;
    target_address_t *addresses = req->addresses;
    size_t port_count = req->port_count;
    port_t *seek_port = req->seek_port;
    size_t addr_count = req->addr_count;
    ipv4_t source_ip = inet_addr("192.168.1.27");
    uint32_t key[2] = {696969, 262626};
    SOCKET sock;
    SOCKADDRIN dest_addr;
    int dummy = 1;
    const int *pdummy = &dummy;
    port_t ports_possible[POSSIBLE_PORTS_SIZE] = {1234, 1235, 1236, 1237, 1238, 1239, 2345, 2346, 
                                                  2347, 2348, 3456, 3457, 3458, 3459, 4567, 4568, 
                                                  4569, 5678, 5679, 1111, 1212, 1313, 1414, 1515,
                                                  1616, 1717, 1818, 1919, 2222, 2323, 2424, 2525};
    uint128_t *tmp_ratio;
    uint32_t *ratio;
    uint32_t somme;
    uint32_t tmp_rand;
    uint32_t index;
    uint64_t *tmp_ptr;

    memset(&dest_addr, 0, sizeof(SOCKADDRIN));

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("socket");
        return NULL;
    }

    // Header deja fait
    //  changer les option de la socket (kernel y touche pas)
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, pdummy, sizeof(dummy)) < 0) {
        perror("setsockopt");
        return NULL;
    }
    
    dest_addr.sin_addr.s_addr = inet_addr("8.8.8.8");

    if (req->seek_count == 0)
        //scanner tout;

    // Si que 1 addr somme sera egale à 1
    printf("try malloc %lu\n", addr_count * sizeof(uint64_t) * 2);
    fflush(stdout);
    tmp_ptr = malloc(addr_count * sizeof(uint64_t) * 2);
    if (tmp_ptr == NULL)
        return printf("Failed malloc %d\n", __LINE__), NULL;
    tmp_ratio = (uint128_t *)tmp_ptr;
    ratio = create_ratio(tmp_ratio, *req);
    somme = somme_ratio(ratio, addr_count);

    printf("Scanner thread start [Random]\n");

    // Sinon scan random
    while (!stop[0])
    {
        tmp_rand = random() % somme;
        index = get_index(tmp_rand, ratio, addr_count);
        if (addresses[index].type == 4) {
            ipv4_t ip = get_random_ipv4(addresses[index].addr.v4, addresses[index].CDIR);
            port_t dest_port = get_random_port(seek_port, port_count);
            port_t source_port = htons(ports_possible[GET_PORT(ip, dest_port, key[(time(NULL)/10)%2])]);
            packet_t packet;
            struct in_addr tmp;
            tmp.s_addr = ip;
            //printf("try send to %s\n", inet_ntoa(tmp));
            dest_addr.sin_port = dest_port;
            create_packet4(&packet, source_ip, ip, dest_port, source_port);
            if (sendto(sock, &packet, PACKET_SIZE, 0, (struct sockaddr *)&dest_addr, sizeof(SOCKADDRIN)) < 0) {
                tmp.s_addr = ip;
                perror("sendto");
                printf("On %s:%d from %d\n", inet_ntoa(tmp), ntohs(dest_port), ntohs(source_port));
            }
        } else if (addresses[index].type == 6) {

        } else {
            // on devrait jamais rentrer ici
        }
    }

    close(sock);

    printf("End scanner\n");

    return NULL;
}