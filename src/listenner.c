#include <stdio.h>
#include <stdlib.h>

#include <errno.h>

#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <pthread.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include "defines.h"
#include "packet.h"
#include "utils.h"

#define BLACKLIST_SIZE 50

int not_in_blacklist(ipv4_t *blacklist, ipv4_t ip) {
    for (int i = 0; i < BLACKLIST_SIZE; i++) {
        if (ip == blacklist[i])
            return 0;
    }
    return 1;
}

static uint8_t get_biggest_cdir(reqlist_t *reqlist, ipv4_t ip, port_t port) {
    uint8_t CDIR = 0;

    for (size_t i = 0; i < reqlist->len; i++) {
        request_t *req = &(reqlist->ptr[i].request);
        for (size_t j = 0; j < req->port_count; j++) {
            if (port == req->seek_port[j]) {
                for (size_t k = 0; k < req->addr_count; k++) {
                    uint32_t bit_mask = ~((1 << (32 - req->addresses[k].CDIR)) - 1);
                    ipv4_t first_ip = ntohl(req->addresses[k].addr.v4);

                    if (req->addresses[k].CDIR == 0)
                        bit_mask = 0;
                    ip = ntohl(ip);
                    if (ip >= (first_ip & bit_mask) && ip <= (first_ip | ~bit_mask)) {
                        if (req->addresses[k].CDIR > CDIR)
                            CDIR = req->addresses[k].CDIR;
                    }
                }
            }
        }
    }
    return CDIR;
}


static void send_to_correspondant_client(reqlist_t *reqlist, ipv4_t ip, port_t port, uint8_t CDIR) {
    for (size_t i = 0; i < reqlist->len; i++) {
        request_t *req = &(reqlist->ptr[i].request);
        for (size_t j = 0; j < req->port_count; j++) {
            if (port == req->seek_port[j]) {
                for (size_t k = 0; k < req->addr_count; k++) {
                    uint32_t bit_mask = ~((1 << (32 - req->addresses[k].CDIR)) - 1);
                    ipv4_t first_ip = ntohl(req->addresses[k].addr.v4);

                    if (req->addresses[k].CDIR == 0)
                        bit_mask = 0;
                    ip = ntohl(ip);
                    if (ip >= (first_ip & bit_mask) && ip <= (first_ip | ~bit_mask)) {
                        if (req->addresses[k].CDIR == CDIR) {
                            struct in_addr tmp;
                            char ret[23];
                            int len;

                            tmp.s_addr = htonl(ip);
                            memset(ret, 0, 23);
                            snprintf(ret, 23, "%s:%d\n", inet_ntoa(tmp), ntohs(port));
                            len = strlen(ret);
                            pthread_mutex_unlock(&reqlist->mutex);
                            send(reqlist->ptr[i].client, ret, len, 0);
                            pthread_mutex_lock(&reqlist->mutex);
                            if (req->seek_count != 0)
                                req->scan_count++;
                        }
                    }
                }
            }
        }
    }
}

void *listenner(void *data) {
    reqlist_t *reqlist = (reqlist_t *)data;
    SOCKET sock4;
    uint8_t buffer[5000];
    IP_HEADER *ip_hdr;
    TCP_HEADER *tcp_hdr;
    /*port_t ports_possible[POSSIBLE_PORTS_SIZE] = {1234, 1235, 1236, 1237, 1238, 1239, 2345, 2346, 
                                         2347, 2348, 3456, 3457, 3458, 3459, 4567, 4568, 
                                         4569, 5678, 5679, 1111, 1212, 1313, 1414, 1515,
                                         1616, 1717, 1818, 1919, 2222, 2323, 2424, 2525};*/
	port_t ports_possible[POSSIBLE_PORTS_SIZE] = {6969};
    uint32_t key[2] = {696969, 262626};
    int r;
    //ipv4_t blacklist[BLACKLIST_SIZE];

    sock4 = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock4 < 0) {
        perror("socket");
        return NULL;
    }

    printf("Thread Listenner Started\n");
    while (1)
    {
        r = recv(sock4, buffer, 5000, 0);
        if (r < 0)
            perror("recv");
        if (r == 0)
            printf("empty request or socket shutdown\n");
        else {
            // IPV4 seulement !!! IP_HEADER structure du ip header pour ipv4
            ip_hdr = (IP_HEADER *)buffer;
            tcp_hdr = (TCP_HEADER *)(buffer + ip_hdr->ihl * 4);
            if (tcp_hdr->th_flags == (TH_SYN | TH_ACK)) {
                ipv4_t ip = ip_hdr->saddr;
                port_t port = tcp_hdr->th_dport;
                
                if (ntohs(port) == ports_possible[GET_PORT(ip, tcp_hdr->th_sport, key[(time(NULL)/10)%2])]
                 || ntohs(port) == ports_possible[GET_PORT(ip, tcp_hdr->th_sport, key[(time(NULL)/10-1)%2])]) {
                    pthread_mutex_lock(&reqlist->mutex);
                    // On tourne sur chaque requete courante, chaque port pour voir si ca correspond et trouver a quel client envoyer
                    uint8_t CDIR = get_biggest_cdir(reqlist, ip, tcp_hdr->th_sport);
                    send_to_correspondant_client(reqlist, ip, tcp_hdr->th_sport, CDIR);
                    pthread_mutex_unlock(&reqlist->mutex);
                }
            }
        }

    }

    close(sock4);

    printf("End listenner\n");

    return NULL;
}
