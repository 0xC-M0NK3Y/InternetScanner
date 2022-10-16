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

void *scanner(void *req) {
    SOCKET scan_sock;                   // socket pour scanner
    packet_t packet;
    SOCKADDR addr;
    int dummy = 1;
    const int *pdummy = &dummy;
    port_t ports_possible[POSSIBLE_PORTS_SIZE] = {1234, 1235, 1236, 1237, 1238, 1239, 2345, 2346, 
                                                  2347, 2348, 3456, 3457, 3458, 3459, 4567, 4568, 
                                                  4569, 5678, 5679, 1111, 1212, 1313, 1414, 1515,
                                                  1616, 1717, 1818, 1919, 2222, 2323, 2424, 2525};
    port_t port = 0;
    ipv4_t rand_ip;
    ipv4_t source_ip = inet_addr("192.168.1.27");
    uint32_t key[2] = {696969, 262626};
    port_t *http;

    memset(&addr, 0, sizeof(SOCKADDR));

    srand(time(NULL));

    scan_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (scan_sock < 0) {
        perror("socket");
        return 1;
    }

    // Header deja fait
    //  changer les option de la socket (kernel y touche pas)
    if(setsockopt(scan_sock, IPPROTO_IP, IP_HDRINCL, pdummy, sizeof(dummy)) < 0) {
        perror("setsockopt");
        return 1;
    }

    http = htons(80);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("8.8.8.8");
    addr.sin_port = http;


    struct in_addr tmp;

    printf("Start scanning\n");

    while (1)
    {
        rand_ip = get_random_ip();
        port = htons(ports_possible[GET_PORT(rand_ip, 80, key[(time(NULL)/10)%2])]);
        create_packet(&packet, source_ip, rand_ip, http, port);
        if (sendto(scan_sock, &packet, PACKET_SIZE, 0, (struct sockaddr *)&addr, sizeof(SOCKADDR)) < 0) {
            tmp.s_addr = rand_ip;
            perror("sendto");
            printf("On %s:%d from %d\n", inet_ntoa(tmp), ntohs(http), ntohs(port));
        }
    }

    close(scan_sock);
    return 0;
}