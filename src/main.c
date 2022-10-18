#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include <pthread.h>

#include <fcntl.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "packet.h"
#include "utils.h"
#include "structs.h"
#include "defines.h"

#include "request_parse.h"

#include "scanner.h"
#include "listenner.h"


int main(int argc, char **argv)
{
    analyse_t reader;           // utiliser pour creer les addresse
    int flags;      
    SOCKET *socks;              // socket pour ecouter les demande des clients
    int nb_socks = 0;
    int i = 0;
    SOCKET client;              // socket du client qui se connect
    int ipv4_sock = -1;
    int unix_sock = -1;
    POLLFD pollfd[50];
    char msg[100];
    int msg_len;
    request_t *req;
    communicator_t bridge;
    pthread_t listen_thread;
    pthread_t scan_thread;
    char *response;

    if (argc != 2) {
        printf("Usage: %s <listen_format>\n", argv[0]);
        return 1;
    }

    flags = parse_arg(argv[1], &reader);
    if (flags <= 0) {
        printf("Bad argument\n");
        return 1;
    }

    memset(pollfd, 0, 50 * sizeof(POLLFD));
    memset(&req, 0, sizeof(request_t));

    if ((flags & FLAG_UNIX) == FLAG_UNIX)
        nb_socks++;
    if ((flags & FLAG_IPV4) == FLAG_IPV4)
        nb_socks++;

    socks = malloc(nb_socks * sizeof(SOCKET));
    if (socks == NULL) {
        printf("Critical error\n");
        return 1;
    }

    if ((flags & FLAG_IPV4) == FLAG_IPV4) {
        struct in_addr tmp;
        SOCKADDRV4 ipv4_addr;
        memset(&ipv4_addr, 0, sizeof(SOCKADDRV4));
        ipv4_addr.sin_family = AF_INET;
        ipv4_addr.sin_addr.s_addr = reader.listen_ipv4;
        ipv4_addr.sin_port = reader.listen_portv4;

        socks[i] = socket(AF_INET, SOCK_STREAM, 0);
        if (socks[i] < 0)
            return perror("Socket"), free(socks), 1;
        if (bind(socks[i], (struct sockaddr *)&ipv4_addr, sizeof(SOCKADDRV4)) < 0)
            return perror("Binding"), free(socks), 1;
        if (listen(socks[i], 0) < 0)
            return perror("Listening"), free(socks), 1;
        ipv4_sock = i;
        pollfd[ipv4_sock].fd = socks[ipv4_sock];
        pollfd[ipv4_sock].events = POLLIN;
        pollfd[ipv4_sock].revents = 0;
        i++;
        tmp.s_addr = reader.listen_ipv4;
        printf("Listenning on ipv4 %s:%d\n", inet_ntoa(tmp), ntohs(reader.listen_portv4));
    }
    if ((flags & FLAG_UNIX) == FLAG_UNIX) {
        SOCKADDRUN unix_addr;
        memset(&unix_addr, 0, sizeof(SOCKADDRUN));
        memcpy(unix_addr.sun_path, reader.unix_path, strlen(reader.unix_path));

        socks[i] = socket(AF_UNIX, SOCK_STREAM, 0);
        if (socks[i] < 0)
            return perror("Socket"), free(socks), 1;
        unix_sock = i;
        pollfd[unix_sock].fd = socks[unix_sock];
        pollfd[unix_sock].events = POLLIN;
        pollfd[unix_sock].revents = 0;
        i++;
        printf("Listenning on unix socket, path %s\n", reader.unix_path);
    }

    bridge.stop = malloc(1);
    if (bridge.stop == NULL)
        return perror("malloc"), free(socks), free(req), 1;
    bridge.stop[0] = 0;

    printf("Waiting for client\n");
    while (1)
    {
        if (poll(pollfd, i, -1) < 0)
            return perror("poll"), free(socks), 1;
        for (int j = 0; j < i; j++) {
            if (pollfd[j].revents == POLLIN) {
                if (j == ipv4_sock) {
                    SOCKADDRIN client_addr;
                    socklen_t tmp;

                    memset(&client_addr, 0, sizeof(SOCKADDRIN));
                    client = accept(socks[ipv4_sock], (struct sockaddr *)&client_addr, &tmp);
                    if (client > 0) {
                        pollfd[i].fd = client;
                        pollfd[i].events = POLLIN;
                        pollfd[i].revents = 0;
                        fcntl(pollfd[i].fd, F_SETFL, fcntl(pollfd[i].fd, F_GETFL, 0) | O_NONBLOCK);
                        i++;
                    }
                    printf("Client connected from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
                }
                else if (j == unix_sock) {
                    // handle unix socket
                }
                else { // client socket
                    int r;
                    memset(msg, 0, 100);

                    msg_len = recv(pollfd[j].fd, msg, 100, 0);
                    if (msg_len == 0) {
                        printf("Client disconnected\n");
                        memmove(&pollfd[j], &pollfd[j+1], (i - j) * sizeof(POLLFD));
                        i--;
                        continue;
                    }
                    printf("Received request len : %d\n", msg_len);
                    req = malloc(sizeof(request_t));
                    if (req == NULL)
                        return perror("malloc"), free(socks), 1;
                    bridge.request = req;
                    if ((r = parse_request(req, msg)) < 0)
                        printf("Failed create request : %d\n", r);
                    else {
                        bridge.client = pollfd[j].fd;
                        bridge.stop[0] = 0;
                        pthread_create(&scan_thread, NULL, scanner, (void *)&bridge);
                        pthread_create(&listen_thread, NULL, listenner, (void *)&bridge);
                        pthread_join(listen_thread, (void **)&response);
                        pthread_join(scan_thread, NULL);
                        bridge.stop[0] = 1;
                        free_request(req);
                        printf("Request done\n");
                    }
                }
            }
        }
    }
}