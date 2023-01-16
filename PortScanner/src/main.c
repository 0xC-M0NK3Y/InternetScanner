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
	analyse_t reader;		   // utiliser pour creer les addresse
	int flags;	  
	SOCKET *socks;			  // socket pour ecouter les demande des clients
	int nb_socks = 0;
	int i = 0;				  // pollnb
	SOCKET client;			  // socket du client qui se connect
	int ipv4_sock = -1;
	int unix_sock = -1;
	POLLFD pollfd[50];
	pthread_t listen_thread;	// thread ecoute
	pthread_t scan_thread;	  // thread envoi
	reqlist_t *reqlist;
	communicator_t *bridge = NULL;

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

	if ((flags & FLAG_UNIX) == FLAG_UNIX)
		nb_socks++;
	if ((flags & FLAG_IPV4) == FLAG_IPV4)
		nb_socks++;

	socks = malloc(nb_socks * sizeof(SOCKET));
	if (socks == NULL) {
		printf("Critical error\n");
		return 1;
	}

	srandom(time(NULL));

	/* Construction de l'écoute du serveur. */

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
		setsockopt(socks[i], SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
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

	reqlist = malloc(sizeof(reqlist_t));
	if (reqlist == NULL)
		return perror("malloc"), free(socks), 1;

	reqlist->ptr = bridge;
	reqlist->len = 0;
	reqlist->cap = 50;

	pthread_mutex_init(&reqlist->mutex, NULL);

	/* Deux thread un scanner (envoi les paquets) et un listenner (recoit les paquets) */
	/* Le main ecoute les requete et les construit, les threads scanner et listenner se mettent a travailler */

	pthread_create(&scan_thread, NULL, scanner, (void *)reqlist);
	pthread_create(&listen_thread, NULL, listenner, (void *)reqlist);

	printf("Waiting for client\n");
	while (1)
	{
		if (poll(pollfd, i, 1000) < 0)
			perror("poll");
		// ckeck ici chaque requete le status
		// TODO: si passer le cap realloc a la baisse
		pthread_mutex_lock(&reqlist->mutex);
		for (size_t j = 0; j < reqlist->len; j++) {
			request_t *req = &(reqlist->ptr[j].request);
			if (req->seek_count == 0 && req->finished_at) {
				if (time(NULL) - req->finished_at >= TIMEOUT) {
					send(reqlist->ptr[j].client, "end\n", 5, MSG_NOSIGNAL);
					memmove(&reqlist->ptr[j], &reqlist->ptr[j + 1], (reqlist->len - j) * sizeof(communicator_t));
					printf("request %ld ended\n", j+1);
					reqlist->len--;
					j--;
				}
			} else if (req->seek_count) {
				if (req->scan_count >= req->seek_count) {
					send(reqlist->ptr[j].client, "end\n", 5, MSG_NOSIGNAL);
					memmove(&reqlist->ptr[j], &reqlist->ptr[j + 1], (reqlist->len - j) * sizeof(communicator_t));
					printf("request %ld ended\n", j+1);
					reqlist->len--;
					j--;
				}
			}
		}
		pthread_mutex_unlock(&reqlist->mutex);
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
						printf("Client connected from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
					}
				}
				else if (j == unix_sock) {
					// handle unix socket
				}
				else { // client socket
					int len;
					char msg[100];
					int r;

					memset(msg, 0, 100);
					len = recv(pollfd[j].fd, msg, 100, 0);
					if (len == 0) {
						printf("Client disconnected\n");
						memmove(&pollfd[j], &pollfd[j+1], (i - j) * sizeof(POLLFD));
						i--;
						continue;
					}
					pthread_mutex_lock(&reqlist->mutex);
					if (reqlist->len >= reqlist->cap) {
						send(pollfd[j].fd, "Y'a trop de requete la zin att un peu !\n", 41, MSG_NOSIGNAL);
						continue;
					}
					reqlist->ptr = realloc(reqlist->ptr, (reqlist->len+1) * sizeof(communicator_t));
					reqlist->ptr[reqlist->len].client = pollfd[j].fd;
					if ((r = parse_request(&(reqlist->ptr[reqlist->len].request), msg)) < 0)
						printf("Failed create request %d\n", r);
					else
						reqlist->len++;
					printf("New request %ld\n", reqlist->len);
					pthread_mutex_unlock(&reqlist->mutex);
				}
			}
		}
	}
}
