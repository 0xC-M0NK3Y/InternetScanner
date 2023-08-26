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

extern const port_t ports_possible[POSSIBLE_PORTS_SIZE];

#define BLACKLIST_SIZE 50

int not_in_blacklist(blacklist_t *blacklist, ipv4_t ip, port_t port) {
	for (int i = 0; i < BLACKLIST_SIZE; i++) {
		if (ip == blacklist[i].ip && port == blacklist[i].port)
			return 0;
	}
	return 1;
}

static uint8_t get_biggest_cdir(reqlist_t *reqlist, ipv4_t ip, port_t port) {
	uint8_t CDIR = 0;

	ip = ntohl(ip);
	for (size_t i = 0; i < reqlist->len; i++) {
		request_t *req = &(reqlist->ptr[i].request);
		if (req->seek_count && req->scan_count >= req->seek_count)
			continue;
		for (size_t j = 0; j < req->port_count; j++) {
			if (port == req->seek_port[j]) {
				for (size_t k = 0; k < req->addr_count; k++) {
					uint32_t	bit_mask = ~((1 << (32 - req->addresses[k].CDIR)) - 1);
					ipv4_t		first_ip = ntohl(req->addresses[k].addr.v4);

					if (req->addresses[k].CDIR == 0)
						bit_mask = 0;
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
	ip = ntohl(ip);
	for (size_t i = 0; i < reqlist->len; i++) {
		request_t *req = &(reqlist->ptr[i].request);
		if (req->seek_count && req->scan_count >= req->seek_count)
			continue;
		for (size_t j = 0; j < req->port_count; j++) {
			if (port == req->seek_port[j]) {
				for (size_t k = 0; k < req->addr_count; k++) {
					uint32_t	bit_mask = ~((1 << (32 - req->addresses[k].CDIR)) - 1);
					ipv4_t		first_ip = ntohl(req->addresses[k].addr.v4);

					if (req->addresses[k].CDIR == 0)
						bit_mask = 0;
					if (ip >= (first_ip & bit_mask) && ip <= (first_ip | ~bit_mask)) {//ip >= (first_ip & bit_mask) && ip <= (first_ip | ~bit_mask)) {
						if (req->addresses[k].CDIR == CDIR) {
							struct in_addr	tmp;
							char			ret[23];
							int				len;

							tmp.s_addr = htonl(ip);
							memset(ret, 0, 23);
							snprintf(ret, 23, "%s:%d\n", inet_ntoa(tmp), ntohs(port));
							len = strlen(ret);
							pthread_mutex_unlock(&reqlist->mutex);
							send(reqlist->ptr[i].client, ret, len, MSG_NOSIGNAL);
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
	reqlist_t	*reqlist = (reqlist_t *)data;
	socket_t	sock4;
	uint32_t	key[2] = {696969, 262626};
	int			r; // for recv
	blacklist_t	blacklist[BLACKLIST_SIZE];
	int			i = 0; // for blacklist

	memset(blacklist, 0, sizeof(blacklist));

	sock4 = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sock4 < 0)
		return perror("socket"), NULL;

	printf("Thread Listenner Started\n");
	while (1)
	{
		uint8_t	buffer[5000];

		memset(buffer, 0, sizeof(buffer));
		r = recv(sock4, buffer, 5000, 0);
		if (r < 0)
			perror("recv");
		if (r == 0)
			printf("empty request or socket shutdown\n");
		else {
			// IPV4 seulement !!! IP_HEADER structure du ip header pour ipv4
			IP_HEADER	*ip_hdr = (IP_HEADER *)buffer;
			TCP_HEADER	*tcp_hdr = (TCP_HEADER *)(buffer + ip_hdr->ihl * 4);
			if (tcp_hdr->th_flags == (TH_SYN | TH_ACK)) {
				ipv4_t ip = ip_hdr->saddr;
				port_t port = ntohs(tcp_hdr->th_dport);

				if (not_in_blacklist(blacklist, ip, tcp_hdr->th_sport) &&
				   (port == ports_possible[GET_PORT(ntohl(ip), tcp_hdr->th_sport, key[(time(NULL)/10)%2])]
				 || port == ports_possible[GET_PORT(ntohl(ip), tcp_hdr->th_sport, key[(time(NULL)/10-1)%2])])) {
					pthread_mutex_lock(&reqlist->mutex);
					// On tourne sur chaque requete courante, chaque port pour voir si ca correspond et trouver a quel client envoyer
					uint8_t CDIR = get_biggest_cdir(reqlist, ip, tcp_hdr->th_sport);
					send_to_correspondant_client(reqlist, ip, tcp_hdr->th_sport, CDIR);
					blacklist[i%BLACKLIST_SIZE].ip = ip;
					blacklist[i%BLACKLIST_SIZE].port = tcp_hdr->th_sport;
					i++;
					pthread_mutex_unlock(&reqlist->mutex);
				}
			}
		}

	}

	close(sock4);
	printf("End listenner\n");
	return NULL;
}
