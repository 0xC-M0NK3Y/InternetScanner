#ifndef STRUCTS_H
# define STRUCTS_H

#include <unistd.h>

#include "defines.h"

typedef uint8_t stop_t;

typedef struct analyse
{
	ipv4_t	listen_ipv4;
	port_t	listen_portv4;
	char	unix_path[108];
}   analyse_t;

typedef struct target_address {
	union	{
		ipv4_t	v4;
		ipv6_t	v6;
	} addr;
	uint8_t	type;	/* v4/v6 */
	uint8_t	CDIR;	/* .../x */
	uint32_t ratio;
}	target_address_t;

typedef struct request {
	target_address_t	*addresses;
	size_t				curr_addr;
	size_t				addr_count;
	size_t				scan_count; 	/* pour savoir à où on en est au niveau de la liste d'IP */
	size_t				seek_count;		/* le nombre de résultat qu'on veut */
	port_t				*seek_port;
	size_t				port_count;
	uint32_t			somme_ratio;

	/* si on scan toutes les IPs, faut choisir un temps d'attente
	 * pour recevoir les réponses des scans sur les dernières IPs
	 * donc faut stocker le moment de l'envoie du dernier paquet pour ça
	*/
	time_t				finished_at;
} request_t;

typedef struct communicator {
	request_t		request;
	socket_t		client;
} communicator_t;

typedef struct request_list {
	communicator_t		*ptr;
	volatile size_t		len;
	size_t				cap;
	pthread_mutex_t		mutex;
}	reqlist_t;

typedef struct blacklist {
	ipv4_t ip;
	port_t port;
}	blacklist_t;

/*
typedef struct found_address {
	uint8_t type;
	union {
		ipv4_t *v4;
		ipv6_t *v6;
	} addr;
	size_t count;
} found_address_t;

typedef struct response {
	uint8_t 		success;
	found_address_t *found;
} response_t;
*/


#endif
