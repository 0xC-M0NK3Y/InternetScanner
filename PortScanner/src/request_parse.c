#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "defines.h"
#include "structs.h"
#include "utils.h"

static inline int	check_password(char **str) {
	char	*ptr;

	// on vérifie que y'a bien un espèce après le mdp
	ptr = strchr(*str, ' ');
	if (ptr == NULL)
		return INVALID_REQUEST;

	// on coupe au niveau de l'espère, puis on le compare
	// à la variable d'environement "SCANNER_PASSWD"
	// ou 1488 si elle existe pas
	ptr[0] = 0;
	if (strcmp(*str, "groume" /*getenv("SCANNER_PASSWD")*/ ) != 0)
		return ptr[0] = ' ', INVALID_PASSWORD;

	// on le remet et on continue
	ptr[0] = ' ';
	*str = ptr+1;
	return 0;
}

static inline int	parse_target(target_address_t *target, char **str) {
	unsigned char	addr[16];
	char			*ptr;

	memset(target, 0, sizeof(*target));

	ptr = strchr(*str, '/');
	if (ptr == NULL)
		return INVALID_REQUEST;
	ptr[0] = 0;

	if (inet_pton(AF_INET, *str, addr)) {
		ptr[0] = '/';
		target->type = 4;
		target->addr.v4 = ((struct in_addr *)addr)->s_addr;

		// on vérifie que le CDIR dépasse pas 32 (+ balec overflow)
		if ((unsigned int)atoi(ptr+1) > 32)
			return INVALID_MASK;

		target->CDIR = atoi(ptr+1);
	} else if (inet_pton(AF_INET6, *str, addr)) {
		ptr[0] = '/';
		target->type = 6;
		memcpy(&target->addr.v6, addr, 16);

		// on vérifie que le CDIR dépasse pas 128 (+ balec overflow)
		if ((unsigned int)atoi(ptr+1) > 128)
			return INVALID_MASK;

		target->CDIR = atoi(ptr+1);
	} else
		return ptr[0] = '/', INVALID_IP;

	*str = ptr+1+strspn(ptr+1, "0123456789");
	return 0;
}

static inline int parse_port(port_t **ports, size_t *port_count, char **str) {

	while (*str && **str != ' ')
	{
		int port = strtol(*str, str, 10);
		if (port <= 0 || port > UINT16_MAX)
			return INVALID_PORT;
		if (**str == '-') {
			str[0]++;
			int port_to = strtol(*str, str, 10);
			int tmp;
			if (port_to <= 0 || port_to > UINT16_MAX || port > port_to)
				return INVALID_PORT;
			tmp = *port_count;
			*port_count += port_to - port;
			if (tmp == 0)
				*ports = malloc(*port_count * sizeof(port_t));
			else
				*ports = realloc(*ports, *port_count * sizeof(port_t));
			if (*ports == NULL)
				return CRITICAL_ERROR;
			for (int i = port; i < port_to; i++) {
				(*ports)[tmp] = htons(i);
				tmp++;
			}
		} else {
			port_count[0]++;
			if (*port_count == 1)
				*ports = malloc(sizeof(port_t));
			else
				*ports = realloc(*ports, *port_count * sizeof(port_t));
			if (*ports == NULL)
				return CRITICAL_ERROR;
			(*ports)[*port_count-1] = htons(port);
		}
		if (**str == ',')
			str[0]++;
	}

	return 0;
}

/* parses str into request_t struct */
int	parse_request(request_t	*req, char *str) {

	int r;

	memset(req, 0, sizeof(request_t));

	if ((r = check_password(&str)) < 0)
		return r;
	while (str && *str != ' ')
	{
		target_address_t target;

		// ca parse on se retrouve a la virgule ou espace
		if ((r = parse_target(&target, &str)) < 0)
			return r;
		req->addr_count++;
		if (req->addr_count == 1)
			req->addresses = malloc(sizeof(target_address_t));
		else
			req->addresses = realloc(req->addresses, req->addr_count * sizeof(target_address_t));
		if (req->addresses == NULL)
			return CRITICAL_ERROR;
		memcpy(&req->addresses[req->addr_count-1], &target, sizeof(target_address_t));
		if (*str == ',')
			str++;
	}
	str++;
	if ((r = parse_port(&req->seek_port, &req->port_count, &str)) < 0)
		return free(req->addresses), r;
	str++;
	req->seek_count = strtol(str, &str, 10);
	if (*str != '\n')
		return free(req->addresses), free(req->seek_port), INVALID_REQUEST;

	// On doit créer les ratio pour prendre aléatoirement
	if (req->seek_count != 0)
		if ((r = create_ratio(req)) < 0)
			return free(req->addresses), r;

	req->curr_addr = 0;

	return 0;
}

void print_request(request_t req) {

	struct in_addr tmp;

	printf("<Request>\n");
	printf("  Seek number = %ld\n", req.seek_count);
	printf("  Target nb = %ld\n", req.addr_count);
	for (size_t i = 0; i < req.addr_count; i++) {
		printf("    Target type = %d\n", req.addresses[i].type);
		if (req.addresses[i].type == 4) {
			tmp.s_addr = req.addresses[i].addr.v4;
			printf("      Target addr = %s\n", inet_ntoa(tmp));
		} else if (req.addresses[i].type == 6) {
			printf("      Target addr = ");
			for (size_t j = 0; j < 16; j++)
				printf("%X:", req.addresses[i].addr.v6.__in6_u.__u6_addr8[i]);
			printf("\n");
		}
		printf("    Target mask = %d\n", req.addresses[i].CDIR);
		printf("    Target ratio = %d\n\n", req.addresses[i].ratio);
	}
	printf("  Somme ratio: %d\n", req.somme_ratio);

	printf("  Port nb = %ld\n", req.port_count);
	for (size_t i = 0; i < req.port_count; i++)
		printf("    Port = %d\n", ntohs(req.seek_port[i]));
	printf("</Request>\n");
}

void free_request(request_t *req) {
	free(req->addresses);
	free(req->seek_port);
}
