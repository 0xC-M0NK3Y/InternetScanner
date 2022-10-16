#ifndef UTILS_H
# define UTILS_H

#include "defines.h"
#include "structs.h"

ipv4_t get_random_ip(void);
unsigned short in_cksum(unsigned short *addr, int len);
int is_possible_port(port_t port, port_t *ports, int size);
int parse_arg(char *arg, analyse_t *reader);
int create_request(request_t *req, char *msg);
void free_request(request_t *req);
void print_request(request_t req);
#endif