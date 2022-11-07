#ifndef REQUEST_PARSE_H
# define REQUEST_PARSE_H

#include "structs.h"

int	parse_request(request_t	*req, char *str);
void print_request(request_t req);
void free_request(request_t *req);
#endif