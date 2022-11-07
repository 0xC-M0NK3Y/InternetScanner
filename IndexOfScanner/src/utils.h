#ifndef UTILS_H
# define UTILS_H

#include "structs.h"

int check_if_indexof(char *data);
void init_string(struct string *s);
size_t writefunc(void *ptr, size_t size, size_t nmemb, struct string *s);
#endif