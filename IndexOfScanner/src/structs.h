#ifndef STRUCTS_H
# define STRUCTS_H

#include <curl/curl.h>

typedef struct data {

    CURL *curl;
    char *ip;
}   data_t;


struct string {
    char *ptr;
    size_t len;
};

#endif