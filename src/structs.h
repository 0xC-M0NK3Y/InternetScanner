#ifndef STRUCTS_H
# define STRUCTS_H

#include "defines.h"

typedef struct analyse
{
    ipv4_t listen_ipv4;
    port_t listen_portv4;
    char unix_path[108];
}   analyse_t;

typedef struct request
{
    int     nb;
    port_t *port;
    int     portnb;
    ipv4_t *ipv4;
    int     *ipv4_mask;
    int     ipv4nb;
    //ipv6 *ipv6;

}   request_t;
#endif