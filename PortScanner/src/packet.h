#ifndef PACKET_H
# define PACKET_H

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip6.h>

#include "defines.h"

typedef struct iphdr IP_HEADER;
typedef struct ip6_hdr IP_HEADER6;
typedef struct tcphdr TCP_HEADER;

typedef struct packet {
    IP_HEADER  ip_hdr;
    TCP_HEADER tcp_hdr;
}   packet_t;

typedef struct packet6 {
    IP_HEADER6 ip_hdr;
    TCP_HEADER tcp_hdr;
}   packet6_t;

typedef struct pseudo_tcp_header4 {
    ipv4_t source_ip;
    ipv4_t dest_ip;
    uint8_t zero;
    uint8_t protocole;
    uint16_t lenght;
}   pseudo_tcp_header4_t;

typedef struct pseudo_tcp_header6 {
    ipv6_t source_ip;
    ipv6_t dest_ip;
    uint16_t protocole;
    uint16_t length;
}   pseudo_tcp_header6_t;

#define PACKET_SIZE (sizeof(packet_t)) // = sizeof(packet_t)

/* Construction Raw Socket */

#define PROTOCOLE_TCP 6 // definie dans /etc/protocols et dans in.h

/* Construction IP_HEADER */

#define VERSION_IPV4           4    // version pour le protocole IP
#define VERSION_IPV6           6
#define INTERNET_HEADER_LENGTH 5    // Valeur en DWORD, rappel 1 DWORD = 4 Octets donc 5 * 4 = 20 Octets
                                    // Devrait toujours être à 5 si pas d'option utilisé


// VOIR RFC 1349 et RFC 791 et https://linuxreviews.org/Type_of_Service_(ToS)_and_DSCP_Values#The_DSCP_and_The_ToS_Byte_Values

#define DEFAULT_TOS             0x00
#define MININMIZE_COST          0x02
#define MAXIMIZE_RELIABILITY    0x04
#define MAXIMIZE_THROUGHPUT     0x08
#define MINIMIZE_DELAY          0x10    

//      Utilisé pour la fragmentation
// /!\  Correspond seulement au 3 premier bit de frag_off /!\ //
#define NO_FRAG         0x0
#define MORE_FRAG       0x1
#define DONT_FRAG       0x2
#define MORE_DONT_FRAG  0x3

// Les 13 bits après de frag_off correspondent à l'offset, l'emplacement du fragement
// Il est calculé sur 8 octets, 64 bits (pas trop compris)
// Le datagram, premier fragment, a un offset de 0
// Derniere offset = tot_len

/* Construction TCP_HEADER */

#define TCP_DATAOFF_NO_OPT 5

// Fonction pour créer le packet
void create_packet4(packet_t *packet, ipv4_t source_ip, ipv4_t dest_ip, port_t dest_port, port_t source_port);
void create_packet6(packet6_t *packet, ipv6_t source_ip, ipv6_t dest_ip, port_t dest_port, port_t source_port);
#endif