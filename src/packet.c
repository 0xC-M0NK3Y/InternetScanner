#include <stdlib.h>
#include <string.h>

#include "defines.h"
#include "packet.h"
#include "utils.h"

static void create_ip_header6(IP_HEADER6 *ip_hdr, ipv6_t source_ip, ipv6_t dest_ip) {

    memset(ip_hdr, 0, sizeof(IP_HEADER6));
    // et le truc c'est que ya un next header, celui du tcp
    // je suis pas sur en vrai, memcpy pour etre sur au pire
    ip_hdr->ip6_ctlun.ip6_un2_vfc = VERSION_IPV6; // 4 bits pour la version
    ip_hdr->ip6_ctlun.ip6_un1.ip6_un1_flow = 0; // Utilité similaire à Type Of Service de ipv4 Header, 0 = default (traffic class + flow)
    ip_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen = sizeof(TCP_HEADER); // Taille du payload sans compter ce header, donc juste sizeof(TCP_HEADER);
    ip_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_TCP; // Type de protcole du prochain header, pareil que protocole dans header ipv4
    ip_hdr->ip6_ctlun.ip6_un1.ip6_un1_hlim = 51; // Decrementé de 1 à chaque saut, packet dropper à 0, similaire à TTL dans ipv4 header;
    ip_hdr->ip6_src = source_ip; // IP source
    ip_hdr->ip6_dst = dest_ip; // IP destination
}

static void create_ip_header4(IP_HEADER *ip_hdr, ipv4_t source_ip, ipv4_t dest_ip) {

    memset(ip_hdr, 0, sizeof(IP_HEADER));

    ip_hdr->version = VERSION_IPV4;
    ip_hdr->ihl = INTERNET_HEADER_LENGTH;
    ip_hdr->tos = DEFAULT_TOS;
    ip_hdr->tot_len = PACKET_SIZE; // Taille total du paquet
    ip_hdr->id = 0; // inutilisé, incrémenté de datagram en datagram apparement
                   // d'après la RFC 791 :
                                        // An identifying value assigned by the sender to aid in assembling the
                                        // fragments of a datagram.
    ip_hdr->frag_off = NO_FRAG; // Permet de fragmenter un gros paquet en petits paquets
    ip_hdr->ttl = 51; // Nombre de saut que la paquet peut faire, decrementé a chaque seconde ou chaque saut si c'est moins de 1sec
    ip_hdr->protocol = IPPROTO_TCP; // protocole utilisé, definie dans in.h
    //ip_hdr.check; somme de controle calculé à la fin
    ip_hdr->saddr = source_ip; // source ip
    ip_hdr->daddr = dest_ip; // dest ip
}

static void create_tcp_header(TCP_HEADER *tcp_hdr, port_t dest_port, port_t source_port) {

    memset(tcp_hdr, 0, sizeof(TCP_HEADER));

    tcp_hdr->th_sport = source_port; // Source port
    tcp_hdr->th_dport = dest_port; // Dest port
    tcp_hdr->th_seq = random(); // Sequence number
                        // utilisé pour enumerer les segments tcp
    tcp_hdr->th_ack = 0; // Acknowledgment number
                            // utilisé par le recpteur pour demander le prochain segment tcp
                            // incrémenté de 1 a chaque fois
    tcp_hdr->th_off = TCP_DATAOFF_NO_OPT; // data offset = 5 sans option
    tcp_hdr->th_flags = TH_SYN;
    tcp_hdr->th_win = htons(1024); // Nombre d'octet qui peuvent etre envoyé avant d'etre aknowledged
    tcp_hdr->th_sum = 0;
    tcp_hdr->th_urp = 0;
}

static unsigned short calcul_tcp_checksum4(IP_HEADER ip_hdr, TCP_HEADER tcp_hdr) {
    char buffer[sizeof(pseudo_tcp_header4_t) + sizeof(TCP_HEADER)];
    pseudo_tcp_header4_t tmp;

    memcpy(&tmp.source_ip, (char *)&ip_hdr.saddr, sizeof(ipv4_t));
    memcpy(&tmp.dest_ip, (char *)&ip_hdr.daddr, sizeof(ipv4_t));
    tmp.protocole = IPPROTO_TCP;
    tmp.lenght = htons(sizeof(TCP_HEADER));
    tmp.zero = 0;

    memset(buffer, 0, sizeof(pseudo_tcp_header4_t) + sizeof(TCP_HEADER));

    memcpy(buffer, (char *)&tmp, sizeof(pseudo_tcp_header4_t));
    memcpy(buffer + sizeof(pseudo_tcp_header4_t), (char *)&tcp_hdr, sizeof(TCP_HEADER));

    return in_cksum((unsigned short *)buffer, sizeof(pseudo_tcp_header4_t) + sizeof(TCP_HEADER));
}

static unsigned short calcul_tcp_checksum6(IP_HEADER6 ip_hdr, TCP_HEADER tcp_hdr) {
    char buffer[sizeof(pseudo_tcp_header6_t) + sizeof(TCP_HEADER)];
    pseudo_tcp_header6_t tmp;

    memcpy(&tmp.source_ip, (char *)&ip_hdr.ip6_src, sizeof(ipv6_t));
    memcpy(&tmp.dest_ip, (char *)&ip_hdr.ip6_dst, sizeof(ipv6_t));
    tmp.protocole = IPPROTO_TCP;
    tmp.length = htons(sizeof(TCP_HEADER));

    memset(buffer, 0, sizeof(pseudo_tcp_header6_t) + sizeof(TCP_HEADER));

    memcpy(buffer, (char *)&tmp, sizeof(pseudo_tcp_header6_t));
    memcpy(buffer + sizeof(pseudo_tcp_header6_t), (char *)&tcp_hdr, sizeof(TCP_HEADER));

    return in_cksum((unsigned short *)buffer, sizeof(pseudo_tcp_header6_t) + sizeof(TCP_HEADER));
}

void create_packet4(packet_t *packet, ipv4_t source_ip, ipv4_t dest_ip, port_t dest_port, port_t source_port) {
    IP_HEADER ip_hdr;
    TCP_HEADER tcp_hdr;

    memset(&ip_hdr, 0, sizeof(IP_HEADER));
    memset(&tcp_hdr, 0, sizeof(TCP_HEADER));

    create_ip_header4(&ip_hdr, source_ip, dest_ip);
    create_tcp_header(&tcp_hdr, dest_port, source_port);

    memset(packet, 0, sizeof(packet_t));

    memcpy(&packet->ip_hdr, (char *)&ip_hdr, sizeof(IP_HEADER));
    memcpy(&packet->tcp_hdr, (char *)&tcp_hdr, sizeof(TCP_HEADER));

    packet->tcp_hdr.th_sum = calcul_tcp_checksum4(ip_hdr, tcp_hdr);
    packet->ip_hdr.check = in_cksum((unsigned short *)packet, PACKET_SIZE);
}

void create_packet6(packet6_t *packet, ipv6_t source_ip, ipv6_t dest_ip, port_t dest_port, port_t source_port) {
    IP_HEADER6 ip_hdr;
    TCP_HEADER tcp_hdr;

    memset(&ip_hdr, 0, sizeof(IP_HEADER6));
    memset(&tcp_hdr, 0, sizeof(TCP_HEADER));

    create_ip_header6(&ip_hdr, source_ip, dest_ip);
    create_tcp_header(&tcp_hdr, dest_port, source_port);

    memset(packet, 0, sizeof(packet6_t));

    memcpy(&packet->ip_hdr, (char *)&ip_hdr, sizeof(IP_HEADER6));
    memcpy(&packet->tcp_hdr, (char *)&tcp_hdr, sizeof(TCP_HEADER));

    packet->tcp_hdr.th_sum = calcul_tcp_checksum6(ip_hdr, tcp_hdr);
}