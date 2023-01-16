#ifndef CONFIG_H
# define CONFIG_H

#include "packet.h"

#define INTERFACE_INTERNET "8.8.8.8"
#define SOURCE_IP "192.168.1.27"

#define ONE_SECONDE 1000000

#define DEBIT_OpS(DEBIT) (ONE_SECONDE/DEBIT/(sizeof(packet_t)))

#endif