#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include "config.h"
#include "defines.h"

int make_request(char **tab, int size, int verbosity) {

    int r = 0;
    int t;
    char *ret;
    char request[100];
    SOCKADDR addr;
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0)
        return -__LINE__;

    ret = malloc(size * 22 + 5);
    if (ret == NULL)
        return -__LINE__;

    memset(ret, 0, size * 22 + 5);
    memset(request, 0, 100);
    memset(&addr, 0, sizeof(SOCKADDR));

    addr.sin_addr.s_addr = PORT_SCANNER_ADDR;
    addr.sin_port = PORT_SCANNER_PORT;
    addr.sin_family = AF_INET;

    (verbosity)?printf("[1/4] Connecting...\n"):verbosity;
    if (connect(sock, (struct sockaddr *)&addr, sizeof(SOCKADDR)) < 0)
        return free(ret), -__LINE__;


    snprintf(request, 100, "%s %s %s %d\n", PASSWORD, SEEK_IP, SEEK_PORT, size);

    (verbosity)?printf("[2/4] Sending request (%s)...\n", request):verbosity;
    if (send(sock, request, strlen(request), 0) < 0)
        return free(ret), -__LINE__;

    (verbosity)?printf("[3//4] Waiting response...\n"):verbosity;
    while (!strchr(ret, 'e')) 
    {
        t = recv(sock, &ret[r], (size * 22 + 4) - r, 0);
        if (t < 0)
            return free(ret), -__LINE__;
        r += t;
    }

    *tab = ret;
    (verbosity)?printf("[4/4] Received !...\n"):verbosity;
    close(sock);

    return 1;
}