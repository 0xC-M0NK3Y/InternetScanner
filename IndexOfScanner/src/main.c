#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include <pthread.h>

#include <curl/curl.h>

#include "config.h"
#include "port_scanner_api.h"
#include "utils.h"
#include "structs.h"

void *check_ip(void *data) {

    char *ip = data;
    CURL *curl;
    struct string txt;
    CURLcode res;
    char first_ip[23];

    curl = curl_easy_init();
    if (curl == NULL)
        return NULL;

    init_string(&txt);
    memset(first_ip, 0, 23);
    memcpy(first_ip, "http://", 7);
    memcpy(first_ip + 7, ip, strchr(ip, ':') - ip);

    curl_easy_setopt(curl, CURLOPT_URL, first_ip);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &txt);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);

    res = curl_easy_perform(curl);

    if (res == CURLE_OK && check_if_indexof(txt.ptr)) {
        printf("%s\n", first_ip);
        char link[31];
        memset(link, 0, 31);
        memcpy(link, "firefox ", 8);
        memcpy(link + 8, first_ip, strlen(first_ip));
        system(link);
    }

    free(txt.ptr);
    curl_easy_cleanup(curl);

    return NULL;
}

int main(int argc, char **argv)
{
    char *ip;
    (void)argc;
    (void)argv;
    char *tmp;
    pthread_t threads[NUMBER];

    curl_global_init(CURL_GLOBAL_ALL);

    while (1)
    {
        if (make_request(&ip, NUMBER, 0) < 0)
        printf("failed request\n");
        tmp = ip;

        for (int i = 0; i < NUMBER; i++) {
            pthread_create(&threads[i], NULL, check_ip, (void *)ip);
            ip = strchr(ip, '\n')+1;
        }
        for (int i = 0; i < NUMBER; i++)
            pthread_join(threads[i], NULL);
        free(tmp);
    }

    curl_global_cleanup();

    return 0;
}