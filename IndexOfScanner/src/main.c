#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <signal.h>
#include <unistd.h>

#include <pthread.h>

#include <curl/curl.h>

#include "config.h"
#include "port_scanner_api.h"
#include "utils.h"
#include "structs.h"

FILE *fp = NULL;

void signal_exit(int signum) {

	if (signum == SIGINT) {
		printf("Exiting...\n");
	    curl_global_cleanup();
		fclose(fp);
		exit(0);
	}
}

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
    memcpy(first_ip + 7, ip, strchr(ip, '\n') - ip);

    curl_easy_setopt(curl, CURLOPT_URL, first_ip);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &txt);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);

    res = curl_easy_perform(curl);

    if (res == CURLE_OK && check_if_indexof(txt.ptr)) {
		fwrite(first_ip, 1, strlen(first_ip), fp);
		fwrite("\n", 1, 1, fp);
        printf("%s\n", first_ip);
        //char link[31];
        //memset(link, 0, 31);
        //memcpy(link, "firefox ", 8);
        //memcpy(link + 8, first_ip, strlen(first_ip));
        //system(link);
    }

    free(txt.ptr);
    curl_easy_cleanup(curl);

    return NULL;
}

int main(int argc, char **argv)
{
    char *ip;
    char *tmp;
    pthread_t threads[NUMBER];

	if (argc != 2) {
		printf("Usage: %s <outfile>\n", argv[0]);
		return 1;
	}
	fp = fopen(argv[1], "w");
	if (fp == NULL)
		return perror("fopen"), 1;

    curl_global_init(CURL_GLOBAL_ALL);

	signal(SIGINT, signal_exit);
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
	fclose(fp);

    return 0;
}
