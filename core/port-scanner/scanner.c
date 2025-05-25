#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "scanner_utils.h"



#define START_PORT 1
#define END_PORT 1024
#define NUM_THREADS 100

int next_port = START_PORT;
pthread_mutex_t mutex;


void *scan(void *arg) {
    while (1) {
        pthread_mutex_lock(&mutex);
        if (next_port > END_PORT) {
            pthread_mutex_unlock(&mutex);
            break;
        }
        int port = next_port++;
        pthread_mutex_unlock(&mutex);
    
        int sockfd = connect_to_port(port);
        if (sockfd < 0) {
            //Couldn't establish a connection
            //Port closed
            continue;
        }

        //Banner grabbing
        char banner[256];
        int n = grab_banner(sockfd, banner, sizeof(banner)-1);

        if (n > 0) {
            printf("%4d abierto ➔ %s (banner: %.200s)\n", port,
                   get_service_name(port), banner);
        } else {
            printf("%4d abierto ➔ %s (sin banner)\n", port,
                   get_service_name(port));
        }

        close_socket(sockfd);
    }

    return NULL;
}


int main() {
    pthread_t port_threads[NUM_THREADS];
    pthread_mutex_init(&mutex, NULL);


    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_create(&port_threads[i], NULL, scan, NULL);
    }


    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(port_threads[i], NULL);
    }

    pthread_mutex_destroy(&mutex);
    return 0;
}