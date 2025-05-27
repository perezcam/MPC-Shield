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
            //Port closed or filtered (no danger)
            continue;
        }

        int known_port = is_known(port); //devuelve -1 si es malicioso, 0 si no se conoce y 1 si es banner conocido

        char banner[256];
        int n = grab_banner(sockfd, banner, sizeof(banner)-1);
        char *danger_word;

        if (known_port == -1) {
            search_danger_words(banner, n); //TODO: devuelva la palabra o NULL si no tiene
        } else if (known_port == 1) {
            int secure = is_expected_banner(port, banner);
        } else {
            //servicio no conocido
            search_danger_words(banner);
        }





        // //Banner grabbing

        // if (n > 0) {
        //     printf("%4d abierto ➔ %s (banner: %.200s)\n", port,
        //            get_service_name(port), banner);
        // } else {
        //     printf("%4d abierto ➔ %s (sin banner)\n", port,
        //            get_service_name(port));
        // }

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