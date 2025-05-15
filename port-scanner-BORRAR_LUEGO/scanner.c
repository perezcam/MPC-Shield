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

    int port;

    while (1) {
        pthread_mutex_lock(&mutex);
        if (next_port > END_PORT) {
            pthread_mutex_unlock(&mutex);
            break;
        }
        port = next_port++;
        pthread_mutex_unlock(&mutex);
        printf("Scanning port %d...\n", port);
    
        int connection_status = connect_to_port(port);
    
        if (connection_status == -1) {
            printf("There was an error with the socket with port %d", port);
        } else if (connection_status == 1) {
            printf("%d %s \n", port, get_service_name(port));
        } 
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