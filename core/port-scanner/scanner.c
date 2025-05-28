#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "scanner_utils.h"



#define START_PORT 1
#define END_PORT 6000
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
            // Port closed or filtered (no banner, no danger)
            continue;
        }

        // Grab port banner if it has one
        char banner[256];
        int n = grab_banner(sockfd, banner, sizeof(banner) - 1);

        // Search for dangerous word
        const char *danger_word = search_dangerous_words(banner, n);

        // -1 = malicious, 0 = unknown, 1 = expected banner
        int port_classification = classify(port);

        // Determine if it matches the expected banner (only makes sense if class==1)
        int secure = 0;
        if (port_classification == 1) {
            secure = is_expected_banner(port, banner);
        }

        // ==== PRINTS DE TEST ====
        printf("[TEST] Puerto %d | Clasificación = %d | Banner = \"%s\" | Seguro = %s | Palabra peligrosa = \"%s\" \n",
                port,
                port_classification,
                (n > 0 ? banner : "<no banner>"),
                (secure ? "sí" : "no"),
                (danger_word != NULL ? danger_word : "ninguna"));
        // ========================

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