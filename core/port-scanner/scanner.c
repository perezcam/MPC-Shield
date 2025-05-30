#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "scanner_utils.h"
#include "models.h"

#define START_PORT 1
#define END_PORT 6000
#define MAX_PORTS (END_PORT - START_PORT + 1)
#define NUM_THREADS 100

static int next_port = START_PORT;
static int output_index = 0;
static ScanOutput *output = NULL;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;


static void *scan_thread(void *arg) {
    while (1) {
        pthread_mutex_lock(&mutex);
        if (next_port > END_PORT) {
            pthread_mutex_unlock(&mutex);
            break;
        }
        int port = next_port++;
        pthread_mutex_unlock(&mutex);

        int sockfd = connect_to_port(port);
        if (sockfd < 0) continue;

        char banner[256] = {0};
        int n = grab_banner(sockfd, banner, sizeof(banner) - 1);

        const char *found_word = search_dangerous_words(banner, n);
        int port_class = classify(port);
        int secure = (port_class == 1) ? is_expected_banner(port, banner) : 0;

        // Prepare output
        ScanOutput entry;
        entry.port = port;
        entry.classification = port_class;
        entry.banner = strdup((n > 0) ? banner : "<no banner>");
        entry.dangerous_word = strdup(
            (found_word != NULL) ? found_word : "Sin palabra peligrosa detectada"
        );
        entry.security_level = secure;  // 0 or 1

        pthread_mutex_lock(&mutex);

        output[output_index] = entry;
        output_index++;

        pthread_mutex_unlock(&mutex);

        close_socket(sockfd);
    }
    return NULL;
}


ScanResult scan_ports(void) {
    
    output = malloc(sizeof(ScanOutput) * MAX_PORTS);
    if (!output) {
        //TODO: MANEJO DE ERRORES
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    next_port = START_PORT;
    output_index = 0;


    pthread_t threads[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_create(&threads[i], NULL, scan_thread, NULL);
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    // Prepare result
    ScanResult result;
    result.data = output;
    result.size = output_index;
    return result;
}
