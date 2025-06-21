#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "scanner_utils.h"
#include "models.h"
#include "scanner.h"

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
        //secure: 0: warning, 1: ok, -1: critical 
        int secure = (port_class == 1)? is_expected_banner(port, banner) : 
                    (found_word != NULL)? -1 : 
                    (port_class == -1)? -1 : 0;

        // Prepare output
        ScanOutput entry;
        entry.port = port;
        entry.classification = strdup((port_class == -1)? "Suspicious" : 
                                    (port_class == 1)? "Service associated" : "Unknown");
        entry.banner = strdup((n > 0) ? banner : "<no banner>");
        entry.dangerous_word = strdup((found_word != NULL) ? found_word : "Sin palabra peligrosa detectada");
        entry.security_level = strdup((secure == 0)? "warning" :
                                    (secure == -1)? "critical" : "ok");


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

void free_result(ScanResult *res)
{
    if (!res || !res->data)
        return;

    for (int i = 0; i < res->size; i++) {
        free((char*)res->data[i].banner);
        free((char*)res->data[i].dangerous_word);
        free((char*)res->data[i].security_level);
        free((char*)res->data[i].classification);
    }

    free(res->data);
    
    res->data = NULL;
    res->size = 0;
}
