#include "shared.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/fanotify.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

/* Thread entrypoints */
void *monitor_thread(void *arg);
void *scanner_thread(void *arg);
void *worker_thread (void *arg);

/* Definition of the global fanotify FDs */
int g_fan_content_fd = -1;
int g_fan_notify_fd  = -1;

pthread_mutex_t path_table_mutex;
path_stat_table_t path_table;

int total=0;
int suspicious=0;

int main() {
    /* Initialize content fd*/
    g_fan_content_fd = fanotify_init(
        FAN_CLOEXEC        // close-on-exec
    | FAN_NONBLOCK      // no bloqueante
    | FAN_CLASS_CONTENT, // clase CONTENT: md + fd
        O_RDONLY          // lecturas
    | O_LARGEFILE       // soporte archivos >2 GB (en 32-bit)
    );
    if (g_fan_content_fd < 0) {
        perror("fanotify_init content");
        return EXIT_FAILURE;
    }

    /* Initialize notification FD */
    g_fan_notify_fd = fanotify_init(
        FAN_CLOEXEC
    | FAN_NONBLOCK
    | FAN_CLASS_NOTIF       // class NOTIF: md without fd
    | FAN_REPORT_DFID_NAME // entry name + dir FID 
    | FAN_REPORT_FID,
        O_RDONLY
    | O_LARGEFILE
    );
    if (g_fan_notify_fd < 0) {
        perror("fanotify_init notify");
        close(g_fan_content_fd);
        return EXIT_FAILURE;
    }

    /*Initialize path-stat table (pst)*/
    pst_init(&path_table);

    /*Initialize pst mutex*/
    pthread_mutex_init(&path_table_mutex, NULL);

    /* Spawn threads */
    pthread_t scan_tid, mon_tid, workers[NUM_WORKERS];
    if (pthread_create(&scan_tid, NULL, scanner_thread, NULL) != 0) {
        perror("pthread_create(scanner)");
        exit(EXIT_FAILURE);
    }
    if (pthread_create(&mon_tid,  NULL, monitor_thread, NULL) != 0) {
        perror("pthread_create(monitor)");
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < NUM_WORKERS; i++) {
        if (pthread_create(&workers[i], NULL, worker_thread, NULL) != 0) {
            perror("pthread_create(worker)");
            exit(EXIT_FAILURE);
        }
    }

    /* Join (daemon-style) */
    pthread_join(scan_tid,  NULL);
    pthread_join(mon_tid,   NULL);
    for (int i = 0; i < NUM_WORKERS; i++)
        pthread_join(workers[i], NULL);

    /* Cleanup */
    close(g_fan_content_fd);
    close(g_fan_notify_fd);
    pthread_mutex_destroy(&path_table_mutex);
    return 0;
}