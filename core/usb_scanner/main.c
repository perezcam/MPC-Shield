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

int main(int argc, char **argv) {
    // 1) Inicializa el FD de contenido (para abrir fds de fichero)
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

    // 2) Inicializa el FD de notificación (solo metadata)
    //    Incluye FAN_REPORT_DIR_FID + FAN_REPORT_NAME usando la macro FAN_REPORT_DFID_NAME
    g_fan_notify_fd = fanotify_init(
        FAN_CLOEXEC
    | FAN_NONBLOCK
    | FAN_CLASS_NOTIF       // clase NOTIF: md sin fd
    | FAN_REPORT_DFID_NAME, // nombre de entrada + dir FID :contentReference[oaicite:1]{index=1}
        O_RDONLY
    | O_LARGEFILE
    );
    if (g_fan_notify_fd < 0) {
        perror("fanotify_init notify");
        close(g_fan_content_fd);
        return EXIT_FAILURE;
    }

    /* 2) Spawn threads */
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

    /* 3) Join (daemon-style) */
    pthread_join(scan_tid,  NULL);
    pthread_join(mon_tid,   NULL);
    for (int i = 0; i < NUM_WORKERS; i++)
        pthread_join(workers[i], NULL);

    /* 4) Cleanup */
    close(g_fan_content_fd);
    close(g_fan_notify_fd);
    return 0;
}