#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <limits.h>
#include <linux/limits.h>    // For PATH_MAX
#include <sys/fanotify.h>
#include <fcntl.h>
#include "shared.h"         

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* Número de hilos worker */
#define NUM_WORKERS 2

/* Identificadores de hilos */
static pthread_t scan_tid;
static pthread_t mon_tid;
static pthread_t workers[NUM_WORKERS];

/**
 * scann_start:
 *   - Inicializa fanotify (content + notify).
 *   - Lanza scanner_thread, monitor_thread y worker_thread(s).
 *   - Sale con EXIT_FAILURE si algo crítico falla.
 */
void scann_start(void)
{
    /* 1) FD de contenido (metadatos + fd) */
    g_fan_content_fd = fanotify_init(
        FAN_CLOEXEC | FAN_NONBLOCK | FAN_CLASS_CONTENT,
        O_RDONLY | O_LARGEFILE
    );
    if (g_fan_content_fd < 0) {
        perror("fanotify_init content");
        exit(EXIT_FAILURE);
    }

    /* 2) FD de notificación (solo metadatos + nombres) */
    g_fan_notify_fd = fanotify_init(
        FAN_CLOEXEC
      | FAN_NONBLOCK
      | FAN_CLASS_NOTIF
      | FAN_REPORT_DFID_NAME
      | FAN_REPORT_FID,
      O_RDONLY | O_LARGEFILE
    );
    if (g_fan_notify_fd < 0) {
        perror("fanotify_init notify");
        close(g_fan_content_fd);
        exit(EXIT_FAILURE);
    }

    /* 3) Lanzar scanner_thread */
    if (pthread_create(&scan_tid, NULL, scanner_thread, NULL) != 0) {
        perror("pthread_create scanner_thread");
        close(g_fan_content_fd);
        close(g_fan_notify_fd);
        exit(EXIT_FAILURE);
    }

    /* 4) Lanzar monitor_thread */
    if (pthread_create(&mon_tid, NULL, monitor_thread, NULL) != 0) {
        perror("pthread_create monitor_thread");
        pthread_cancel(scan_tid);
        pthread_join(scan_tid, NULL);
        close(g_fan_content_fd);
        close(g_fan_notify_fd);
        exit(EXIT_FAILURE);
    }

    /* 5) Lanzar worker_thread(s) */
    for (int i = 0; i < NUM_WORKERS; i++) {
        if (pthread_create(&workers[i], NULL, worker_thread, NULL) != 0) {
            perror("pthread_create worker_thread");
            /* continuamos intentando con los demás */
        }
    }
}

/**
 * scann_stop:
 *   - Cancela y une todos los hilos.
 *   - Cierra los file descriptors de fanotify.
 */
void scann_stop(void)
{
    /* 1) Cancelar hilos */
    pthread_cancel(scan_tid);
    pthread_cancel(mon_tid);
    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_cancel(workers[i]);
    }

    /* 2) Join */
    pthread_join(scan_tid, NULL);
    pthread_join(mon_tid, NULL);
    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(workers[i], NULL);
    }

    /* 3) Cerrar fds de fanotify */
    if (g_fan_content_fd >= 0) close(g_fan_content_fd);
    if (g_fan_notify_fd  >= 0) close(g_fan_notify_fd);
}
