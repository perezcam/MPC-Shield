// monitor.c
#define _GNU_SOURCE

#include "shared.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/fanotify.h>
#include <poll.h>

/**
 * monitor_thread:
 *   - Inicializa la tabla de rutas.
 *   - Escucha en g_fan_notify_fd y g_fan_content_fd.
 *   - Para cada evento relevante, resuelve la ruta y actualiza:
 *       • path_table (crea/quita snapshot)
 *       • la cola de eventos (push_event)
 */
void *monitor_thread(void *arg) {
    (void)arg;

    /* 1) Inicializar la tabla de rutas */
    pst_init(&path_table);

    /* 2) Prepara el poll de los dos FDs */
    struct pollfd fds[2] = {
        { .fd = g_fan_notify_fd,  .events = POLLIN },
        { .fd = g_fan_content_fd, .events = POLLIN },
    };
    /* Buffer para leer metadatos de fanotify */
    char buf[8192];

    while (1) {
        int ret = poll(fds, 2, -1);
        if (ret < 0) {
            if (errno == EINTR) 
                continue;
            perror("monitor poll");
            break;
        }

        for (int idx = 0; idx < 2; idx++) {
            if (!(fds[idx].revents & POLLIN))
                continue;

            ssize_t len = read(fds[idx].fd, buf, sizeof(buf));
            if (len <= 0) 
                continue;

            /* 3) Procesa cada fanotify_event_metadata en el buffer */
            off_t ptr = 0;
            while (ptr < len) {
                struct fanotify_event_metadata *md =
                    (struct fanotify_event_metadata *)(buf + ptr);
                /* Sanity check */
                if (md->event_len < sizeof(*md)) {
                    ptr += md->event_len;
                    continue;
                }

                /* Prepara nuestro EventInfo */
                EventInfo ev = { .mask = md->mask, .proc.pid = md->pid };

                if (fds[idx].fd == g_fan_notify_fd) {
                    /* Notificaciones: creación, borrado, movimiento, atributos */
                    uint64_t m = md->mask;
                    if (!(m & (FAN_CREATE | FAN_DELETE |
                               FAN_MOVED_FROM | FAN_MOVED_TO | FAN_ATTRIB))) {
                        ptr += md->event_len;
                        continue;
                    }

                    /* 3.1) Resuelve la ruta absoluta */
                    char fullpath[PATH_MAX];
                    if (get_event_fullpath(md, fullpath, sizeof(fullpath)) == 0) {
                        strncpy(ev.file.path, fullpath, PATH_MAX);
                        ev.file.path[PATH_MAX-1] = '\0';
                    }

                    /* 3.2) Si es dir nuevo, marcamos recursivamente */
                    if (m & (FAN_CREATE | FAN_MOVED_TO)) {
                        struct stat st;
                        if (stat(ev.file.path, &st) == 0) {
                            mark_path(ev.file.path);
                            if (S_ISREG(st.st_mode)) {
                                pst_update(&path_table, ev.file.path, &st);
                            }
                        }
                    }
                    /* 3.3) Si es borrado o movido desde, lo quitamos */
                    if (m & (FAN_DELETE | FAN_MOVED_FROM)) {
                        pst_remove(&path_table, ev.file.path);
                    }

                } else {
                    /* Contenido: open, modify, close_write */
                    uint64_t m = md->mask;
                    if (!(m & (FAN_OPEN | FAN_MODIFY | FAN_CLOSE_WRITE))) {
                        close(md->fd);
                        ptr += md->event_len;
                        continue;
                    }

                    /* 3.5) Resuelve ruta desde el FD */
                    char path[PATH_MAX];
                    if (get_path_from_fd(md->fd, path, sizeof(path)) == 0) {
                        strncpy(ev.file.path, path, PATH_MAX);
                        ev.file.path[PATH_MAX-1] = '\0';
                    }
                    close(md->fd);

                }
                push_event(ev);
                atomic_fetch_add(&g_total_events, 1);
                ptr += md->event_len;
            }
        }
    }

    return NULL;
}
