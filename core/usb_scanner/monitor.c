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
 * get_path_from_fd:
 *   Resuelve la ruta real de un fd de fanotify leyendo
 *   el enlace /proc/self/fd/<fd>.
 *   Devuelve 0 en éxito, -1 en error (y errno queda seteado).
 */
int get_path_from_fd(int fd, char *buf, size_t bufsiz) {
    char linkpath[64];
    ssize_t len;

    if (!buf || bufsiz == 0) {
        errno = EINVAL;
        return -1;
    }

    int n = snprintf(linkpath, sizeof(linkpath),
                     "/proc/self/fd/%d", fd);
    if (n < 0 || (size_t)n >= sizeof(linkpath)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    len = readlink(linkpath, buf, bufsiz - 1);
    if (len < 0) {
        // errno ya está seteado
        return -1;
    }

    buf[len] = '\0';
    return 0;
}

/**
 * monitor_thread:
 *   - Inicializa la tabla de snapshots.
 *   - Escucha ambos FDs de fanotify.
 *   - Empuja a la cola sólo los eventos relevantes
 *     con rutas válidas.
 *   - Incrementa g_total_events.
 */
void *monitor_thread(void *arg) {
    (void)arg;

    pst_init(&path_table);

    struct pollfd fds[2] = {
        { .fd = g_fan_notify_fd,  .events = POLLIN },
        { .fd = g_fan_content_fd, .events = POLLIN },
    };
    char buf[8192];

    while (1) {
        int ret = poll(fds, 2, -1);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("monitor poll");
            break;
        }

        for (int idx = 0; idx < 2; idx++) {
            if (!(fds[idx].revents & POLLIN))
                continue;

            ssize_t len = read(fds[idx].fd, buf, sizeof(buf));
            if (len <= 0)
                continue;

            off_t ptr = 0;
            while (ptr < len) {
                struct fanotify_event_metadata *md =
                    (struct fanotify_event_metadata *)(buf + ptr);

                if (md->event_len < sizeof(*md)) {
                    ptr += md->event_len;
                    continue;
                }

                EventInfo ev = { .mask = md->mask, .proc.pid = md->pid };

                if (fds[idx].fd == g_fan_notify_fd) {
                    uint64_t m = md->mask;

                    /* Sólo CREATE, DELETE, MOVED, ATTRIB */
                    if (m & (FAN_CREATE | FAN_DELETE |
                             FAN_MOVED_FROM | FAN_MOVED_TO | FAN_ATTRIB)) {

                        char fullpath[PATH_MAX];
                        if (get_event_fullpath(md,
                                               fullpath, sizeof(fullpath)) == 0) {
                            strncpy(ev.file.path,
                                    fullpath, PATH_MAX-1);
                            ev.file.path[PATH_MAX-1] = '\0';

                            /* Marca nuevo snapshot en CREATE/MOVED_TO */
                            if (m & (FAN_CREATE | FAN_MOVED_TO)) {
                                struct stat st;
                                if (stat(ev.file.path, &st) == 0) {
                                    mark_path(ev.file.path);
                                    if (S_ISREG(st.st_mode))
                                        pst_update(&path_table,
                                                   ev.file.path, &st);
                                }
                            }
                            /* Elimina de la tabla en DELETE/MOVED_FROM */
                            if (m & (FAN_DELETE | FAN_MOVED_FROM)) {
                                pst_remove(&path_table,
                                           ev.file.path);
                            }

                            push_event(ev);
                            atomic_fetch_add(&g_total_events, 1);
                        }
                    }

                } else {
                    uint64_t m = md->mask;

                    /* Sólo al cerrar escritura */
                    if (m & FAN_CLOSE_WRITE) {
                        char path[PATH_MAX];
                        if (get_path_from_fd(md->fd,
                                             path, sizeof(path)) == 0) {
                            strncpy(ev.file.path,
                                    path, PATH_MAX-1);
                            ev.file.path[PATH_MAX-1] = '\0';

                            push_event(ev);
                            atomic_fetch_add(&g_total_events, 1);
                        }
                    }
                    close(md->fd);
                }

                ptr += md->event_len;
            }
        }
    }

    return NULL;
}
