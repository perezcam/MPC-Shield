#define _GNU_SOURCE
#include "shared.h"
#include <stdio.h>
#include <sys/fanotify.h>
#include <poll.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <openssl/sha.h>
#include <fcntl.h>
#include <limits.h>



/**
 * monitor_thread:
 *   - Listens on both fanotify descriptors (notify and content).
 *   - Filters and processes events: create/delete/move on notify FD,
 *     open/modify/close_write on content FD.
 *   - Retrieves file names (requires FAN_REPORT_NAME) and resolves
 *     paths from FDs.
 *   - Pushes events into the shared queue and logs debug info.
 */
void *monitor_thread(void *arg) {
    (void)arg;
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
        for (int i = 0; i < 2; i++) {
            if (!(fds[i].revents & POLLIN))
                continue;
            ssize_t len = read(fds[i].fd, buf, sizeof(buf));
            if (len <= 0)
                continue;

            off_t ptr = 0;
            while (ptr < len) {
                struct fanotify_event_metadata *md = (void *)(buf + ptr);
                /* Validate metadata length and version */
                if (md->event_len < sizeof(*md)) {
                    ptr += md->event_len;
                    continue;
                }

                EventInfo ev = { .mask = md->mask, .proc.pid = md->pid };

                if (fds[i].fd == g_fan_notify_fd) {
                    /* Notify FD: handle create/delete/move events */
                    if (!(md->mask & (FAN_CREATE | FAN_DELETE |
                                      FAN_MOVED_FROM | FAN_MOVED_TO))) {
                        ptr += md->event_len;
                        continue;
                    }
                    /* Get file path*/
                    char fullpath[PATH_MAX];
                    if (get_event_fullpath(md, fullpath, sizeof(fullpath)) == 0) {
                        strncpy(ev.file.path, fullpath, PATH_MAX-1);
                        ev.file.path[PATH_MAX-1] = '\0';
                    }

                    /* Auto-mark new directories */
                    if (md->mask & (FAN_CREATE | FAN_MOVED_TO)) {
                        struct stat st;
                        if (stat(ev.file.path, &st) == 0) {
                            // 1) Fanotify‐mark everything (dirs + files)
                            mark_path(ev.file.path);

                            // 2) Only snapshot regular files in our table
                            if (S_ISREG(st.st_mode)) {
                                pst_update(&path_table, ev.file.path, &st);
                            }
                        }
                    }
                    if (md->mask & (FAN_DELETE | FAN_MOVED_FROM)) {
                        pst_remove(&path_table, ev.file.path); 
                    }
                    push_event(ev);
                } else {
                    /* Content FD: handle open/modify/close_write */
                    if (!(md->mask & (FAN_OPEN | FAN_MODIFY |
                                      FAN_CLOSE_WRITE))) {
                        close(md->fd);
                        ptr += md->event_len;
                        continue;
                    }
                    /* Resolve path from FD */
                    char path[PATH_MAX];
                    get_path_from_fd(md->fd, path, sizeof(path));
                    strncpy(ev.file.path, path, PATH_MAX);
                    close(md->fd);
                    push_event(ev);
                }

                // /* Debug logging */
                // fprintf(stderr, "[DEBUG] fd=%d mask=0x%llx path=%s\n",
                //         md->fd,
                //         (unsigned long long)md->mask,
                //         ev.file.path);
                // fflush(stderr);

                ptr += md->event_len;
            }
        }
    }
    return NULL;
}
