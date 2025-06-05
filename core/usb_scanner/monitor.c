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
#include <fcntl.h>             //fstat & O_PATH
#include <sys/stat.h>         
#include "shared.h"    
#include <string.h>       

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
            if (!(fds[i].revents & POLLIN)) continue;
            ssize_t len = read(fds[i].fd, buf, sizeof(buf));
            if (len <= 0) continue;
            off_t ptr = 0;
            while (ptr < len) {
                struct fanotify_event_metadata *md = (void *)(buf + ptr);
                if (md->event_len < sizeof(*md) || ptr + md->event_len > len) break;
                EventInfo ev = { .mask = md->mask, .proc.pid = md->pid };

                // check for create, delete, move notifications (no content)
                if (fds[i].fd == g_fan_notify_fd) {
                    if (!(md->mask & (FAN_CREATE | FAN_DELETE | FAN_MOVED_FROM | FAN_MOVED_TO))) {
                        ptr += md->event_len;
                        continue;
                    }
                    // metadata events can report the name when FAN_REPORT_NAME is enabled
                    // the kernel appends a null-terminated filename after the metadata header
                    char *name = (char *)md + sizeof(struct fanotify_event_metadata);
                    snprintf(ev.file.path, PATH_MAX, "%s", name);
                    // on directory creation or move-to, mark the new directory
                    if (md->mask & (FAN_CREATE | FAN_MOVED_TO)) {
                        struct stat st;
                        if (stat(ev.file.path, &st) == 0 && S_ISDIR(st.st_mode)) {
                            mark_mount(ev.file.path);
                        }
                    }
                    push_event(ev);
                } 
                //else ckeck for content events (modifications)
                else {
                    char path[PATH_MAX];
                    get_path_from_fd(md->fd, path, sizeof(path));
                    strncpy(ev.file.path, path, PATH_MAX);
                    close(md->fd);
                    push_event(ev);
                }
                ptr += md->event_len;
            }
        }
    }
    return NULL;
}