#include "shared.h"
#include <stdio.h>
#include <poll.h>
#include <unistd.h>
#include <sys/fanotify.h>
#include <limits.h>
#include <errno.h>

/* Ring buffer + sync */
static event_t         queue[QUEUE_SIZE];
static int             q_head = 0, q_tail = 0;
static pthread_mutex_t q_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  q_cond  = PTHREAD_COND_INITIALIZER;

/* Drop‐oldest enqueue */
void push_event(event_t ev) {
    pthread_mutex_lock(&q_mutex);
    int next = (q_tail + 1) % QUEUE_SIZE;
    if (next == q_head) {
        /* buffer full → drop the oldest */
        q_head = (q_head + 1) % QUEUE_SIZE;
    }
    queue[q_tail] = ev;
    q_tail = next;
    pthread_cond_signal(&q_cond);
    pthread_mutex_unlock(&q_mutex);
}

/* Blocking dequeue */
void pop_event(event_t *ev) {
    pthread_mutex_lock(&q_mutex);
    while (q_head == q_tail) {
        pthread_cond_wait(&q_cond, &q_mutex);
    }
    *ev = queue[q_head];
    q_head = (q_head + 1) % QUEUE_SIZE;
    pthread_mutex_unlock(&q_mutex);
}

/* Monitor thread: read from fanotify and enqueue */
void *monitor_thread(void *arg) {
    (void)arg;
    struct pollfd pfd = { .fd = g_fan_fd, .events = POLLIN };
    char buf[8192];

    while (1) {
        int ret = poll(&pfd, 1, -1);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("monitor poll");
            break;
        }
        if (pfd.revents & POLLIN) {
            ssize_t len = read(g_fan_fd, buf, sizeof(buf));
            if (len < 0) {
                if (errno == EINTR) continue;
                perror("monitor read");
                break;
            }

            struct fanotify_event_metadata *md;
            for (char *ptr = buf; ptr < buf + len;
                 ptr += md->event_len) {
                md = (void*)ptr;

                /* version mismatch? */
                if (md->vers != FANOTIFY_METADATA_VERSION)
                    continue;

                /* drop overflow or notification-only events */
                if ((md->mask & FAN_Q_OVERFLOW) || md->fd < 0)
                    continue;

                push_event((event_t){
                    .mask = md->mask,
                    .pid  = md->pid,
                    .fd   = md->fd
                });
            }
        }
    }
    return NULL;
}
