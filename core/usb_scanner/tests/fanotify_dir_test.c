#define _GNU_SOURCE
#include <sys/fanotify.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SZ 4096

int main(int argc, char *argv[]) {
    const char *dir = (argc > 1 ? argv[1] : "/tmp/fanotify_test");
    int fan_fd, dir_fd;
    unsigned long mask = FAN_CREATE | FAN_DELETE;

    /* 1) Open the directory so we can resolve file handles */
    dir_fd = open(dir, O_DIRECTORY | O_RDONLY);
    if (dir_fd < 0) {
        perror("open(dir)");
        return EXIT_FAILURE;
    }

    /* 2) Initialize fanotify */
    fan_fd = fanotify_init(FAN_CLASS_NOTIF | FAN_REPORT_FID, O_RDONLY);
    if(fan_fd == -1) {
        perror("fanotify_init");
        close(dir_fd);
        exit(EXIT_FAILURE);
    }


    /* 3) Mark just this directory for child-create/delete */
    int ret = fanotify_mark(
        fan_fd,
        FAN_MARK_ADD,
        mask | FAN_MODIFY | FAN_EVENT_ON_CHILD,
        AT_FDCWD,
        dir
    );
    if(ret == -1) {
        fprintf(
            stderr,
            "fanotify_mark(%s) failed: %s\n",
            dir, strerror(errno)
        );
        close(dir_fd);
        close(fan_fd);
        exit(EXIT_FAILURE);
    }

    printf("✔ Watching %s for CREATE and DELETE …\n", dir);

    /* 4) Event loop */
    while (1) {
        char buf[BUF_SZ];
        ssize_t len = read(fan_fd, buf, sizeof(buf));
        if (len < 0) {
            if (errno == EINTR) continue;
            perror("read");
            break;
        }

        for (ssize_t off = 0; off < len; off += FAN_EVENT_METADATA_LEN) {
            struct fanotify_event_metadata *ev = (void*)(buf + off);
            if (ev->vers != FANOTIFY_METADATA_VERSION) {
                fprintf(stderr, "Version mismatch\n");
                break;
            }

            if (ev->mask & FAN_CREATE)
                printf("CREATED:  fd=%d\n", ev->fd);
            if (ev->mask & FAN_DELETE)
                printf("DELETED in %s\n", dir);

            if (ev->fd >= 0)
                close(ev->fd);
        }
    }

    close(dir_fd);
    close(fan_fd);
    return EXIT_SUCCESS;
}
