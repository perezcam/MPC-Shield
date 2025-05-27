// fanotify_mount_test.c
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

int main(int argc, char *argv[]) {
    const char *path = (argc > 1 ? argv[1] : "/tmp/fanotify_test");
    int fan_fd;
    /* these events are allowed with FAN_MARK_MOUNT */
    unsigned long mask = FAN_OPEN
                       | FAN_CLOSE_WRITE
                       | FAN_CLOSE_NOWRITE
                       | FAN_MODIFY;

    /* 1) init a notify-only FD */
    fan_fd = fanotify_init(
        FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK,
        O_RDONLY | O_LARGEFILE
    );
    if (fan_fd < 0) {
        perror("fanotify_init");
        return EXIT_FAILURE;
    }

    /* 2) try the mount mark */
    if (fanotify_mark(
            fan_fd,
            FAN_MARK_ADD | FAN_MARK_MOUNT,
            mask,
            AT_FDCWD,
            path
        ) < 0) {
        fprintf(stderr,
                "fanotify_mark(%s) failed: %s\n",
                path, strerror(errno));
        close(fan_fd);
        return EXIT_FAILURE;
    }

    /* 3) report success */
    printf("✔ fanotify_mark succeeded on mount containing %s\n", path);
    close(fan_fd);
    return EXIT_SUCCESS;
}
