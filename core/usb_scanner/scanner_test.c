#define _GNU_SOURCE
// scanner_test.c
// Test harness for scanner.c using globals from shared.h

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <limits.h>
#include <linux/limits.h> // For PATH_MAX
#include <sys/fanotify.h>
#include <fcntl.h>

#include "shared.h"  // shared.h should declare:
int g_fan_content_fd;
int g_fan_notify_fd;

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

// Core scanner interfaces
extern void *scanner_thread(void *arg);
extern int get_current_mounts(char *mounts[], int max);
extern void mark_mount(const char *path);
extern void report_current_mounts(void);

int main(void) {
    // 1) Initialize fanotify fds (declared in shared.h)
    g_fan_content_fd = fanotify_init(
        FAN_CLASS_CONTENT, O_RDONLY | O_CLOEXEC
        | FAN_NONBLOCK |O_LARGEFILE
    );
    if (g_fan_content_fd < 0) {
        perror("fanotify_init content");
        return EXIT_FAILURE;
    }
    // Use NOTIF class for metadata (create/delete) events
    g_fan_notify_fd = fanotify_init(FAN_CLASS_NOTIF | FAN_REPORT_FID, O_RDONLY | O_CLOEXEC);
    if (g_fan_notify_fd < 0) {
        perror("fanotify_init notify");
        close(g_fan_content_fd);
        return EXIT_FAILURE;
    }

    // 2) Launch scanner thread
    pthread_t tid;
    if (pthread_create(&tid, NULL, scanner_thread, NULL) != 0) {
        perror("pthread_create scanner_thread");
        close(g_fan_content_fd);
        close(g_fan_notify_fd);
        return EXIT_FAILURE;
    }

    // 3) Give scanner_thread time to enumerate mounts
    sleep(2);
    printf("\n=== Initial USB mounts ===\n");
    report_current_mounts();

    // 4) Test mark_mount against a temporary directory (mount a tmpfs if testing MOUNT flag)
    char tmpdir[] = "/tmp/usbtestXXXXXX";
    char *mount_dir = mkdtemp(tmpdir);
    if (!mount_dir) {
        perror("mkdtemp");
    } else {
        printf("\n=== Testing mark_mount on %s ===\n", mount_dir);
        // If testing FAN_MARK_MOUNT, mount a tmpfs here:
        // sudo mount -t tmpfs tmpfs %s
        mark_mount(mount_dir);
        printf("Creating a file under %s to trigger events\n", mount_dir);
        char filepath[PATH_MAX];
        snprintf(filepath, sizeof(filepath), "%s/testfile.txt", mount_dir);
        FILE *f = fopen(filepath, "w");
        if (f) {
            fputs("hello world\n", f);
            fclose(f);
            sleep(1); // allow event to be processed
        } else {
            perror("fopen testfile");
        }
    }


    // 6) Infinite periodic reporting
    while (1) {
        sleep(2);
        // printf("\n=== USB mounts (periodic) ===\n");
        report_current_mounts();
    }
    // 6) Shutdown scanner_thread cleanly
    pthread_cancel(tid);
    pthread_join(tid, NULL);

    close(g_fan_content_fd);
    close(g_fan_notify_fd);
    return EXIT_SUCCESS;
}
