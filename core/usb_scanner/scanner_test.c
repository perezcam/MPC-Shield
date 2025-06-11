#define _GNU_SOURCE
// scanner_test.c

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <limits.h>
#include <linux/limits.h> // For PATH_MAX
#include <sys/fanotify.h>
#include <fcntl.h>

#include "shared.h"  // Aquí están los prototipos y los extern de las globals

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int main(void) {
// 1) FD de contenido (sin REPORT_NAME)
g_fan_content_fd = fanotify_init(
    FAN_CLOEXEC
  | FAN_NONBLOCK
  | FAN_CLASS_CONTENT,    // md + fd de fichero
  O_RDONLY
| O_LARGEFILE
);
if (g_fan_content_fd < 0) {
  perror("fanotify_init content");
  return EXIT_FAILURE;
}

// 2) FD de notificación (aquí SÍ pedimos el nombre)
//    Usamos el macro FAN_REPORT_DFID_NAME = FAN_REPORT_NAME|FAN_REPORT_DIR_FID
g_fan_notify_fd = fanotify_init(
    FAN_CLOEXEC
  | FAN_NONBLOCK
  | FAN_CLASS_NOTIF       // sólo md, sin fd
  | FAN_REPORT_DFID_NAME, // nombre tras la metadata + dir-FID
  O_RDONLY
| O_LARGEFILE
);
if (g_fan_notify_fd < 0) {
  perror("fanotify_init notify");
  close(g_fan_content_fd);
  return EXIT_FAILURE;
}



    // 2) Launch scanner_thread, monitor_thread, worker_thread(s)
    pthread_t scan_tid;
    if (pthread_create(&scan_tid, NULL, scanner_thread, NULL) != 0) {
        perror("pthread_create scanner_thread");
        close(g_fan_content_fd);
        close(g_fan_notify_fd);
        return EXIT_FAILURE;
    }

    pthread_t mon_tid;
    if (pthread_create(&mon_tid, NULL, monitor_thread, NULL) != 0) {
        perror("pthread_create monitor_thread");
        pthread_cancel(scan_tid);
        pthread_join(scan_tid, NULL);
        close(g_fan_content_fd);
        close(g_fan_notify_fd);
        return EXIT_FAILURE;
    }

    #define NUM_WORKERS 2
    pthread_t workers[NUM_WORKERS];
    for (int i = 0; i < NUM_WORKERS; i++) {
        if (pthread_create(&workers[i], NULL, worker_thread, NULL) != 0) {
            perror("pthread_create worker_thread");
        }
    }

    // 3) Pausa corta para que scanner_thread haga su trabajo
    sleep(2);
    printf("\n=== Initial USB mounts ===\n");
    report_current_mounts();

    // 4) Test mark_mount en un tmpdir
    char tmpdir[] = "/tmp/usbtestXXXXXX";
    char *mount_dir = mkdtemp(tmpdir);
    if (!mount_dir) {
        perror("mkdtemp");
    } else {
        printf("\n=== Testing mark_mount on %s ===\n", mount_dir);
        mark_mount(mount_dir);

        char filepath[PATH_MAX];
        snprintf(filepath, sizeof(filepath), "%s/testfile.txt", mount_dir);
        FILE *f = fopen(filepath, "w");
        if (f) {
            fputs("hello world\n", f);
            fclose(f);
            sleep(1);  // <— dar tiempo a que monitor+worker detecten el CREATE
        } else {
            perror("fopen testfile");
        }
    }

    // 5) Loop infinito de report_current_mounts (igual que antes)
    while (1) {
        sleep(2);
        report_current_mounts();
    }

    // 6) (teórico) cleanup
    pthread_cancel(scan_tid);
    pthread_cancel(mon_tid);
    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_cancel(workers[i]);
        pthread_join(workers[i], NULL);
    }
    pthread_join(scan_tid, NULL);
    pthread_join(mon_tid, NULL);
    close(g_fan_content_fd);
    close(g_fan_notify_fd);
    return EXIT_SUCCESS;
}
