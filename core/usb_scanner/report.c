// report.c
#define _GNU_SOURCE
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/fanotify.h>
#include <limits.h>
#include <errno.h>
#include <glib.h>           // <-- para g_async_queue_push, g_strdup

#include "shared.h"

/* ------------------------------------------------------------------ */
/*                         Utilidades generales                       */
/* ------------------------------------------------------------------ */
static void timestamp(char *buf, size_t sz)
{
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(buf, sz, "%Y-%m-%d %H:%M:%S", &tm);
}

static void print_file_stat(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0) {
        char mtime[32];
        struct tm tm;
        localtime_r(&st.st_mtime, &tm);
        strftime(mtime, sizeof(mtime), "%Y-%m-%d %H:%M:%S", &tm);
        printf("    inode=%llu size=%lld bytes uid=%u gid=%u perms=%04o mtime=%s\n",
               (unsigned long long)st.st_ino,
               (long long)st.st_size,
               st.st_uid, st.st_gid,
               st.st_mode & 07777,
               mtime);
    } else {
        printf("    stat failed for %s: %s\n", path, strerror(errno));
    }
}

/* ------------------------------------------------------------------ */
/*                   Reporte de modificaciones de archivos            */
/* ------------------------------------------------------------------ */
void report_file_modification(const char *filepath,
                              uint64_t     mask,
                              pid_t        pid)
{
    static const struct { uint64_t bit; const char *name; } causes[] = {
        { FAN_CREATE,     "create"    },
        { FAN_DELETE,     "delete"    },
        { FAN_MOVED_FROM, "move-from" },
        { FAN_MOVED_TO,   "move-to"   },
        { FAN_MODIFY,     "modify"    },
        { FAN_ATTRIB,     "attrib"    },
        { FAN_ACCESS,     "access"    },
        { FAN_OPEN,       "open"      },
        { 0,              NULL        }
    };

    char cause_buf[128] = "";
    for (int i = 0; causes[i].name; ++i) {
        if (mask & causes[i].bit) {
            if (*cause_buf) strcat(cause_buf, "|");
            strcat(cause_buf, causes[i].name);
        }
    }
    if (!*cause_buf) strcpy(cause_buf, "unknown");

    char ts[64];
    timestamp(ts, sizeof(ts));

    char line[1024];
    snprintf(line, sizeof(line),
        "[%s] File change: %s (pid=%d) cause=%s (mask=0x%llx)",
        ts, filepath, pid, cause_buf, (unsigned long long)mask);

    // 1) Empuja a la cola para la GUI
    g_async_queue_push(event_queue, g_strdup(line));

    // 2) (Opcional) sigue imprimiendo en stdout
    printf("%s\n", line);
    print_file_stat(filepath);
    fflush(stdout);
}

/* ------------------------------------------------------------------ */
/*                     Reporte de procesos sospechosos                */
/* ------------------------------------------------------------------ */
void report_suspicious(pid_t pid, const char *exe_path)
{
    char ts[64];
    timestamp(ts, sizeof(ts));

    char line[512];
    snprintf(line, sizeof(line),
        "[%s] Suspicious process: pid=%d exe=%s",
        ts, pid, exe_path);

    g_async_queue_push(event_queue, g_strdup(line));
    printf("%s\n", line);
    fflush(stdout);
}

/* ------------------------------------------------------------------ */
/*                  Live-view de dispositivos USB montados           */
/* ------------------------------------------------------------------ */
static char **prev_mounts = NULL;
static int    prev_count  = 0;

static void free_prev_mounts(void)
{
    for (int i = 0; i < prev_count; ++i)
        free(prev_mounts[i]);
    free(prev_mounts);
    prev_mounts = NULL;
    prev_count  = 0;
}

void report_current_mounts(void)
{
    char *mounts[MAX_USBS];
    int   n = get_current_mounts(mounts, MAX_USBS);

    // Detectar cambio
    int changed = (n != prev_count);
    if (!changed) {
        for (int i = 0; i < n; ++i) {
            if (strcmp(mounts[i], prev_mounts[i]) != 0) {
                changed = 1;
                break;
            }
        }
    }

    if (changed) {
        char ts[64];
        timestamp(ts, sizeof(ts));

        char header[128];
        snprintf(header, sizeof(header),
            "[%s] USB mounts changed: %d device%s",
            ts, n, n == 1 ? "" : "s");
        g_async_queue_push(event_queue, g_strdup(header));
        printf("=== USB mounts (live) ===\n");
        printf("%s\n", header);

        for (int i = 0; i < n; ++i) {
            char line[PATH_MAX + 8];
            snprintf(line, sizeof(line), "  • %s", mounts[i]);
            g_async_queue_push(event_queue, g_strdup(line));
            printf("%s\n", line);
        }
        fflush(stdout);

        // Actualizar snapshot
        free_prev_mounts();
        if (n > 0) {
            prev_mounts = malloc(sizeof(char*) * n);
            for (int i = 0; i < n; ++i)
                prev_mounts[i] = strdup(mounts[i]);
            prev_count = n;
        }
    }

    // Liberar mounts temporales
    for (int i = 0; i < n; ++i)
        free(mounts[i]);
}

__attribute__((destructor))
static void cleanup_mount_cache(void)
{
    free_prev_mounts();
}

/* ------------------------------------------------------------------ */
/*          Reporte de metadatos y eliminación de archivos           */
/* ------------------------------------------------------------------ */
void report_metadata_change(const char *filepath,
                            const struct stat *old,
                            const struct stat *curr,
                            pid_t pid)
{
    char ts[64];
    timestamp(ts, sizeof(ts));

    if ((old->st_mode & 0777) != (curr->st_mode & 0777)) {
        char line[256];
        snprintf(line, sizeof(line),
            "[%s] [METADATA] %s perms %03o->%03o pid=%d",
            ts, filepath,
            old->st_mode & 0777, curr->st_mode & 0777,
            pid);
        g_async_queue_push(event_queue, g_strdup(line));
        printf("%s\n", line);
    }
    if (old->st_size != curr->st_size) {
        char line[256];
        snprintf(line, sizeof(line),
            "[%s] [METADATA] %s size %lld->%lld pid=%d",
            ts, filepath,
            (long long)old->st_size, (long long)curr->st_size,
            pid);
        g_async_queue_push(event_queue, g_strdup(line));
        printf("%s\n", line);
    }
    if (old->st_mtime != curr->st_mtime) {
        char line[256];
        snprintf(line, sizeof(line),
            "[%s] [METADATA] %s mtime %lld->%lld pid=%d",
            ts, filepath,
            (long long)old->st_mtime, (long long)curr->st_mtime,
            pid);
        g_async_queue_push(event_queue, g_strdup(line));
        printf("%s\n", line);
    }
    fflush(stdout);
}

void report_file_deletion(const char *filepath, pid_t pid)
{
    char ts[64];
    timestamp(ts, sizeof(ts));

    char line[512];
    snprintf(line, sizeof(line),
        "[%s] File deleted: %s (pid=%d)",
        ts, filepath, pid);

    g_async_queue_push(event_queue, g_strdup(line));
    printf("%s\n", line);
    fflush(stdout);
}
