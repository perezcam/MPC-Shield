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

#include "shared.h"

/* ------------------------------------------------------------------ */
/*                         Utilidades generales                       */
/* ------------------------------------------------------------------ */

/* Timestamp helper ― devuelve “YYYY-MM-DD HH:MM:SS” */
static void timestamp(char *buf, size_t sz)
{
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(buf, sz, "%Y-%m-%d %H:%M:%S", &tm);
}

/* Print file metadata: inode, size, uid, gid, perms, mtime */
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
    /* Tabla bit → nombre legible */
    static const struct {
        uint64_t    bit;
        const char *name;
    } causes[] = {
        { FAN_CREATE,     "create"    },
        { FAN_DELETE,     "delete"    },
        { FAN_MOVED_FROM, "move-from" },
        { FAN_MOVED_TO,   "move-to"   },
        { FAN_MODIFY,     "modify"    },
        { FAN_ATTRIB,     "attrib"    },
        { FAN_ACCESS,   "access"   },
        { FAN_OPEN,     "open"     },
        { 0,              NULL         }
    };

    char cause_buf[128] = "";
    for (int i = 0; causes[i].name; ++i) {
        if (mask & causes[i].bit) {
            if (*cause_buf)
                strcat(cause_buf, "|");
            strcat(cause_buf, causes[i].name);
        }
    }
    if (!*cause_buf)
        strcpy(cause_buf, "unknown");

    char ts[64];
    timestamp(ts, sizeof(ts));
    printf("[%s] File change: %s (pid=%d) cause=%s (mask=0x%llx)\n",
           ts, filepath, pid, cause_buf, (unsigned long long)mask);

    /* Imprime metadata del fichero */
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
    printf("[%s] Suspicious process: pid=%d exe=%s\n",
           ts, pid, exe_path);
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

    /* Detectar cambio */
    int changed = (n != prev_count);
    if (!changed) {
        for (int i = 0; i < n; ++i) {
            if (strcmp(mounts[i], prev_mounts[i]) != 0) {
                changed = 1;
                break;
            }
        }
    }

    /* Si no cambió, limpiar mounts temporal y salir */
    if (!changed) {
        for (int i = 0; i < n; ++i)
            free(mounts[i]);
        return;
    }

    /* Mostrar nueva lista */
    char ts[64];
    timestamp(ts, sizeof(ts));
    printf("=== USB mounts (live) ===\n");
    printf("[%s] %d device%s mounted\n", ts, n, n == 1 ? "" : "s");
    for (int i = 0; i < n; ++i) {
        printf("  • %s\n", mounts[i]);
    }
    fflush(stdout);

    /* Actualizar snapshot */
    free_prev_mounts();
    if (n > 0) {
        prev_mounts = malloc(sizeof(char*) * n);
        for (int i = 0; i < n; ++i) {
            prev_mounts[i] = strdup(mounts[i]);
        }
        prev_count = n;
    }

    /* Liberar mounts temporal */
    for (int i = 0; i < n; ++i)
        free(mounts[i]);
}

__attribute__((destructor))
static void cleanup_mount_cache(void)
{
    free_prev_mounts();
}

/**
 * report_metadata_change:
 *   Compares old vs current stat and prints any permission, size, or mtime differences.
 */
void report_metadata_change(const char *filepath,
                            const struct stat *old,
                            const struct stat *curr,
                            pid_t pid)
{
    /* Permissions (owner/group/other bits only) */
    mode_t old_perms = old->st_mode & 0777;
    mode_t curr_perms = curr->st_mode & 0777;
    if (old_perms != curr_perms) {
        printf("[METADATA] %s perms: %03o -> %03o by PID %d\n",
               filepath, old_perms, curr_perms, pid);
    }

    /* Size */
    if (old->st_size != curr->st_size) {
        printf("[METADATA] %s size: %lld -> %lld by PID %d\n",
               filepath,
               (long long)old->st_size,
               (long long)curr->st_size,
               pid);
    }

    /* Modification time */
    if (old->st_mtime != curr->st_mtime ||
        old->st_mtime != curr->st_mtime)
    {
        printf("[METADATA] %s mtime: %lld.%09ld -> %lld.%09ld by PID %d\n",
               filepath,
               (long long)old->st_mtime,  old->st_mtime,
               (long long)curr->st_mtime, curr->st_mtime,
               pid);
    }
}
