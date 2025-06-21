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
#include <glib.h>           // para g_async_queue_push, g_strdup, g_new0, g_free

#include "shared.h"         // declara GuiEvent, event_queue, get_current_mounts, etc.

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

    /* Empuja un GuiEvent a la cola para la GUI */
    GuiEvent *gev = g_new0(GuiEvent, 1);
    gev->time  = g_strdup(ts);
    gev->path  = g_strdup(filepath);
    gev->cause = g_strdup(cause_buf);
    g_async_queue_push(event_queue, gev);

    /* (Opcional) continúa imprimiendo en stdout */
    printf("[%s] File change: %s (pid=%d) cause=%s\n",
           ts, filepath, pid, cause_buf);
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

    /* Encolar evento */
    GuiEvent *gev = g_new0(GuiEvent, 1);
    gev->time  = g_strdup(ts);
    gev->path  = g_strdup(exe_path);
    gev->cause = g_strdup("suspicious");
    g_async_queue_push(event_queue, gev);

    printf("[%s] Suspicious process: pid=%d exe=%s\n",
           ts, pid, exe_path);
    fflush(stdout);
}

/* ------------------------------------------------------------------ */
/*          Live-view de dispositivos USB montados (opcional)        */
/* ------------------------------------------------------------------ */
static char **prev_mounts = NULL;
static int    prev_count  = 0;
static void free_prev_mounts(void) { /* ... igual que antes ... */ }

void report_current_mounts(void)
{
    /* Opcional: si quieres también encolar como GuiEvent puedes adaptarlo aquí,
       o simplemente dejar el printf para debugging. */
    /* ... código existente ... */
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
                            const struct stat *old_s,
                            const struct stat *new_s,
                            pid_t pid)
{
    char ts[64];
    timestamp(ts, sizeof(ts));

    if ((old_s->st_mode & 0777) != (new_s->st_mode & 0777)) {
        char buf[64];
        snprintf(buf, sizeof(buf), "perms %03o->%03o",
                 old_s->st_mode & 0777, new_s->st_mode & 0777);
        GuiEvent *gev = g_new0(GuiEvent, 1);
        gev->time  = g_strdup(ts);
        gev->path  = g_strdup(filepath);
        gev->cause = g_strdup(buf);
        g_async_queue_push(event_queue, gev);
        printf("[%s] [METADATA] %s %s pid=%d\n",
               ts, filepath, buf, pid);
    }
    if (old_s->st_size != new_s->st_size) {
        char buf[64];
        snprintf(buf, sizeof(buf), "size %lld->%lld",
                 (long long)old_s->st_size, (long long)new_s->st_size);
        GuiEvent *gev = g_new0(GuiEvent, 1);
        gev->time  = g_strdup(ts);
        gev->path  = g_strdup(filepath);
        gev->cause = g_strdup(buf);
        g_async_queue_push(event_queue, gev);
        printf("[%s] [METADATA] %s %s pid=%d\n",
               ts, filepath, buf, pid);
    }
    fflush(stdout);
}

void report_file_deletion(const char *filepath, pid_t pid)
{
    char ts[64];
    timestamp(ts, sizeof(ts));

    GuiEvent *gev = g_new0(GuiEvent, 1);
    gev->time  = g_strdup(ts);
    gev->path  = g_strdup(filepath);
    gev->cause = g_strdup("delete");
    g_async_queue_push(event_queue, gev);

    printf("[%s] File deleted: %s (pid=%d)\n",
           ts, filepath, pid);
    fflush(stdout);
}
