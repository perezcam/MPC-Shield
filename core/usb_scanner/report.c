#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>

#include "shared.h"

/* ------------------------------------------------------------------ */
/*                         Utilidades generales                        */
/* ------------------------------------------------------------------ */

/* Timestamp helper ― devuelve “YYYY-MM-DD HH:MM:SS” */
static void timestamp(char *buf, size_t sz)
{
    time_t t = time(NULL);
    strftime(buf, sz, "%Y-%m-%d %H:%M:%S", localtime(&t));
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
        { 0,              NULL        }
    };

    char cause_buf[128] = "";
    for (int i = 0; causes[i].name; ++i) {
        if (mask & causes[i].bit) {
            if (*cause_buf)                /* concat con ‘|’ si hay varios */
                strcat(cause_buf, "|");
            strcat(cause_buf, causes[i].name);
        }
    }
    if (!*cause_buf)
        strcpy(cause_buf, "unknown");

    char ts[64];
    timestamp(ts, sizeof(ts));
    printf("[%s] File change: %s (pid=%d) cause=%s (mask=0x%lx)\n",
           ts, filepath, pid, cause_buf, mask);
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
/*                  Live-view de dispositivos USB montados             */
/* ------------------------------------------------------------------ */

extern void report_connected_devices(const char **devices, int count);

/* Snapshot anterior para comparar cambios */
static char **prev_mounts = NULL;
static int    prev_count  = -1;

static void free_prev_mounts(void)
{
    if (!prev_mounts)
        return;

    for (int i = 0; i < prev_count; ++i)
        free(prev_mounts[i]);

    free(prev_mounts);
    prev_mounts = NULL;
    prev_count  = -1;
}

/**
 * Report the up-to-date list of USB mounts.
 * Sólo se refresca la pantalla cuando la lista cambia,
 * emulando el comportamiento de utilidades como `top`.
 */
void report_current_mounts(void)
{
    char *mounts[MAX_USBS];
    int   n = get_current_mounts(mounts, MAX_USBS);

    /* 1️⃣  ¿Se modificó la lista? */
    int changed = (n != prev_count);
    if (!changed) {
        for (int i = 0; i < n && !changed; ++i)
            if (strcmp(mounts[i], prev_mounts[i]) != 0)
                changed = 1;
    }

    if (!changed) {                     /* Sin cambios → salida silenciosa */
        for (int i = 0; i < n; ++i)
            free(mounts[i]);
        return;
    }

    /* 2️⃣  Limpia la pantalla y re-pinta la info */
    printf("\033[2J\033[H");            /* ANSI clear-screen + cursor-home */

    char ts[20];
    timestamp(ts, sizeof(ts));

    printf("=== USB mounts (live) ===\n");
    printf("[%s] %d device%s mounted\n", ts, n, n == 1 ? "" : "s");
    for (int i = 0; i < n; ++i) {
        printf("  • %s\n", mounts[i]);
        free(mounts[i]);
    }
    fflush(stdout);

    /* 3️⃣  Actualiza el snapshot para la próxima llamada */
    free_prev_mounts();
    if (n > 0) {
        prev_mounts = malloc(sizeof(char *) * n);
        for (int i = 0; i < n; ++i)
            prev_mounts[i] = strdup(mounts[i]); /* dup de los paths */
    }
    prev_count = n;
}

/* Liberar memoria al finalizar el programa */
__attribute__((destructor))
static void cleanup_mount_cache(void)
{
    free_prev_mounts();
}
