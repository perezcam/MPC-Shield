#define _GNU_SOURCE

#include "shared.h"
#include <limits.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include "legitimacy.h"

/* ---------------------------------------------------------------- */
/* Funciones de informe (implementadas en report.c)                 */
/* ---------------------------------------------------------------- */
void report_file_modification(const char *filepath, uint64_t mask, pid_t pid);
void report_file_deletion   (const char *filepath, pid_t pid);
void report_suspicious      (pid_t pid, const char *path);
void report_metadata_change (const char *filepath,
                             const struct stat *old_s,
                             const struct stat *new_s,
                             pid_t pid);

/* ---------------------------------------------------------------- */
/* Helper: ruta del ejecutable del PID                              */
/* ---------------------------------------------------------------- */
static int get_process_info(pid_t pid, ProcessInfo *out) {
    char buf[PATH_MAX];
    snprintf(buf, sizeof(buf), "/proc/%d/exe", pid);
    ssize_t len = readlink(buf, out->exe, sizeof(out->exe)-1);
    if (len > 0) out->exe[len] = '\0';
    else          out->exe[0]   = '\0';
    out->pid = pid;
    return 0;
}

/* ---------------------------------------------------------------- */
/* worker_thread:
 *   - Consume eventos de la cola
 *   - Filtra CLOSE_WRITE y MOVED_FROM para evitar duplicados
 *   - Reporta DELETE, CREATE, MODIFY, MOVED_TO y ATTRIB
 *   - Siempre llama primero al report de acción original
 *   - Si el evento o el proceso es sospechoso, llama luego a report_suspicious
 *   - Actualiza la tabla de metadata para ATTRIB, MODIFY y MOVED_TO
/* ---------------------------------------------------------------- */
void *worker_thread(void *arg) {
    (void)arg;

    while (1) {
        EventInfo ev;
        pop_event(&ev);

        uint64_t m = ev.mask;

        /* Filtrar eventos irrelevantes */
        if (m & FAN_CLOSE_WRITE)    continue;
        if (m & FAN_MOVED_FROM)     continue;

        /* Obtener info del proceso */
        if (get_process_info(ev.proc.pid, &ev.proc) != 0)
            continue;

        /* BORRADO */
        if (m & FAN_DELETE) {
            report_file_deletion(ev.file.path, ev.proc.pid);
            if (!is_legit(ev.proc.exe)) {
                report_suspicious(ev.proc.pid, ev.file.path);
                atomic_fetch_add(&g_suspicious_events, 1);
            }
            continue;
        }

        /* Nos interesan ahora CREATE, MODIFY, MOVED_TO y ATTRIB */
        if (!(m & (FAN_CREATE | FAN_MODIFY | FAN_MOVED_TO | FAN_ATTRIB)))
            continue;

        /* Leer estado del fichero, si existe */
        struct stat st;
        if (stat(ev.file.path, &st) != 0) {
            /* Si fallo stat tras CREATE, igual es un archivo efímero */
            continue;
        }

        /* Reporte de la acción original (CREATE/MODIFY/ATTRIB/MOVED_TO) */
        report_file_modification(ev.file.path, m, ev.proc.pid);

        /* Validar hash y proceso, notificar si es sospechoso */
        int bad_hash = (!S_ISDIR(st.st_mode) && is_known_malware(ev.file.sha256));
        int bad_proc = !is_legit(ev.proc.exe);
        if (bad_hash || bad_proc) {
            report_suspicious(ev.proc.pid, ev.file.path);
            atomic_fetch_add(&g_suspicious_events, 1);
        }

        /* Metadata change para ATTRIB, MODIFY y MOVED_TO */
        if (m & (FAN_ATTRIB | FAN_MODIFY | FAN_MOVED_TO)) {
            struct stat old;
            if (pst_lookup(&path_table, ev.file.path, &old) == 0) {
                report_metadata_change(ev.file.path, &old, &st, ev.proc.pid);
            }
            pst_update(&path_table, ev.file.path, &st);
        }
    }

    return NULL;
}
