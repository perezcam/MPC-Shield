#include "shared.h"
#include <limits.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <asm-generic/fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include "legitimacy.h"


/* Provided by report.c */
void report_file_modification(const char *filepath, uint64_t mask, pid_t pid);
void report_suspicious(pid_t pid, const char *exe_path);

/*Helpers to receive and validate Process Info*/

static int get_process_info(pid_t pid, ProcessInfo *out) {
    char buf[PATH_MAX];
    snprintf(buf, sizeof(buf), "/proc/%d/exe", pid);
    ssize_t len = readlink(buf, out->exe, sizeof(out->exe)-1);
    if (len != -1) out->exe[len] = '\\0';

    snprintf(buf, sizeof(buf), "/proc/%d/cmdline", pid);
    int fd = open(buf, O_RDONLY);
    if (fd >= 0) {
        len = read(fd, out->cmdline, sizeof(out->cmdline)-1);
        if (len > 0) out->cmdline[len] = '\\0';
        close(fd);
    }

    snprintf(buf, sizeof(buf), "/proc/%d/status", pid);
    FILE *fp = fopen(buf, "r");
    if (fp) {
        while (fgets(buf, sizeof(buf), fp)) {
            if (sscanf(buf, "Uid:\\t%u", &out->uid) == 1) continue;
            if (sscanf(buf, "Gid:\\t%u", &out->gid) == 1) continue;
            if (sscanf(buf, "PPid:\\t%d", &out->ppid) == 1) continue;
        }
        fclose(fp);
    }
    out->pid = pid;
    return 0;
}

/* Helpers to resolve paths */
int get_path_from_fd(int fd, char *buf, size_t bufsiz) {
    char linkpath[PATH_MAX];
    ssize_t len;

    if (buf == NULL || bufsiz == 0) {
        errno = EINVAL;
        return -1;
    }

    // Construimos la ruta "/proc/self/fd/<fd>"
    int n = snprintf(linkpath, sizeof(linkpath), "/proc/self/fd/%d", fd);
    if (n < 0 || (size_t)n >= sizeof(linkpath)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    // Leemos el enlace simbólico; readlink no añade '\0'
    len = readlink(linkpath, buf, bufsiz - 1);
    if (len < 0) {
        // errno ya está seteado por readlink
        return -1;
    }

    // Aseguramos un terminador nulo
    if ((size_t)len >= bufsiz) {
        buf[bufsiz - 1] = '\0';
    } else {
        buf[len] = '\0';
    }
    return 0;
}

static void get_exe_path(pid_t pid, char *out, size_t sz) {
    char link[64];
    snprintf(link, sizeof(link), "/proc/%d/exe", pid);
    ssize_t len = readlink(link, out, sz-1);
    out[(len>0)?len:0] = '\0';
}

void *worker_thread(void *arg) {
    (void)arg;
    while (1) {
        EventInfo ev;
        pop_event(&ev);

        if (get_process_info(ev.proc.pid, &ev.proc) != 0) {
            /* PID already finished */
            continue;
        }
        
        struct stat st;
        if (stat(ev.file.path, &st) != 0) {
            report_file_deletion(ev.file.path,ev.proc.pid);
            /*
            PENDIENTE INSERTAR LOGICA DE SOSPECHOSO PARA ELIMINACIONES
            */
            continue;
        }

        ev.file.mode  = st.st_mode;
        ev.file.mtime = st.st_mtim;  

        /*  SHA-256 */
        if (!S_ISDIR(st.st_mode)) {
            if (sha256_file(ev.file.path, ev.file.sha256) != 0) {
                /* Failed read */
                continue;
            }
        } else {
            memset(ev.file.sha256, 0, sizeof(ev.file.sha256));
        }

        /* Validacion de Legitimidad */
        int bad_hash = (!S_ISDIR(st.st_mode) && is_known_malware(ev.file.sha256));
        int bad_proc = is_legit(ev.proc.exe); //cambie legitimidad a negado marca lo ok

        if (bad_hash || bad_proc) {
            suspicious++;
            report_suspicious(ev.proc.pid, ev.proc.exe);
        }

        report_file_modification(ev.file.path, ev.mask, ev.proc.pid);
        /*  Only on modification events, compare & update PST */
        if (ev.mask & (FAN_ATTRIB|FAN_MODIFY|FAN_MOVED_TO)) {
            struct stat old;
            if (pst_lookup(&path_table, ev.file.path, &old) == 0) {
                report_metadata_change(ev.file.path, &old, &st, ev.proc.pid);
            }
            pst_update(&path_table, ev.file.path, &st);
        }
    }
    return NULL;
}
