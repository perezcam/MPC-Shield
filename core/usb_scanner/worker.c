#include "shared.h"
#include <limits.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <asm-generic/fcntl.h>


/* Provided by report.c */
void report_file_modification(const char *filepath, uint64_t mask, pid_t        pid);
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

static int sha256_file(const char *path, unsigned char out[SHA256_DIGEST_LENGTH]) {
    unsigned char buf[8192];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0)
        SHA256_Update(&ctx, buf, n);
    close(fd);
    SHA256_Final(out, &ctx);
    return 0;
}

/* Helpers to resolve paths */
static void get_path_from_fd(int fd, char *out, size_t sz) {
    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t len = readlink(link, out, sz-1);
    out[(len>0)?len:0] = '\0';
}

static void get_exe_path(pid_t pid, char *out, size_t sz) {
    char link[64];
    snprintf(link, sizeof(link), "/proc/%d/exe", pid);
    ssize_t len = readlink(link, out, sz-1);
    out[(len>0)?len:0] = '\0';
}

/* Whitelist check */
static int is_legit(const char *exe) {
    const char *ok[] = { "/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/", NULL };
    for (int i = 0; ok[i]; i++)
        if (strncmp(exe, ok[i], strlen(ok[i])) == 0)
            return 1;
    return 0;
}
/*Know Malware list*/
static const unsigned char KNOWN_MALWARE[][SHA256_DIGEST_LENGTH] = {
    /* Zeus */ {0x12,0x34},
    /* WannaCry */ {0xab,0xcd}
};
static inline int is_known_malware(const unsigned char digest[SHA256_DIGEST_LENGTH]) {
    for (size_t i = 0; i < sizeof(KNOWN_MALWARE)/sizeof(KNOWN_MALWARE[0]); ++i)
        if (!memcmp(digest, KNOWN_MALWARE[i], SHA256_DIGEST_LENGTH))
            return 1;
    return 0;
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
            /* the file already exists */
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
        int bad_proc = !is_legit(ev.proc.exe);

        if (bad_hash || bad_proc) {
            report_suspicious(ev.proc.pid, ev.proc.exe);
        }

        report_file_modification(ev.file.path, ev.mask, ev.proc.pid);
    }
    return NULL;
}
