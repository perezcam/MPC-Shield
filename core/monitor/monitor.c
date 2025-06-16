#include "monitor.h"
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

static const char *whitelist[] = {
    "gnome-shell",
    "Xorg",
    "xfwm4",
    "compiz",
    "plasmashell",
    "kwin_x11",
    "kwin_wayland",
    "conky",
    "pulseaudio",
    "pipewire",
    "systemd",
    "init",
    "bash",
    "zsh",
    "tmux",
    "screen",
    "ssh",
    "dbus-daemon",
    "chromium-browser",
    "chrome",
    "firefox",
    "alacritty",
    "gnome-terminal-",
    "konsole",
    "terminator",
    "code",           // VSCode
    "kate",
    "gedit",
    "nano",
    "vim",
    "emacs",
    "compiler",       // tu ejemplo
    NULL              // ¡Importante! Para terminar el array
};

static gboolean is_whitelisted(const char *proc_name) {
    for (int i = 0; whitelist[i] != NULL; ++i) {
        if (strcmp(proc_name, whitelist[i]) == 0)
            return TRUE;
    }
    return FALSE;
}

// Estructura interna para guardar el estado anterior de cada PID
typedef struct {
    guint64 cpu_ticks;  // utime + stime
    guint64 mem_rss;    // bytes
} PrevInfo;

// Variables estáticas de módulo
static GHashTable   *prev_table       = NULL;
static guint64       prev_total_cpu   = 0;
static gdouble       cpu_threshold    = 80.0;                // % CPU
static guint64       mem_threshold    = 200 * 1024 * 1024;   // bytes (200 MB)

// ----------------------------------------------------------------------------
// Lectura del total de ticks de CPU en todo el sistema (/proc/stat “cpu”)
// ----------------------------------------------------------------------------
static guint64 read_total_cpu(void) {
    FILE *f = fopen("/proc/stat","r");
    if (!f) return 0;
    char buf[512];
    if (!fgets(buf,sizeof(buf),f)) { fclose(f); return 0; }
    fclose(f);

    // Tokenizamos y sumamos todos los valores numéricos tras “cpu”
    guint64 sum = 0, val;
    char *tok = strtok(buf, " ");
    while ((tok = strtok(NULL, " "))) {
        if (sscanf(tok, "%llu", &val) == 1)
            sum += val;
    }
    return sum;
}

// ----------------------------------------------------------------------------
// Nombre de proceso: leemos /proc/[pid]/comm
// ----------------------------------------------------------------------------
static gchar* get_proc_name(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (!f) return g_strdup("");
    char buf[256];
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        return g_strdup("");
    }
    fclose(f);
    buf[strcspn(buf, "\n")] = '\0';
    return g_strdup(buf);
}

// ----------------------------------------------------------------------------
// Ticks de CPU de un proceso: utime + stime en /proc/[pid]/stat
// ----------------------------------------------------------------------------
static gboolean get_proc_times(pid_t pid, guint64 *ticks) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) return FALSE;

    int    _pid;
    char   comm[256], state;
    unsigned long utime, stime;

    if (fscanf(f, "%d (%255[^)]) %c", &_pid, comm, &state) != 3) {
        fclose(f);
        return FALSE;
    }

    // Saltamos campos 4–13
    for (int i = 0; i < 11; i++) {
        unsigned long dummy;
        fscanf(f, "%lu", &dummy);
    }
    if (fscanf(f, "%lu %lu", &utime, &stime) != 2) {
        fclose(f);
        return FALSE;
    }
    fclose(f);

    *ticks = (guint64)utime + (guint64)stime;
    return TRUE;
}

// ----------------------------------------------------------------------------
// Memoria residente de un proceso (VmRSS en kB) en /proc/[pid]/status
// ----------------------------------------------------------------------------
static gboolean get_proc_mem(pid_t pid, guint64 *rss_bytes) {
    char  path[64], buf[256];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *f = fopen(path, "r");
    if (!f) return FALSE;

    while (fgets(buf, sizeof(buf), f)) {
        if (g_str_has_prefix(buf, "VmRSS:")) {
            guint64 vm_kb;
            if (sscanf(buf, "VmRSS: %llu kB", &vm_kb) == 1) {
                *rss_bytes = vm_kb * 1024;
                fclose(f);
                return TRUE;
            }
        }
    }
    fclose(f);
    return FALSE;
}

// ----------------------------------------------------------------------------
// Inicialización y ajuste de umbrales:
//   cpu_thr: % de CPU; mem_thr_mb: MB de RAM
// ----------------------------------------------------------------------------
void monitor_init(gdouble cpu_thr, guint64 mem_thr_mb) {
    // Crear tabla una sola vez
    if (!prev_table) {
        prev_table     = g_hash_table_new_full(
                            g_direct_hash,
                            g_direct_equal,
                            NULL,
                            g_free        // libera PrevInfo al reemplazar
                         );
        prev_total_cpu = read_total_cpu();
    }
    // Ajustar umbrales siempre que se llame
    cpu_threshold  = cpu_thr;
    mem_threshold  = mem_thr_mb * 1024 * 1024;
}

// ----------------------------------------------------------------------------
// Lee todos los procesos, calcula %CPU y marca sospechosos.
// Devuelve un GPtrArray* de ProcInfo* (liberar con g_ptr_array_free(..., TRUE))
// ----------------------------------------------------------------------------
GPtrArray* monitor_get_process_list(void) {
    guint64     total_cpu_now = read_total_cpu();
    GPtrArray  *infos         = g_ptr_array_new_with_free_func(g_free);
    DIR        *dir           = opendir("/proc");
    struct dirent *entry;

    while ((entry = readdir(dir))) {
        if (!isdigit(entry->d_name[0])) continue;
        pid_t    pid   = atoi(entry->d_name);
        guint64  ticks, mem;
        if (!get_proc_times(pid, &ticks) ||
            !get_proc_mem(pid,   &mem))
            continue;

        gchar *name = get_proc_name(pid);
        ProcInfo *info = g_new0(ProcInfo, 1);
        info->pid       = pid;
        g_strlcpy(info->name, name, sizeof(info->name));
        info->cpu_ticks = ticks;
        info->mem_rss   = mem;

        PrevInfo *prev = g_hash_table_lookup(prev_table, GINT_TO_POINTER(pid));
        if (prev && (total_cpu_now > prev_total_cpu)) {
            guint64 dt     = ticks - prev->cpu_ticks;
            guint64 dt_tot = total_cpu_now - prev_total_cpu;
            info->cpu_percent = (gdouble)dt * 100.0 / (gdouble)dt_tot;
        } else {
            info->cpu_percent = 0.0;
        }

        info->suspicious =
            (info->cpu_percent > cpu_threshold) ||
            (info->mem_rss    > mem_threshold);

         // ---- SOLO AÑADIR SI ES SOSPECHOSO Y NO ESTÁ EN LA LISTA BLANCA ----
        if (info->suspicious && !is_whitelisted(info->name)) {
            g_ptr_array_add(infos, info);
        } else {
            g_free(info);
        }
        
        PrevInfo *new_prev = g_new0(PrevInfo, 1);
        new_prev->cpu_ticks = info->cpu_ticks;
        new_prev->mem_rss   = info->mem_rss;
        g_hash_table_replace(prev_table, GINT_TO_POINTER(pid), new_prev);
        g_free(name);
    }

    closedir(dir);
    prev_total_cpu = total_cpu_now;
    return infos;
}

// ----------------------------------------------------------------------------
// Limpieza al cerrar la aplicación
// ----------------------------------------------------------------------------
void monitor_cleanup(void) {
    if (prev_table) {
        g_hash_table_destroy(prev_table);
        prev_table = NULL;
    }
}
