#ifndef MONITOR_H
#define MONITOR_H

#include <glib.h>      // GPtrArray, gboolean, gdouble, guint64
#include <sys/types.h> // pid_t

/* ---------------------------------------------------------------
 * Estructura que representa la información de un proceso
 * ---------------------------------------------------------------
 */
typedef struct {
    pid_t    pid;           // Identificador del proceso
    char     name[256];     // Nombre (comm) del proceso
    guint64  cpu_ticks;     // Ticks de CPU (utime+stime) en la última lectura
    guint64  mem_rss;       // Memoria residente en bytes (VmRSS)
    gdouble  cpu_percent;   // % de CPU calculado desde la pasada anterior
    gboolean suspicious;    // TRUE si supera umbral de CPU o memoria
} ProcInfo;

/* ---------------------------------------------------------------
 * monitor_init:
 *   Inicializa el módulo de monitorización.
 *   cpu_threshold → umbral de CPU (%)
 *   mem_threshold_mb → umbral de memoria (MB)
 * ---------------------------------------------------------------
 */
void
monitor_init(gdouble cpu_threshold,
             guint64 mem_threshold_mb);

/* ---------------------------------------------------------------
 * monitor_get_process_list:
 *   Lee /proc, calcula deltas de CPU/memoria y detección de picos.
 *   Devuelve un GPtrArray de ProcInfo*; la liberación de cada
 *   ProcInfo* y del array se hace con g_ptr_array_free(array, TRUE).
 * ---------------------------------------------------------------
 */
GPtrArray *
monitor_get_process_list(void);

/* ---------------------------------------------------------------
 * monitor_cleanup:
 *   Libera estructuras internas (hash table de estados previos).
 * ---------------------------------------------------------------
 */
void
monitor_cleanup(void);

#endif /* MONITOR_H */
