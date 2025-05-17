// interface/main.c
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "monitor.h"

/* Flag para controlar el bucle principal */
static volatile sig_atomic_t keep_running = 1;

/* Handler de SIGINT (Ctrl+C) */
static void on_sigint(int signo) {
    (void)signo;
    keep_running = 0;
}

int main(int argc, char *argv[])
{
    /* Umbrales por defecto o pasados por argv */
    gdouble cpu_thr    = 0.10;
    guint64 mem_thr_mb = 100;
    if (argc >= 2) cpu_thr    = g_ascii_strtod(argv[1], NULL);
    if (argc >= 3) mem_thr_mb = (guint64)strtoull(argv[2], NULL, 10);

    /* Instalamos el handler para poder salir con Ctrl+C */
    signal(SIGINT, on_sigint);

    /* Inicializamos monitor y primera muestra para poblar previos */
    monitor_init(cpu_thr, mem_thr_mb);
    GPtrArray *procs = monitor_get_process_list();
    g_ptr_array_free(procs, TRUE);

    /* Bucle principal: cada segundo muestreamos y mostramos los sospechosos */
    while (keep_running) {
        g_usleep(1 * G_USEC_PER_SEC);

        procs = monitor_get_process_list();

        /* Limpiamos la pantalla (opcional) o imprimimos separación */
        printf("\033[H\033[J"); /* clear screen ANSI */
        printf(" Umbral CPU=%.1f%%  Mem=%" G_GUINT64_FORMAT "MB   (Ctrl+C para salir)\n",
               cpu_thr * 100.0, mem_thr_mb);
        printf(" PID    Nombre               CPU%%    MEM MB   Estado\n");
        printf("----------------------------------------------------\n");

        for (guint i = 0; i < procs->len; i++) {
            ProcInfo *info = g_ptr_array_index(procs, i);
            if (info->suspicious) {
                gdouble mem_mb = info->mem_rss / (1024.0 * 1024.0);
                printf("%5d  %-20s %6.2f  %8.2f   SÍ\n",
                       info->pid,
                       info->name,
                       info->cpu_percent * 100.0,
                       mem_mb);
            }
        }

        g_ptr_array_free(procs, TRUE);
    }

    /* Limpieza final */
    monitor_cleanup();
    printf("\nMonitor detenido. ¡Adiós!\n");
    return 0;
}
