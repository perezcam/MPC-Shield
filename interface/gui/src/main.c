#define _GNU_SOURCE

#include <gtk/gtk.h>
#include <glib.h>                   // Para GAsyncQueue
#include <pthread.h>                // Para PTHREAD_MUTEX_INITIALIZER
#include "scanner.h"                // scan_ports()
#include "../../core/monitor/monitor.h"    // monitor_init(), monitor_cleanup()
#include "../../core/usb_scanner/shared.h" // get_current_mounts(), MAX_USBS, scann_start/stop, path_stat_table_t, GuiEvent

/* ---------------------------------------------------------------- */
/* Globals necesarias para usb_scanner/monitor.c                    */
/* ---------------------------------------------------------------- */
int               g_fan_content_fd = -1;
int               g_fan_notify_fd  = -1;
pthread_mutex_t   path_table_mutex = PTHREAD_MUTEX_INITIALIZER;
path_stat_table_t path_table;

/* ---------------------------------------------------------------- */
/* Cola de eventos (definida aquí para que linkee correctamente)    */
/* ---------------------------------------------------------------- */
GAsyncQueue *event_queue = NULL;

/* ---------------- Índices de columnas Puertos -------------------- */
enum {
    COL_PORT,
    COL_CLASS,
    COL_BANNER,
    COL_DANGEROUS_WORD,
    COL_SECURITY_LEVEL,
    N_PORT_COLS
};

/* --------------- Índices de columnas Monturas USB ---------------- */
enum {
    COL_MOUNT_PATH,
    N_MOUNT_COLS
};

/* -------- Índices de columnas Eventos USB (hora, ruta, causa) ---- */
enum {
    COL_EVENT_TIME,
    COL_EVENT_PATH,
    COL_EVENT_CAUSE,
    N_EVENT_COLS
};

/* --------------- Índices de columnas Procesos --------------------- */
enum {
    COL_PID,
    COL_PNAME,
    COL_CPU,
    COL_MEM,
    COL_SUSPICIOUS,
    N_PROC_COLS
};

/* Estructura para los SpinButtons de umbral */
typedef struct {
    GtkSpinButton *cpu_spin;
    GtkSpinButton *mem_spin;
} ThresholdWidgets;

/* Prototipos GTK */
static gboolean update_ports           (gpointer user_data);
static void    prepare_ports_treeview  (GtkBuilder *builder);
static gboolean update_mounts          (gpointer user_data);
static void    prepare_mounts_treeview (GtkBuilder *builder);
static gboolean update_usb_events      (gpointer user_data);
static void    prepare_usb_events_treeview(GtkBuilder *builder);
static gboolean update_processes       (gpointer user_data);
static void    prepare_processes_treeview(GtkBuilder *builder);
static void    on_threshold_changed    (GtkSpinButton *spin, gpointer user_data);
static void    on_activate             (GtkApplication *app, gpointer user_data);

/* ---------------- update_ports: refresca “Puertos” ------------- */
static gboolean update_ports(gpointer user_data)
{
    GtkListStore *store = GTK_LIST_STORE(user_data);
    gtk_list_store_clear(store);

    ScanResult res = scan_ports();
    for (int i = 0; i < res.size; i++) {
        ScanOutput *o = &res.data[i];
        GtkTreeIter iter;
        gtk_list_store_append(store, &iter);
        gtk_list_store_set(store, &iter,
            COL_PORT,           o->port,
            COL_CLASS,          o->classification,
            COL_BANNER,         o->banner,
            COL_DANGEROUS_WORD, o->dangerous_word,
            COL_SECURITY_LEVEL, o->security_level,
            -1);
    }
    free_result(&res);
    return G_SOURCE_CONTINUE;
}

/* ---------------- preparar Puertos --------------------------- */
static void prepare_ports_treeview(GtkBuilder *builder)
{
    GtkTreeView  *tv    = GTK_TREE_VIEW(
        gtk_builder_get_object(builder, "tree_ports"));
    GtkListStore *store = gtk_list_store_new(
        N_PORT_COLS,
        G_TYPE_INT,
        G_TYPE_STRING,
        G_TYPE_STRING,
        G_TYPE_STRING,
        G_TYPE_STRING
    );
    const char *titles[N_PORT_COLS] = {
        "Puerto", "Clasificación", "Banner",
        "Palabra Peligrosa", "Nivel Seguridad"
    };
    for (int i = 0; i < N_PORT_COLS; i++) {
        GtkCellRenderer *rnd = gtk_cell_renderer_text_new();
        gtk_tree_view_insert_column_with_attributes(
            tv, -1, titles[i], rnd, "text", i, NULL);
    }
    gtk_tree_view_set_model(tv, GTK_TREE_MODEL(store));
    update_ports(store);
    g_timeout_add_seconds(5, update_ports, store);
}

/* ---------------- update_mounts: refresca Monturas USB ------------ */
static gboolean update_mounts(gpointer user_data)
{
    GtkListStore *store = GTK_LIST_STORE(user_data);
    gtk_list_store_clear(store);

    char *mounts[MAX_USBS];
    int   n = get_current_mounts(mounts, MAX_USBS);
    for (int i = 0; i < n; i++) {
        GtkTreeIter iter;
        gtk_list_store_append(store, &iter);
        gtk_list_store_set(store, &iter,
            COL_MOUNT_PATH, mounts[i],
            -1);
        free(mounts[i]);
    }
    return G_SOURCE_CONTINUE;
}

/* ------------- preparar Monturas USB TreeView ------------------ */
static void prepare_mounts_treeview(GtkBuilder *builder)
{
    GtkTreeView  *tv    = GTK_TREE_VIEW(
        gtk_builder_get_object(builder, "tree_mounts"));
    GtkListStore *store = gtk_list_store_new(
        N_MOUNT_COLS,
        G_TYPE_STRING
    );
    GtkCellRenderer *rnd = gtk_cell_renderer_text_new();
    gtk_tree_view_insert_column_with_attributes(
        tv, -1, "Monturas USB", rnd, "text", COL_MOUNT_PATH, NULL);
    gtk_tree_view_set_model(tv, GTK_TREE_MODEL(store));
    update_mounts(store);
    g_timeout_add_seconds(1, update_mounts, store);
}

/* ---------------- update_usb_events: refresca Eventos USB --------- */
static gboolean update_usb_events(gpointer user_data)
{
    GtkTreeView  *tv    = GTK_TREE_VIEW(user_data);
    GtkListStore *store = GTK_LIST_STORE(
        gtk_tree_view_get_model(tv)
    );

    /* Sacamos todos los GuiEvent de la cola */
    while (g_async_queue_length(event_queue) > 0) {
        GuiEvent *ev = g_async_queue_try_pop(event_queue);
        if (!ev) break;

        GtkTreeIter it;
        gtk_list_store_append(store, &it);
        gtk_list_store_set(store, &it,
            COL_EVENT_TIME,  ev->time,
            COL_EVENT_PATH,  ev->path,
            COL_EVENT_CAUSE, ev->cause,
            -1);

        /* liberamos */
        g_free(ev->time);
        g_free(ev->path);
        g_free(ev->cause);
        g_free(ev);
    }
    return G_SOURCE_CONTINUE;
}

/* -------- preparar USB Events TreeView ------------------------ */
static void prepare_usb_events_treeview(GtkBuilder *builder)
{
    GtkTreeView  *tv    = GTK_TREE_VIEW(
        gtk_builder_get_object(builder, "tree_usb_events"));
    GtkListStore *store = gtk_list_store_new(
        N_EVENT_COLS,
        G_TYPE_STRING,  /* tiempo */
        G_TYPE_STRING,  /* ruta */
        G_TYPE_STRING   /* causa */
    );
    const char *titles[N_EVENT_COLS] = { "Hora", "Ruta", "Causa" };
    for (int i = 0; i < N_EVENT_COLS; i++) {
        GtkCellRenderer *rnd = gtk_cell_renderer_text_new();
        gtk_tree_view_insert_column_with_attributes(
            tv, -1, titles[i], rnd, "text", i, NULL);
    }
    gtk_tree_view_set_model(tv, GTK_TREE_MODEL(store));
    g_timeout_add_seconds(1, update_usb_events, tv);
}

/* ---------------- update_processes: refresca “Procesos” --------- */
static gboolean update_processes(gpointer user_data)
{
    GtkListStore *store = GTK_LIST_STORE(user_data);
    gtk_list_store_clear(store);

    GPtrArray *arr = monitor_get_process_list();
    for (guint i = 0; i < arr->len; ++i) {
        ProcInfo *p = g_ptr_array_index(arr, i);
        GtkTreeIter it;
        gtk_list_store_append(store, &it);

        gdouble mem_mb = p->mem_rss / 1048576.0;
        const char *alert = p->suspicious ? "⚠️" : "";

        gtk_list_store_set(store, &it,
            COL_PID,        p->pid,
            COL_PNAME,      p->name,
            COL_CPU,        p->cpu_percent,
            COL_MEM,        mem_mb,
            COL_SUSPICIOUS, alert,
            -1);
    }
    g_ptr_array_free(arr, TRUE);
    return G_SOURCE_CONTINUE;
}

/* ------------- preparar Procesos TreeView ---------------------- */
static void prepare_processes_treeview(GtkBuilder *builder)
{
    GtkTreeView  *tv    = GTK_TREE_VIEW(
        gtk_builder_get_object(builder, "tree_processes"));
    GtkListStore *store = gtk_list_store_new(
        N_PROC_COLS,
        G_TYPE_INT,
        G_TYPE_STRING,
        G_TYPE_DOUBLE,
        G_TYPE_DOUBLE,
        G_TYPE_STRING
    );
    const char *titles[N_PROC_COLS] = {
        "PID", "Nombre", "% CPU", "Mem (MB)", "Alerta"
    };
    for (int i = 0; i < N_PROC_COLS; ++i) {
        GtkCellRenderer *rnd = gtk_cell_renderer_text_new();
        if (i == COL_PID || i == COL_CPU || i == COL_MEM)
            g_object_set(rnd, "xalign", 1.0, NULL);
        gtk_tree_view_insert_column_with_attributes(
            tv, -1, titles[i], rnd, "text", i, NULL);
    }
    gtk_tree_view_set_model(tv, GTK_TREE_MODEL(store));
    g_timeout_add_seconds(1, update_processes, store);
}

/* ---------------- umbrales CPU/Mem ----------------------------- */
static void on_threshold_changed(GtkSpinButton *spin, gpointer user_data)
{
    ThresholdWidgets *th = user_data;
    monitor_init(
        gtk_spin_button_get_value(th->cpu_spin),
        gtk_spin_button_get_value(th->mem_spin)
    );
}

/* ---------------------- on_activate ---------------------------- */
static void on_activate(GtkApplication *app, gpointer data)
{
    /* 0) Crear cola de eventos */
    event_queue = g_async_queue_new();

    /* 1) Arrancar backend de fanotify/USB */
    scann_start();

    /* 2) Cargar CSS */
    GtkCssProvider *prov = gtk_css_provider_new();
    gtk_css_provider_load_from_path(prov, "ui/matrix.css");
    gtk_style_context_add_provider_for_display(
        gdk_display_get_default(),
        GTK_STYLE_PROVIDER(prov),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION
    );
    g_object_unref(prov);

    /* 3) Cargar interfaz */
    GtkBuilder *builder = gtk_builder_new_from_file("ui/main_window.ui");
    GtkWindow  *win     = GTK_WINDOW(
        gtk_builder_get_object(builder, "main_window"));
    gtk_window_set_application(win, app);

    /* 4) Umbrales */
    ThresholdWidgets *th = g_new0(ThresholdWidgets, 1);
    th->cpu_spin = GTK_SPIN_BUTTON(
        gtk_builder_get_object(builder, "cpu_threshold_spin"));
    th->mem_spin = GTK_SPIN_BUTTON(
        gtk_builder_get_object(builder, "mem_threshold_spin"));
    double cpu_init = gtk_spin_button_get_value(th->cpu_spin);
    double mem_init = gtk_spin_button_get_value(th->mem_spin);
    monitor_init(cpu_init, mem_init);
    g_signal_connect(th->cpu_spin, "value-changed",
                     G_CALLBACK(on_threshold_changed), th);
    g_signal_connect(th->mem_spin, "value-changed",
                     G_CALLBACK(on_threshold_changed), th);

    /* 5) Montar vistas */
    prepare_mounts_treeview(builder);
    prepare_usb_events_treeview(builder);
    prepare_ports_treeview(builder);
    prepare_processes_treeview(builder);

    /* 6) Mostrar ventana */
    gtk_window_present(win);
    g_object_unref(builder);
}

/* ------------------------ main ------------------------------ */
int main(int argc, char *argv[])
{
    GtkApplication *app =
        gtk_application_new("org.matcom.guard", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(on_activate), NULL);
    int status = g_application_run(G_APPLICATION(app), argc, argv);

    /* Al cerrar: parar backend y cleanup */
    scann_stop();
    monitor_cleanup();
    g_async_queue_unref(event_queue);
    g_object_unref(app);
    return status;
}
