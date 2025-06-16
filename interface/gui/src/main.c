#include <gtk/gtk.h>
#include "scanner.h"                 // Tu core de puertos
#include "../../core/monitor/monitor.h"  // Tu core de monitor

/* -------------------- Índices de columnas Puertos -------------------- */
enum {
    COL_PORT,            // port (int)
    COL_CLASS,           // classification (string)
    COL_BANNER,          // banner (string)
    COL_DANGEROUS_WORD,  // dangerous_word (string)
    COL_SECURITY_LEVEL,  // security_level (string)
    N_PORT_COLS
};

/* ------------------ Índices de columnas Procesos ------------------ */
enum {
    COL_PID,            // PID (int)
    COL_PNAME,          // Nombre (string)
    COL_CPU,            // % CPU (double)
    COL_MEM,            // Memoria MB (double)
    COL_SUSPICIOUS,     // “⚠️” (string)
    N_PROC_COLS
};

/* ------- Estructura para los SpinButtons de umbral ------- */
typedef struct {
    GtkSpinButton *cpu_spin;
    GtkSpinButton *mem_spin;
} ThresholdWidgets;

/* ----- Prototipos ----- */
static gboolean update_ports(gpointer user_data);
static void    prepare_ports_treeview(GtkBuilder *builder);

static gboolean update_processes(gpointer user_data);
static void    prepare_processes_treeview(GtkBuilder *builder);

/* Callback para cuando cambie CPU o Memoria */
static void
on_threshold_changed(GtkSpinButton *spin, gpointer user_data)
{
    ThresholdWidgets *th = user_data;

    double cpu = gtk_spin_button_get_value(th->cpu_spin);
    double mem = gtk_spin_button_get_value(th->mem_spin);

    monitor_init(cpu, mem);
}

/* ---------------- update_ports: refresca la pestaña Puertos ------------- */
static gboolean update_ports (gpointer user_data)
{
    GtkListStore *store = GTK_LIST_STORE(user_data);
    gtk_list_store_clear(store);

    ScanResult res = scan_ports();
    for (int i = 0; i < res.size; i++) {
        ScanOutput *o = &res.data[i];
        GtkTreeIter iter;
        gtk_list_store_append(store, &iter);
        gtk_list_store_set(store, &iter,
            COL_PORT,            o->port,
            COL_CLASS,           o->classification,
            COL_BANNER,          o->banner,
            COL_DANGEROUS_WORD,  o->dangerous_word,
            COL_SECURITY_LEVEL,  o->security_level,
            -1);
    }
    free_result(&res);
    return G_SOURCE_CONTINUE;
}

/* -------------- prepare_ports_treeview: monta la pestaña Puertos -------------- */
static void prepare_ports_treeview(GtkBuilder *builder)
{
    GtkTreeView  *tv    = GTK_TREE_VIEW(
        gtk_builder_get_object(builder, "tree_ports"));
    GtkListStore *store = gtk_list_store_new(
        N_PORT_COLS,
        G_TYPE_INT,    // COL_PORT
        G_TYPE_STRING, // COL_CLASS
        G_TYPE_STRING, // COL_BANNER
        G_TYPE_STRING, // COL_DANGEROUS_WORD
        G_TYPE_STRING  // COL_SECURITY_LEVEL
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

/* ---------------- update_processes: refresca la pestaña Procesos ------------- */
static gboolean update_processes (gpointer user_data)
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

/* ------------ prepare_processes_treeview: monta la pestaña Procesos ------------ */
static void prepare_processes_treeview(GtkBuilder *builder)
{
    GtkTreeView  *tv    = GTK_TREE_VIEW(
        gtk_builder_get_object(builder, "tree_processes"));
    GtkListStore *store = gtk_list_store_new(
        N_PROC_COLS,
        G_TYPE_INT,    // COL_PID
        G_TYPE_STRING, // COL_PNAME
        G_TYPE_DOUBLE, // COL_CPU
        G_TYPE_DOUBLE, // COL_MEM
        G_TYPE_STRING  // COL_SUSPICIOUS
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
    update_processes(store);
    g_timeout_add_seconds(1, update_processes, store);
}

/* ---------------------- on_activate: arranca todo ---------------------- */
static void on_activate (GtkApplication *app, gpointer data)
{
    // 1) Cargar la UI
    GtkBuilder *builder = gtk_builder_new_from_file("ui/main_window.ui");
    GtkWindow  *window  = GTK_WINDOW(
        gtk_builder_get_object(builder, "main_window"));
    gtk_window_set_application(window, app);

    // 2) Recuperar los SpinButtons de umbral
    ThresholdWidgets *th = g_new0(ThresholdWidgets, 1);
    th->cpu_spin = GTK_SPIN_BUTTON(
        gtk_builder_get_object(builder, "cpu_threshold_spin"));
    th->mem_spin = GTK_SPIN_BUTTON(
        gtk_builder_get_object(builder, "mem_threshold_spin"));

    // 3) Leer valores iniciales y arrancar monitor
    double cpu_init = gtk_spin_button_get_value(th->cpu_spin);
    double mem_init = gtk_spin_button_get_value(th->mem_spin);
    monitor_init(cpu_init, mem_init);

    // 4) Conectar cambios de umbral
    g_signal_connect(th->cpu_spin, "value-changed",
                     G_CALLBACK(on_threshold_changed), th);
    g_signal_connect(th->mem_spin, "value-changed",
                     G_CALLBACK(on_threshold_changed), th);

    // 5) Montar cada pestaña
    prepare_ports_treeview(builder);
    // prepare_devices_treeview(builder);  // cuando la tengas
    prepare_processes_treeview(builder);

    // 6) Mostrar la ventana
    gtk_window_present(window);
    g_object_unref(builder);
}

/* -------------------------------- main -------------------------------- */
int main (int argc, char *argv[])
{
    GtkApplication *app =
        gtk_application_new("org.matcom.guard", G_APPLICATION_DEFAULT_FLAGS);

    g_signal_connect(app, "activate", G_CALLBACK(on_activate), NULL);

    int status = g_application_run(G_APPLICATION(app), argc, argv);

    // Limpiar monitor al salir
    monitor_cleanup();
    g_object_unref(app);
    return status;
}
