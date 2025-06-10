#include <gtk/gtk.h>
#include "scanner.h"  // tu header de core

// Definición de índices para las 5 columnas
enum {
    COL_PORT,            // port (int)
    COL_CLASS,           // classification (string)
    COL_BANNER,          // banner (string)
    COL_DANGEROUS_WORD,  // dangerous_word (string)
    COL_SECURITY_LEVEL,  // security_level (string)
    N_COLUMNS
};

// update_ports: vacía y repuebla el modelo con datos de ScanResult
static gboolean update_ports (gpointer user_data)
{
    GtkListStore *store = GTK_LIST_STORE(user_data);
    gtk_list_store_clear(store);

    // 1) Invocar al core
    ScanResult res = scan_ports();

    // 2) Recorrer datos y añadir filas
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

    // 3) Liberar la memoria del core
    free_result(&res);

    // Seguir ejecutando cada 5s
    return G_SOURCE_CONTINUE;
}


static void prepare_ports_treeview(GtkBuilder *builder) {

    // 3. Recuperar el TreeView de puertos
    GtkTreeView *tv_ports = GTK_TREE_VIEW(gtk_builder_get_object(builder, "tree_ports"));


    // 4. Crear el ListStore con todos los tipos de columna
    GtkListStore *store_ports = gtk_list_store_new(
        N_COLUMNS,
        G_TYPE_INT,    // COL_PORT
        G_TYPE_STRING, // COL_CLASS
        G_TYPE_STRING, // COL_BANNER
        G_TYPE_STRING, // COL_DANGEROUS_WORD
        G_TYPE_STRING  // COL_SECURITY_LEVEL
    );


    // 5. Insertar cada columna visual en el TreeView
    const char *titles[N_COLUMNS] = {
        "Puerto",
        "Clasificación",
        "Banner",
        "Palabra Peligrosa",
        "Nivel Seguridad"
    };

    // Bucle que inserta dinámicamente cada columna en el TreeView
    for (int i = 0; i < N_COLUMNS; i++) {
        GtkCellRenderer *renderer = gtk_cell_renderer_text_new();
        gtk_tree_view_insert_column_with_attributes(
            tv_ports,       // 1. El TreeView al que añadimos la columna
            -1,             // 2. Índice donde insertarla (-1 = al final)
            titles[i],      // 3. Texto que aparecerá en el encabezado
            renderer,       // 4. “Renderizador” que dibuja las celdas
            "text", i,      // 5. Mapeo: propiedad “text” del renderer ← columna i del modelo
            NULL            // 6. Fin de lista de pares propiedad→columna
        );
    }


    // 6. Asignar el modelo al TreeView
    gtk_tree_view_set_model(tv_ports, GTK_TREE_MODEL(store_ports));



    // 7. Llamar a update_ports() ahora y cada 5 segundos
    update_ports(store_ports);
    g_timeout_add_seconds(5, update_ports, store_ports);

}


static void on_activate (GtkApplication *app, gpointer data)
{
    // 1. Cargar la UI
    GtkBuilder *builder = gtk_builder_new_from_file("ui/main_window.ui");
    GtkWindow  *window  = GTK_WINDOW(
        gtk_builder_get_object(builder, "main_window"));

    // 2. Asociar la ventana a la aplicación
    gtk_window_set_application(window, app);


    //Recuperar el TreeView de puertos
    prepare_ports_treeview(builder);
    
    //TODO: Aqui estarian las otras funciones que preparan las demas cosas 
    //prepare_devices_treeview() y prepare_processes_treeview()


    // 8. Mostrar la ventana
    gtk_window_present(window);
    g_object_unref(builder);
}

int main (int argc, char *argv[])
{
    // Crear la aplicación GTK
    GtkApplication *app =
        gtk_application_new("org.matcom.guard", G_APPLICATION_FLAGS_NONE);

    // Conectar activate → on_activate
    g_signal_connect(app, "activate", G_CALLBACK(on_activate), NULL);

    // Ejecutar el bucle principal
    int status = g_application_run(G_APPLICATION(app), argc, argv);

    // Liberar la referencia y salir
    g_object_unref(app);
    return status;
}
