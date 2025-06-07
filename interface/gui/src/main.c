#include <gtk/gtk.h>

static void
on_activate (GtkApplication *app, gpointer data)
{
    // 1. Crea un GtkBuilder y carga el XML
    GtkBuilder *builder = gtk_builder_new_from_file ("ui/main_window.ui");

    // 2. Obtiene la ventana por su 'id' en el XML
    GtkWindow  *window  = GTK_WINDOW (
                            gtk_builder_get_object (builder, "main_window")
                          );

    // 3. Asocia la ventana a la aplicación
    gtk_window_set_application (window, app);

    // 4. Muestra la ventana de forma correcta
    gtk_window_present (window);

    // 5. Libera el GtkBuilder (ya no se necesita)
    g_object_unref (builder);
}

int
main (int argc, char *argv[])
{
    // 6. Crea la instancia GtkApplication
    GtkApplication *app =
        gtk_application_new ("org.matcom.guard", G_APPLICATION_FLAGS_NONE);

    // 7. Conecta la señal 'activate' que dispara on_activate()
    g_signal_connect (app, "activate", G_CALLBACK (on_activate), NULL);

    // 8. Ejecuta la aplicación (main loop) y obtiene el código de salida
    int status = g_application_run (G_APPLICATION (app), argc, argv);

    // 9. Libera la referencia a 'app'
    g_object_unref (app);
    return status;
}