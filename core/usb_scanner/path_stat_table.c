#include <sys/stat.h>
#include <limits.h>
#include <string.h>
#include <pthread.h>
#include "shared.h"

/**
 * pst_init(tbl)
 *   Inicializa la tabla (marca todas las entradas como libres).
 */
static void pst_init(path_stat_table_t *tbl) {
    tbl->count = 0;
    for (int i = 0; i < MAX_ENTRIES; i++) {
        tbl->entries[i].in_use = 0;
    }
}

/**
 * pst_find_index(tbl, path)
 *   Busca el índice de la entrada cuyo campo path coincida con 'path'.
 *   Retorna el índice [0..MAX_ENTRIES-1] si existe, o -1 si no está.
 */
static int pst_find_index(path_stat_table_t *tbl, const char *path) {
    for (int i = 0; i < MAX_ENTRIES; i++) {
        if (tbl->entries[i].in_use &&
            strcmp(tbl->entries[i].path, path) == 0) {
            return i;
        }
    }
    return -1;
}

/**
 * pst_update(tbl, path, st)
 *   Inserta o actualiza la entrada (path → *st). Si 'path' ya existía,
 *   sobrescribe el struct stat; si no, lo crea en una ranura libre.
 *   Retorna 0 en éxito, -1 si no hay espacio libre.
 */
static int pst_update(path_stat_table_t *tbl,
                      const char *path,
                      const struct stat *st)
{
    pthread_mutex_lock(&path_table_mutex);

    // 1) ¿Ya existe?
    int idx = pst_find_index(tbl, path);
    if (idx >= 0) {
        // Actualizamos solo el stat
        tbl->entries[idx].st = *st;
        pthread_mutex_unlock(&path_table_mutex);
        return 0;
    }

    // 2) Si no existía, buscamos una ranura libre
    if (tbl->count >= MAX_ENTRIES) {
        pthread_mutex_unlock(&path_table_mutex);
        return -1;  // tabla llena
    }
    for (int i = 0; i < MAX_ENTRIES; i++) {
        if (!tbl->entries[i].in_use) {
            // Usamos esta ranura
            strncpy(tbl->entries[i].path, path, PATH_MAX - 1);
            tbl->entries[i].path[PATH_MAX - 1] = '\0';
            tbl->entries[i].st = *st;
            tbl->entries[i].in_use = 1;
            tbl->count++;
            pthread_mutex_unlock(&path_table_mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&path_table_mutex);
    return -1;  // no debería llegar aquí si count < MAX_ENTRIES
}

/**
 * pst_remove(tbl, path)
 *   Elimina la entrada asociada a 'path', si existe.
 *   Retorna 0 si se borró o no existía, -1 en error interno.
 */
static int pst_remove(path_stat_table_t *tbl, const char *path) {
    pthread_mutex_lock(&path_table_mutex);

    int idx = pst_find_index(tbl, path);
    if (idx < 0) {
        pthread_mutex_unlock(&path_table_mutex);
        return 0;  // no existía, nada que hacer
    }

    tbl->entries[idx].in_use = 0;
    tbl->entries[idx].path[0] = '\0';  // opcional: limpiar cadena
    tbl->count--;

    pthread_mutex_unlock(&path_table_mutex);
    
    return 0;
}

/**
 * pst_lookup(tbl, path)
 *   Retorna puntero al struct stat asociado a 'path', o NULL si no existe.
 *   El puntero permanece válido hasta la siguiente inserción/borrado.
 */
static int pst_lookup(path_stat_table_t *tbl, const char *path,struct stat *out) {
    pthread_mutex_lock(&path_table_mutex);

    int idx = pst_find_index(tbl, path);
    if (idx < 0) {
        pthread_mutex_unlock(&path_table_mutex);
        return -1;
    }

    *out = tbl->entries[idx].st;
    pthread_mutex_unlock(&path_table_mutex);
    return 0;
}

