#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

// Compile with: gcc -o usb_tester usb_tester.c
// Run with sudo ./usb_tester

// Path
const char *base_path = "/media/camilo-perez/Camilo";


die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}


// 1. Make dir test_dir
void crear_directorio() {
    char dirpath[512];
    snprintf(dirpath, sizeof(dirpath), "%s/test_dir", base_path);
    if (mkdir(dirpath, 0755) == -1 && errno != EEXIST) die("mkdir");
    printf("Directorio creado: %s\n", dirpath);
}

// 2.Create file. test_file.txt
void crear_archivo() {
    sleep(5);
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s/test_file.txt", base_path);
    int fd = open(filepath, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd == -1) die("open");
    const char *texto = "Primera línea de prueba\n";
    if (write(fd, texto, strlen(texto)) == -1) die("write");
    close(fd);
    printf("Archivo creado: %s\n", filepath);
}

// 3.Modify file test_file.txt
void modificar_archivo() {
    sleep(5);
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s/test_file.txt", base_path);
    int fd = open(filepath, O_WRONLY | O_APPEND);
    if (fd == -1) die("open para modificar");
    const char *texto2 = "Línea añadida para test de modificación\n";
    if (write(fd, texto2, strlen(texto2)) == -1) die("write modificación");
    close(fd);
    printf("Archivo modificado: %s\n", filepath);
}

// 4. Duplicate file test_file.txt
void duplicar_archivo() {
    sleep(5);
    char src[512], dst[512];
    snprintf(src, sizeof(src), "%s/test_file.txt", base_path);
    snprintf(dst, sizeof(dst), "%s/test_file_copy.txt", base_path);
    int fd_src = open(src, O_RDONLY);
    if (fd_src == -1) die("open src");
    int fd_dst = open(dst, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd_dst == -1) die("open dst");
    char buf[1024];
    ssize_t n;
    while ((n = read(fd_src, buf, sizeof(buf))) > 0) {
        if (write(fd_dst, buf, n) == -1) die("write copy");
    }
    if (n == -1) die("read src");
    close(fd_src);
    close(fd_dst);
    printf("Archivo duplicado: %s -> %s\n", src, dst);
}

// 5. Change permissions of the copy to 777
void cambiar_permisos() {
    sleep(5);
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s/test_file_copy.txt", base_path);
    if (chmod(filepath, 0777) == -1) die("chmod");
    printf("Permisos cambiados a 777: %s\n", filepath);
}

// 6. Delete original file test_file.txt
void eliminar_archivo() {
    sleep(5);
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s/test_file.txt", base_path);
    if (unlink(filepath) == -1) die("unlink");
    printf("Archivo original eliminado: %s\n", filepath);
}

int main() {
    crear_directorio();
    crear_archivo();
    modificar_archivo();
    duplicar_archivo();
    cambiar_permisos();
    eliminar_archivo();

    printf("Todas las operaciones completadas.\n");
    return 0;
}
