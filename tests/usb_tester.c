#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <errno.h>

// gcc -o usb_tester usb_tester.c


const char *base_path = "/home/mauricio-mh/workspace/MPC-Shield/tests/usb_mocked";

void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int main() {
    pid_t pid;
    int status;

    // Hijo 1: Crear carpeta test_dir
    pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
        char dirpath[512];
        snprintf(dirpath, sizeof(dirpath), "%s/test_dir", base_path);
        if (mkdir(dirpath, 0755) == -1 && errno != EEXIST) {
            die("mkdir");
        }
        printf("[Hijo 1] Directorio creado: %s\n", dirpath);
        exit(EXIT_SUCCESS);
    }

    // Hijo 2: Crear archivo test_file.txt
    pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
        sleep(1);
        char filepath[512];
        snprintf(filepath, sizeof(filepath), "%s/test_file.txt", base_path);
        int fd = open(filepath, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd == -1) die("open");
        const char *texto = "Primera línea de prueba\n";
        if (write(fd, texto, strlen(texto)) == -1) die("write");
        close(fd);
        printf("[Hijo 2] Archivo creado: %s\n", filepath);
        exit(EXIT_SUCCESS);
    }

    // Hijo 3: Modificar archivo
    pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
        sleep(10);
        char filepath[512];
        snprintf(filepath, sizeof(filepath), "%s/test_file.txt", base_path);
        int fd = open(filepath, O_WRONLY | O_APPEND);
        if (fd == -1) die("open para modificar");
        const char *texto2 = "Línea añadida para test de modificación\n";
        if (write(fd, texto2, strlen(texto2)) == -1) die("write modificación");
        close(fd);
        printf("[Hijo 3] Archivo modificado: %s\n", filepath);
        exit(EXIT_SUCCESS);
    }

    // Hijo 4: Eliminar archivo
    pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
        sleep(20);
        char filepath[512];
        snprintf(filepath, sizeof(filepath), "%s/test_file.txt", base_path);
        if (unlink(filepath) == -1) die("unlink");
        printf("[Hijo 4] Archivo eliminado: %s\n", filepath);
        exit(EXIT_SUCCESS);
    }

    while (1) {
        if (wait(&status) <= 0) break;
    }
        

    printf("Todas las operaciones completadas.\n");
    return EXIT_SUCCESS;
}
