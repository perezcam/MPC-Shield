#include "test_scanner_utils.h"
#include <unistd.h>
#include <stdio.h>      
#include <stdlib.h>     
#include <unistd.h>    
#include <sys/wait.h>   



#define NUM_PORTS 7

int main() {
    int ports[NUM_PORTS] = {21, 22, 4, 5, 443, 25, 4444};
    int sockets[NUM_PORTS];

    for (int i = 0; i < NUM_PORTS; i++) {
        sockets[i] = open_fake_port(ports[i]);
        if (sockets[i] == -1) {
            //TODO: ERROR HANDLING
            printf("Error al abrir el puerto %d\n", ports[i]);
            
            return -1;
        }

        pid_t pid = fork();
        if (pid < 0) {
            //TODO: Error handling
            perror("fork");
            continue;
        } else if (pid == 0) {
            //Banner server
            int client = send_banner(sockets[i], ports[i]);
            if (client < 0) {
                //TODO: error creando el cliente
            } 

            exit(0);  
        }
    }

    sleep(1); // wait for the ports to be open
    printf("Ejecutando escáner de puertos...\n");

    int pipefd[2];
    pipe(pipefd);


    int pid = fork();

    if (pid < 0) {
        //TODO: Error handling
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO); // Redirect stdout of the process to pipe
        close(pipefd[1]); 
        execl("bin/port-scanner", "port-scanner", (char *)NULL);

        //TODO: Error handling
        perror("execl");
        exit(1);        
    }

    close(pipefd[1]); 
    char output[4096];
    read(pipefd[0], output, sizeof(output));
    close(pipefd[0]);
    wait(NULL);


    printf("Salida del escáner:\n%s\n", output);

    printf("Cerrando sockets...\n");
    for (int i = 0; i < NUM_PORTS; i++) {
        close(sockets[i]);
    }

    return 0;
}