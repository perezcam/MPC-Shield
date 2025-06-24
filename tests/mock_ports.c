/* mock_ports.c  —  gcc mock_ports.c -pthread -o mock_ports  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define MAX_BACKLOG 1         /* connections in queue */

typedef struct {
    int         port;
    const char *banner;             
} PortInfo;

static PortInfo ports[] = {
    {3127, "malicious port example\r\n"}, //example with a malicious port
    {23, "serv associated example with unrecognizable banner\r\n"},
    {514, "shell: recongnizable banner\r\n"},
    {15, "netbus example with a dangerous word\r\n"},
    {16, "example of a simple unknown port\r\n"},
};
static const size_t N_PORTS = sizeof ports / sizeof ports[0];

/* ---- Hilo que atiende SIEMPRE un único puerto ---- */
static void *serve_port(void *arg)
{
    const PortInfo *p = (PortInfo *)arg;

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); pthread_exit(NULL); }

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons(p->port);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(srv); pthread_exit(NULL);
    }
    if (listen(srv, MAX_BACKLOG) < 0) {
        perror("listen"); close(srv); pthread_exit(NULL);
    }

    printf("[+] Listening on %d — banner: %s", p->port, p->banner);

    while(1) {
        int cli = accept(srv, NULL, NULL);
        if (cli < 0) { perror("accept"); continue; }

        printf("[+] Connection accepted on %d\n", p->port);
        send(cli, p->banner, strlen(p->banner), MSG_NOSIGNAL); //MSG_NOSIGNAL: avoid SIGPIPE if the client closed the connection before receiving


        close(cli);
    }
    /* never reaches this part*/
    return NULL;
}

/* ------------------- main -------------------- */
int main(void)
{
    pthread_t tid[N_PORTS];

    for (size_t i = 0; i < N_PORTS; ++i)
        if (pthread_create(&tid[i], NULL, serve_port, &ports[i]) != 0) {
            perror("pthread_create"); exit(EXIT_FAILURE);
        }

    while (1) {
        pause();
    }             /* main thread waiting */
}
