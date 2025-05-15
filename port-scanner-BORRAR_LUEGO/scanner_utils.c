#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>


#define HOST "127.0.0.1"


int connect_to_port(int port) {
    int sock;
    struct sockaddr_in target;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        //TODO: implementar manejo de errores quiza 
        return -1;
    }

    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    inet_pton(AF_INET, HOST, &target.sin_addr);

    int result = connect(sock, (struct sockaddr*) &target, sizeof(target));
    close(sock);
    return result == 0;
}




const char* get_service_name(int port) {
    switch (port) {
        case 22: return "SSH";
        case 80: return "HTTP";
        case 443: return "HTTPS";
        case 21: return "FTP";
        case 25: return "SMTP";
        case 3306: return "MySQL";
        case 631: return "IPP";
        default: return "Desconocido";
    }
}