#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include "test_scanner_utils.h"


int open_fake_port(int port) {
    int sock;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        close(sock);
        return -1;
    }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    target.sin_addr.s_addr = INADDR_ANY; //Listen on all interfaces
    
    if (bind(sock, (struct sockaddr*)&target, sizeof(target)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }

    if (listen(sock, 1) < 0) {
        perror("listen");
        close(sock);
        return -1;
    }

    return sock;

}

int send_banner(int sockfd, int port) {
    int client = accept(sockfd, NULL, NULL);
    if (client < 0) return -1;
   
    const char *banner = get_banner(port);
    send(client, banner, strlen(banner), 0);
    close(client);
    return 0;
     
}

const char* get_banner(int port) {
    switch (port) {
        case 22: return "SSH";
        case 80: return "HTTP";
        case 443: return "HTTPS";
        case 21: return "FTP";
        case 25: return "SMTP 220";
        case 631: return "IPP";
        case 4444: return "backdoor ";
        default: return "FAKE-SERVICE-BANNER";
    }
}