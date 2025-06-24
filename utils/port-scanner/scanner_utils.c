#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <ctype.h>

#include "models.h"


#define HOST "127.0.0.1"


static const BannerExpectation expectations[] = {
    { 21,   "220"        },  // FTP
    { 22,   "SSH-"       },  // SSH
    { 23,   "login:"     },  // Telnet 
    { 25,   "220"        },  // SMTP
    { 80,   ""           },  // HTTP usually opened in Ubuntu
    {110,   "+OK"        },  // POP3

    {143,   "* OK"       },  // IMAP
    {119,   "200"        },  // NNTP
    {513,   "login:"     },  // rlogin
    {514,   "shell"      },  // rsh
    {631,   ""           },  // CUPS, manage printers (usually opened in Ubuntu)
    {1521,  "TNS-"       },  // Oracle TNS Listener
    {5432,  ""           },  // PostgreSQL (usually opened in Ubuntu)
};

//Set global variable for total number of expectations
static const int num_expectations = sizeof(expectations) / sizeof(expectations[0]);


// Change an string to lowercase (maximum len bytes, ensure '\0')
static void to_lowercase(char *dst, const char *src, size_t len) {
    size_t i;
    for (i = 0; i < len && src[i] != '\0'; i++) {
        dst[i] = tolower((unsigned char)src[i]);
    }
    dst[i] = '\0';
}

int connect_to_port(int port) {
    int sock;
    struct sockaddr_in target;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }

    // set timeout for connect
    struct timeval timeout = {2, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    inet_pton(AF_INET, HOST, &target.sin_addr);

    int result = connect(sock, (struct sockaddr*) &target, sizeof(target));
    if (result < 0) {
        close(sock);
        return -1;
    }

    return sock;
}

void close_socket(int sockfd) {
    close(sockfd);
}


int is_banner_known(int port) {

    for (int i = 0; i < num_expectations; i++) {
        if (expectations[i].port == port)
            return 1;
    }
    return 0;
   
}

int is_malicious(int port) {
    int bad_ports[] = {
        3127, //Abierto por el gusano MyDoom para permitir el acceso remoto al sistema infectado
        4444, //Conocido por ser utilizado por el troyano Metasploit (Meterpreter)
        6000 //Este puerto es peligroso si está expuesto en una red pública o mal configurado, especialmente en servidores Linux o Unix
    };
    int n = sizeof(bad_ports) / sizeof(bad_ports[0]);
    for(int i = 0; i < n; i++) {
        if (port == bad_ports[i]) {
            return 1;
        }
    }
    return 0;
}

int classify(int port) {
    if (is_malicious(port)) return -1;
    else if (is_banner_known(port)) return 1;
    return 0;
}

//Returns the expected word in banner of port port
const char *get_expected_banner(int port) {
    for (int i = 0; i < num_expectations; i++) {
        if (expectations[i].port == port)
            return expectations[i].expected;
    }
    return NULL;
}


//Check if original banner contains the expected word
int is_expected_banner(int port, const char *banner) {
    const char *exp = get_expected_banner(port);
    if (!exp) return 1; //if exp == "" is because this port usually doesn't have a banner
    if (!banner) return 0;

    static char lower_banner[512];
    static char lower_exp[64];

    to_lowercase(lower_banner, banner, sizeof(lower_banner)-1);
    to_lowercase(lower_exp, exp, sizeof(lower_exp)-1);

    return (strstr(lower_banner, lower_exp) != NULL);
}


int grab_banner(int sockfd, char *buffer, int buffer_size) {
    int n = recv(sockfd, buffer, buffer_size, 0);
    if (n <= 0) {
        return -1;
    }
    buffer[n] = '\0'; //indicates end of string
    return n;
} 


const char *search_dangerous_words(const char *banner, int n) {
    if (n <= 0) return NULL; //no banner

    const char *danger_words[] = {
        "meterpreter", "netbus", "back orifice", "sub7", 
        "cobalt strike",
        "empire", "pupy", "quasar rat"
    };
    int num_words = sizeof(danger_words) / sizeof(danger_words[0]);

    static char lower_banner[256];
    to_lowercase(lower_banner, banner, sizeof(lower_banner) - 1);

    for (int i = 0; i < num_words; i++) {
        if (strstr(lower_banner, danger_words[i]) != NULL) {
            return danger_words[i];
        }
    }
    return NULL;
}


