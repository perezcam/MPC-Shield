#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>


#define HOST "127.0.0.1"
#define BANNER_TIMEOUT_SEC 2


int connect_to_port(int port) {
    int sock;
    struct sockaddr_in target;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        //TODO: implementar manejo de errores quiza 
        return -1;
    }

    // set a small timeout for connect
    struct timeval timeout = {BANNER_TIMEOUT_SEC, 0};
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


// const char* get_service_name(int port) {
//     switch (port) {
//         case 22: return "SSH";
//         case 80: return "HTTP";
//         case 443: return "HTTPS";
//         case 21: return "FTP";
//         case 25: return "SMTP";
//         case 3306: return "MySQL";
//         case 631: return "IPP";
//         default: return "Desconocido";
//     }
// }


int is_known(int port) {
    if (is_malicious(port)) return -1;
    else if (is_banner_known(port)) return 1;
    return 0;
}

int is_banner_known(int port) {
    int banner_ports[] = {
        //TODO: Revisar bien esta info
        //TODO: Modificar para aceptar tambien banners que hay que enviarles algo primero con send() como http?
        //TODO: Convertirlo en una tabla que tire contra identificacion del banner
        21,    // FTP (responde con "220 Service ready")
        22,    // SSH (responde con "SSH-2.0-...")
        23,    // Telnet (algunas implementaciones envían banner)
        25,    // SMTP ("220 mail.example.com ESMTP Postfix")
        110,   // POP3 ("+OK POP3 server ready")
        143,   // IMAP ("* OK IMAP4 ready")
        220,   // IMAP v3 (algunas variantes)
        119,   // NNTP (Network News Transfer Protocol)
        6667,  // IRC ("NOTICE AUTH" o similar, si está activo)
        513,   // rlogin
        514,   // rsh
        1521,  // Oracle TNS Listener ("TNS-...")
        3306,  // MySQL (banner binario, pero identificable)
        5432,  // PostgreSQL (protocolo binario, pero conexión inicial se puede analizar)
        27017  // MongoDB (algunas implementaciones emiten handshake)
    };

    int n = sizeof(banner_ports) / sizeof(banner_ports[0]);
    for (int i = 0; i < n; i++) {
        if (port == banner_ports[i]) {
            return 1;
        }
    }

    return 0;
}


int is_malicious(int port) {
    int bad_ports[] = {
        31337, 12345, 6667, 4444, 10101, 31335, 20034,
        27444, 27665, 6000
    };
    int n = sizeof(bad_ports) / sizeof(bad_ports[0]);
    for(int i = 0; i < n; i++) {
        if (port == bad_ports[i]) {
            return 1;
        }
    }
    return 0;
}



//TODO: Modularizar

typedef struct {
    int port;
    const char *expected;
} BannerExpectation;


//TODO: MEJORAR ESTO
static const BannerExpectation expectations[] = {
    { 21,   "220"        },  // FTP
    { 22,   "SSH-"       },  // SSH
    { 23,   "login:"     },  // Telnet (muchas implementaciones)
    { 25,   "220"        },  // SMTP
    { 80,   "HTTP/"      },  // HTTP (tras HEAD/GET)
    {110,   "+OK"        },  // POP3
    {143,   "* OK"       },  // IMAP
    {119,   "200"        },  // NNTP
    {513,   "login:"     },  // rlogin
    {514,   "shell"      },  // rsh (a veces)
    {1521,  "TNS-"       },  // Oracle TNS Listener
    {6667,  "NOTICE AUTH"},  // IRC
    // …añade más si quieres
};
static const int num_expectations = sizeof(expectations) / sizeof(expectations[0]);


const char *get_expected_banner(int port) {
    for (int i = 0; i < num_expectations; i++) {
        if (expectations[i].port == port)
            return expectations[i].expected;
    }
    return NULL;
}

int is_expected_banner(int port, const char *banner) {
    const char *exp = get_expected_banner(port);
    if (!exp || !banner) return 0;
    // strcasestr busca substring ignorando mayúsculas/minúsculas
    //TODO: esto no se puede usar en search dangerous words?
    return (strcasestr(banner, exp) != NULL);
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

    // List of dangerous words
    const char *danger_words[] = {
        "backdoor", "shell", "nc", "netcat", "bindshell", "reverseshell",
        "meterpreter", "r00t", "owned", "h4x0r", "hacked", "pwnd",
        "exploit", "trojan", "rat", "malware", "command shell", "listener"
    };
    int num_words = sizeof(danger_words) / sizeof(danger_words[0]);

    // Banner to lowercase
    static char lower_banner[256];
    for (size_t i = 0; i < n; i++) {
        lower_banner[i] = tolower((unsigned char)banner[i]);
    }
    lower_banner[n] = '\0';

    // Look for coincidences
    for (int i = 0; i < num_words; i++) {
        if (strstr(lower_banner, danger_words[i]) != NULL) {
            return danger_words[i]; 
        }
    }

    return NULL; //
}


