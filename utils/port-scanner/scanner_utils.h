#ifndef SCANNER_UTILS_H
#define SCANNER_UTILS_H


/**
 * Try connections to the ports using socket
 * Returns the sockfd if connected, else -1
 */
int connect_to_port(int port);

void close_socket(int sockfd);

/**
 * Attempts to read a banner from an open socket.
 * sockfd must be a valid, connected TCP socket.
 * buffer should be at least `len + 1` in size.
 * Returns number of bytes read, or -1 on error/timeout.
 */
int grab_banner(int sockfd, char *buffer, int len);

/**
 * Returns -1 if is a malicious known port
 * Returns 1 if is a banner known port
 * Returns 0 if is an unknown port
 */
int is_known(int port);


/**
 * Returns 1 if is known as a malicious port
 * Else return 0
 */
int is_malicious(int port);

/**
 * Returns 1 if port is known for a service with identifiable banner
 * Else return 0
 */
int is_banner_known(int port);


/**
 * Receives string banner and n (size of banner)
 * Returns dangerous word if banner contains it else NULL
 */
const char *search_dangerous_words(const char *banner, int n);

#endif // SCANNER_UTILS_H
