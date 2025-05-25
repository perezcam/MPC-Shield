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
 * Maps common ports to service names.
 */
const char* get_service_name(int port);

#endif // SCANNER_UTILS_H
