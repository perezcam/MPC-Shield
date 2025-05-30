#ifndef TEST_SCANNER_UTILS_H
#define TEST_SCANNER_UTILS_H



// Open a fake port to test the scanner, return the socket descriptor or -1 if there is an error    
int open_fake_port(int port);       

/** 
 * Abre el socket que ya tienes en escucha (`sockfd`) y acepta una única conexión,
 * luego envía un banner según `port`.
 * Returns 0 if success else -1.
 */
int send_banner(int sockfd, int port);

/**
 * Maps common ports to banners.
 */
const char* get_banner(int port);

#endif // TEST_SCANNER_UTILS_H