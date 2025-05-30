#ifndef SCANNER_UTILS_H
#define SCANNER_UTILS_H

// ———— Connection & Socket Management ————
/**
 * Opens a TCP socket to localhost:port with a timeout of 2 sec.
 * @param port Destination port.
 * @return Socket descriptor >= 0 on success, or -1 on error.
 */
int  connect_to_port(int port);

/**
 * Closes the given socket descriptor.
 * @param sockfd Socket descriptor to close.
 */
void close_socket(int sockfd);

// ———— Port Classification ————
/**
 * Classifies a port:
 *   - returns -1 if it’s malicious,
 *   -  1 if it’s a known-banner port,
 *   -  0 otherwise.
 */
int classify(int port);

/** Returns 1 if the port should emit a recognizable banner. */
int is_banner_known(int port);

/** Returns 1 if the port is in the “malicious” list. */
int is_malicious(int port);

// ———— Banner Handling ————
/**
 * Reads up to buffer_size bytes from sockfd into buffer and null-terminates it.
 * @param sockfd       Connected socket descriptor.
 * @param buffer       Destination buffer for the banner.
 * @param buffer_size  Max bytes to read.
 * @return Number of bytes read (>0), or -1 on error/timeout.
 */
int grab_banner(int sockfd, char *buffer, int buffer_size);

/**
 * Searches for dangerous words in banner[0..n-1].
 * @param banner Banner text (not necessarily null-terminated beyond n).
 * @param n      Length of valid data in banner.
 * @return Pointer to the first matched danger word, or NULL if none found.
 */
const char *search_dangerous_words(const char *banner, int n);

/**
 * Returns the expected banner substring for a given port, or NULL if undefined.
 */
const char *get_expected_banner(int port);

/**
 * Case-insensitive check whether banner contains the expected substring.
 * @param port   Port being checked.
 * @param banner Null-terminated banner string.
 * @return 1 if match found, 0 otherwise.
 */
int is_expected_banner(int port, const char *banner);

#endif /* SCANNER_UTILS_H */
