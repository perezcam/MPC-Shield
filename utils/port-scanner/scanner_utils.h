#ifndef SCANNER_UTILS_H
#define SCANNER_UTILS_H

// Try connection to the port, return 1 if open, 0 if not open and -1 if there is and error with the socket creation
int connect_to_port(int port);                

// Return common service name
const char* get_service_name(int port);       

#endif
