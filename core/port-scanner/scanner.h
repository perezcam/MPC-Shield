#ifndef SCANNER_H
#define SCANNER_H

// Include model that define ScanResult and ScanOutput
#include "models.h"

/**
 * Initiate the scanner and returns and ScanResult
 */
ScanResult scan_ports(void);

/**
 * Free memory allocated for ScanResult
 */
void       free_result (ScanResult *res);

#endif // SCANNER_H
