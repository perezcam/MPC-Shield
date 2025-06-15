#ifndef LEGITIMACY_H
#define LEGITIMACY_H

#include <openssl/sha.h>

/**
 * Comprueba si el ejecutable está en una ruta de sistema “de confianza”.
 * Devuelve 1 si es legítimo, 0 si no.
 */
int is_legit(const char *exe_path);

/**
 * Comprueba si el hash SHA256 coincide con alguna firma
 * de malware conocido.
 * Devuelve 1 si es malware, 0 si no.
 */
int is_known_malware(const unsigned char digest[SHA256_DIGEST_LENGTH]);

/**
 * Calcula el SHA256 de un fichero dado su path.
 * Escribe el digest en out (tamaño SHA256_DIGEST_LENGTH).
 * Devuelve 0 en éxito, -1 en error.
 */
int sha256_file(const char *path, unsigned char out[SHA256_DIGEST_LENGTH]);

#endif
