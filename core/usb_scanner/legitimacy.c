#include "legitimacy.h"
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdio.h>
#include <openssl/sha.h>

/* --- Whitelist de rutas “seguras” --- */
static const char *whitelist_dirs[] = {
    "/bin/",
    "/usr/bin/",
    "/sbin/",
    "/usr/sbin/",
    NULL
};

int is_legit(const char *exe_path) {
    for (int i = 0; whitelist_dirs[i]; i++) {
        size_t len = strlen(whitelist_dirs[i]);
        if (strncmp(exe_path, whitelist_dirs[i], len) == 0)
            return 1;
    }
    return 0;
}

/* --- Lista de hashes de malware conocido --- */
static const unsigned char KNOWN_MALWARE[][SHA256_DIGEST_LENGTH] = {
    /* Zeus     */ {0x12, 0x34, /* ...resto del hash... */},
    /* WannaCry */ {0xab, 0xcd, /* ...resto del hash... */}
};
static const size_t N_MALWARE = sizeof(KNOWN_MALWARE)/SHA256_DIGEST_LENGTH;

int is_known_malware(const unsigned char digest[SHA256_DIGEST_LENGTH]) {
    for (size_t i = 0; i < N_MALWARE; i++) {
        if (memcmp(digest,
                   KNOWN_MALWARE[i],
                   SHA256_DIGEST_LENGTH) == 0)
            return 1;
    }
    return 0;
}


