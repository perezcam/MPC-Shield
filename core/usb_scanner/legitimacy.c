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

int sha256_file(const char *path, unsigned char out[SHA256_DIGEST_LENGTH]) {
    unsigned char buf[8192];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0)
        SHA256_Update(&ctx, buf, n);
    close(fd);

    if (n < 0) return -1;  /* error durante la lectura */

    SHA256_Final(out, &ctx);
    return 0;
}
