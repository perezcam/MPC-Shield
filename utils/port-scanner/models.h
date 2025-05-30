#ifndef MODELS_H
#define MODELS_H

typedef struct {
    int port;
    int classification; // -1: suspicious, 0: unknown, 1: service associated
    const char *banner;
    int security_level; // 0: secure, 1: warning, 2: critical
    const char *dangerous_word;
} ScanOutput;

typedef struct {
    ScanOutput *data;
    int size;
} ScanResult;

typedef struct {
    int port;
    const char *expected;
} BannerExpectation;


#endif // MODELS_H
