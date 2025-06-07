#ifndef MODELS_H
#define MODELS_H

typedef struct {
    int port;
    const char *classification; // suspicious, unknown, service associated
    const char *banner;
    const char * security_level; // ok, warning, critical
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
