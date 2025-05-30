#include <stdio.h>
#include <stdlib.h>


#include "scanner.h"
#include "models.h"

int main(void) {
    ScanResult res = scan_ports();

    for (int i = 0; i < res.size; i++) {
        ScanOutput *output = &res.data[i];
        printf("Puerto: %d | Clasif: %d | Banner: %s | Secure: %d | Palabra: %s\n",
               output->port, output->classification, output->banner, output->security_level, output->dangerous_word);
        free((void*)output->banner);
        free((void*)output->dangerous_word);
    }
    free(res.data);

    return 0;
}