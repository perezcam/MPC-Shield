#include "shared.h"
#include <pthread.h>
#include <string.h>



static EventInfo queue[QUEUE_SIZE];
static int head = 0;
static int tail = 0;

/* Mutex para proteger acceso concurrente a cabeza/cola */
static pthread_mutex_t qlock = PTHREAD_MUTEX_INITIALIZER;
/* Condición para notificar a pop_event que hay un elemento disponible */
static pthread_cond_t qcond = PTHREAD_COND_INITIALIZER;

/*
 * push_event:
 *   Mete “ev” en la cola. 
 *   Si la cola está llena (tail+1 == head), simplemente sobreescribimos el elemento más antiguo
 *   o bien podemos esperar hasta que el consumidor avance. En este ejemplo optamos por sobreescribir:
 */
void push_event(EventInfo ev) {
    pthread_mutex_lock(&qlock);

    int siguiente = (tail + 1) % QUEUE_SIZE;
    if (siguiente == head) {
        // La cola está llena. Podríamos:
        //  a) Esperar a que pop_event saque elementos, o
        //  b) Sobreescribir el más antiguo (head). 
        // Aquí elegimos sobreescribir: avanzamos head para descartar el evento más viejo.
        head = (head + 1) % QUEUE_SIZE;
    }

    // Copiamos el EventInfo entero en la posición “tail”
    queue[tail] = ev;
    tail = siguiente;

    // Avisamos a cualquier pop_event() que esté bloqueado
    pthread_cond_signal(&qcond);
    pthread_mutex_unlock(&qlock);
}

/*
 * pop_event:
 *   Espera hasta que haya un EventInfo en la cola, lo saca y lo devuelve en *ev.
 *   Siempre retorna 0 (podrías cambiarlo para devolver -1 en caso de error).
 */
void pop_event(EventInfo *ev) {
    pthread_mutex_lock(&qlock);

    // Mientras no haya elementos (head == tail), esperar
    while (head == tail) {
        pthread_cond_wait(&qcond, &qlock);
    }

    // Sacar el elemento en “head” y avanzar head
    *ev = queue[head];
    head = (head + 1) % QUEUE_SIZE;

    pthread_mutex_unlock(&qlock);
}
