// event_queue.c
#define _GNU_SOURCE

#include "shared.h"
#include <pthread.h>
#include <stdlib.h>

/* Tamaño máximo de la cola */
#ifndef QUEUE_SIZE
#define QUEUE_SIZE 1024
#endif

/* Cola circular de eventos */
static EventInfo queue[QUEUE_SIZE];
static int head = 0;
static int tail = 0;

/* Mutex y condición para sincronizar productor/consumidor */
static pthread_mutex_t qlock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  qcond = PTHREAD_COND_INITIALIZER;

/**
 * push_event:
 *   Mete “ev” en la cola. Si está llena, descarta el más antiguo.
 */
void push_event(EventInfo ev) {
    pthread_mutex_lock(&qlock);

    int next = (tail + 1) % QUEUE_SIZE;
    if (next == head) {
        /* Cola llena: descartamos el evento más viejo avanzando head */
        head = (head + 1) % QUEUE_SIZE;
    }

    queue[tail] = ev;
    tail = next;

    /* Despierta a cualquier pop_event() bloqueado */
    pthread_cond_signal(&qcond);
    pthread_mutex_unlock(&qlock);
}

/**
 * pop_event:
 *   Espera hasta que haya un evento en la cola, lo extrae y lo devuelve en *ev.
 */
void pop_event(EventInfo *ev) {
    pthread_mutex_lock(&qlock);

    /* Si la cola está vacía, esperamos */
    while (head == tail) {
        pthread_cond_wait(&qcond, &qlock);
    }

    *ev = queue[head];
    head = (head + 1) % QUEUE_SIZE;

    pthread_mutex_unlock(&qlock);
}
