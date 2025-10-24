#ifndef RING_BUFFER_H
#define RING_BUFFER_H

#include <stddef.h>
#include <string.h>
#include <unistd.h>

#define RING_BUFFER_SIZE 100
#define MAX_LOG_MESSAGE_SIZE 256

typedef struct
{
  char messages[RING_BUFFER_SIZE][MAX_LOG_MESSAGE_SIZE];
  size_t head;
  size_t tail;
  size_t count;
  int initialized;
} ring_buffer_t;

void ring_buffer_init (ring_buffer_t *rb);
int ring_buffer_push (ring_buffer_t *rb, const char *message);
void ring_buffer_write_to_file (ring_buffer_t *rb, const char *filename);

#endif