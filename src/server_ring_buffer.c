#include "ring_buffer.h"
#include <fcntl.h>
#include <sys/stat.h>

void
ring_buffer_init (ring_buffer_t *rb)
{
  if (rb == NULL)
    return;
  rb->head = 0;
  rb->tail = 0;
  rb->count = 0;
  rb->initialized = 1;
  for (size_t i = 0; i < RING_BUFFER_SIZE; i++)
    {
      rb->messages[i][0] = '\0';
    }
}

int
ring_buffer_push (ring_buffer_t *rb, const char *message)
{
  if (rb == NULL || message == NULL || !rb->initialized)
    {
      return -1;
    }
  // Копирование буфера в head
  size_t msg_len = 0;
  const char *src = message;
  char *dest = rb->messages[rb->head];

  while (msg_len < MAX_LOG_MESSAGE_SIZE - 1 && *src != '\0')
    {
      *dest++ = *src++;
      msg_len++;
    }
  *dest = '\0';
  // Обновляем индексы
  rb->head = (rb->head + 1) % RING_BUFFER_SIZE;

  if (rb->count < RING_BUFFER_SIZE)
    {
      rb->count++;
    }
  else
    {
      // Буфер полный, двигаем tail
      rb->tail = (rb->tail + 1) % RING_BUFFER_SIZE;
    }
  return 0;
}

void
ring_buffer_write_to_file (ring_buffer_t *rb, const char *filename)
{
  if (rb == NULL || filename == NULL || !rb->initialized || rb->count == 0)
    {
      return;
    }
  int fd = open (filename, O_WRONLY | O_CREAT | O_TRUNC,
                 S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  if (fd == -1)
    {
      return;
    }

  for (size_t i = 0; i < rb->count; i++)
    {
      size_t index = (rb->tail + i) % RING_BUFFER_SIZE;
      const char *msg = rb->messages[index];
      size_t len = 0;
      while (len < MAX_LOG_MESSAGE_SIZE && msg[len] != '\0')
        {
          len++;
        }
      if (len > 0)
        {
          write (fd, msg, len);
        }
    }

  close (fd);
}