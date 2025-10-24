#ifndef _BROADCAST_H_
#define _BROADCAST_H_

#include <inttypes.h>

struct brd_thread_info
{
  char *addr;
  uint16_t port;
  int fl_crypt;
};

int recvDataServer (const char *l_addr, char *sv_addr, uint16_t *sv_port,
                    int fl_crypt);
void *sendDataServer (void *data);

#endif