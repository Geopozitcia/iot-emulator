#ifndef DEEVICES_H
#define DEEVICES_H

#include <netinet/in.h>
#include <sys/socket.h>

typedef enum
{
  LC, /*Light controller*/
  TS  /*Temperature sensor*/
} device_type;

typedef struct device
{
  struct sockaddr_in client;
  device_type type;
  float temperature;   /*for temperature sensor*/
  uint32_t light_mask; /*for light controller. used to be unsigned int*/
  int tcp_fd;
  char is_connected;
  char dev_name[32]; /*device name*/
} device_t;

#endif