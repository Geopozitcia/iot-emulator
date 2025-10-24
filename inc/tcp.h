#ifndef _TCP_H_
#define _TCP_H_

#include <netinet/in.h>

#include "packet.h"

typedef enum
{
  MSG,
  EXIT
} msg_type_t;

enum return_flags_err
{
  TCP_EAGAIN = -4, /* попробуй еще раз (закончилось время). */
  TCP_ECALL,       /* ошибка системного вызова. */
  TCP_EARG,        /* неверные аргументы функции. */
  TCP_EFLAG,       /* получен неверный пакет. */
};

int tcpConnect (int sfd, struct sockaddr_in *l_addr, struct sockaddr_in *dest);
int tcpAccept (int sfd, struct sockaddr_in *l_addr,
               struct sockaddr_in *result);
int tcpSend (int sfd, char *buf, size_t size, struct sockaddr_in *l_addr,
             struct sockaddr_in *dest, msg_type_t t);
int tcpRecv (int sfd, char *buf, size_t size, struct sockaddr_in *l_addr,
             struct sockaddr_in *src);

int setTcpHdrInfo (struct tcp_header_info *thinfo, uint16_t sport,
                   uint16_t dport, uint32_t seq, uint32_t ack, uint8_t flags);

int setIpHdrInfo (struct ip_header_info *ipinfo, uint16_t tlen, uint16_t id,
                  uint32_t saddr, uint32_t daddr);
#endif