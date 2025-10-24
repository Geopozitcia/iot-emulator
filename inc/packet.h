#ifndef _PACKET_H_
#define _PACKET_H_

#include <netinet/in.h>
#include <netinet/tcp.h>

#define MTU 476
#define TCP_HLEN 20
#define IP_HLEN 20
#define DATA_LEN (MTU - IP_HLEN - TCP_HLEN)

struct ip_header_info
{
  uint16_t total_len;
  uint16_t id;
  uint32_t saddr, daddr;
};

struct tcp_header_info
{
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t seq;
  uint32_t ack;
  uint8_t flags;
};

struct packet_data
{
  char *buf;
  size_t size;
  size_t len;
};

struct packet_info_snd
{
  struct packet_data data;         /* данные */
  struct sockaddr_in *src;         /* источник */
  struct sockaddr_in *dest;        /* назначение */
  struct tcp_header_info *th_info; /* информация tcp */
  struct ip_header_info *iph_info; /* информация ip */
};

struct packet_info_rcv
{
  char *packet;
  struct packet_data data;
  struct sockaddr_in *src;
  struct sockaddr_in *l_addr;
  uint32_t seq, ack;
  struct sockaddr_in dest;
  uint8_t flags;
};

enum
{
  TCP_FIN = 0x01,
  TCP_SYN = 0x02,
  TCP_RST = 0x04,
  TCP_PSH = 0x08,
  TCP_ACK = 0x10,
};

enum
{
  PACKET_EAGAIN = -3, /* неправильная контрольная сумма/закончилось время. */
  PACKET_ECALL,       /* ошибки с recvfrom/sendto. */
  PACKET_EARG,        /* несоответствие аргументов. */
};

int sendPacket (int sfd, struct packet_info_snd *pinfo);
int recvPacket (int sfd, struct packet_info_rcv *res, int timeval);

#endif