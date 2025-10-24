#include "tcp.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "packet.h"

#define MAX_REPEAT_SEND_PACKET 3

int
setTcpHdrInfo (struct tcp_header_info *thinfo, uint16_t sport, uint16_t dport,
               uint32_t seq, uint32_t ack, uint8_t flags)
{
  if (thinfo == NULL)
    return -1;
  thinfo->src_port = sport;
  thinfo->dst_port = dport;
  thinfo->seq = seq;
  thinfo->ack = ack;
  thinfo->flags = flags;
  return 0;
}

int
setIpHdrInfo (struct ip_header_info *ipinfo, uint16_t tlen, uint16_t id,
              uint32_t saddr, uint32_t daddr)
{
  if (ipinfo == NULL)
    return -1;
  ipinfo->total_len = tlen;
  ipinfo->id = id;
  ipinfo->saddr = saddr;
  ipinfo->daddr = daddr;
  return 0;
}

int
tcpConnect (int sfd, struct sockaddr_in *l_addr, struct sockaddr_in *dest)
{
  if (l_addr == NULL || dest == NULL)
    return TCP_EARG;

  struct packet_info_snd pinfo_s;
  struct packet_info_rcv pinfo_r;
  struct tcp_header_info tcp_hinfo;
  struct ip_header_info ip_hinfo;

  setTcpHdrInfo (&tcp_hinfo, l_addr->sin_port, dest->sin_port, 0, 0, TCP_SYN);
  setIpHdrInfo (&ip_hinfo, TCP_HLEN + IP_HLEN, 8547, l_addr->sin_addr.s_addr,
                dest->sin_addr.s_addr);
  pinfo_s.data.buf = NULL;
  pinfo_s.data.size = 0;
  pinfo_s.src = l_addr;
  pinfo_s.dest = dest;
  pinfo_s.th_info = &tcp_hinfo;
  pinfo_s.iph_info = &ip_hinfo;
  pinfo_r.packet = NULL;
  pinfo_r.data.buf = NULL;
  pinfo_r.src = dest;
  pinfo_r.l_addr = l_addr;

  int flag_send = 0;
  int len;
  for (int i = 0; !flag_send && i < MAX_REPEAT_SEND_PACKET; i++)
    {
      if ((len = sendPacket (sfd, &pinfo_s)) != (IP_HLEN + TCP_HLEN))
        {
          if (len == PACKET_EAGAIN || len >= 0)
            continue;
          else
            return TCP_ECALL;
        }
      if ((len = recvPacket (sfd, &pinfo_r, 8)) < 0)
        {
          if (len == PACKET_EAGAIN)
            continue;
          else
            return TCP_ECALL;
        }
      flag_send = 1;
    }
  if (!flag_send)
    return TCP_EAGAIN;
  flag_send = 0;
  if (pinfo_r.flags != (uint8_t)(TCP_SYN | TCP_ACK))
    return TCP_EFLAG;
  tcp_hinfo.flags = TCP_ACK;
  tcp_hinfo.seq = tcp_hinfo.ack = 1;

  for (int i = 0; !flag_send && i < MAX_REPEAT_SEND_PACKET; i++)
    {
      if (sendPacket (sfd, &pinfo_s) != (IP_HLEN + TCP_HLEN))
        {
          if (len == PACKET_EAGAIN || len >= 0)
            continue;
          else
            return TCP_ECALL;
        }
      flag_send = 1;
    }
  if (!flag_send)
    return TCP_EAGAIN;
  return 0;
}

int
tcpAccept (int sfd, struct sockaddr_in *l_addr, struct sockaddr_in *result)
{
  if (l_addr == NULL || result == NULL)
    return TCP_EARG;

  struct packet_info_snd pinfo_s;
  struct packet_info_rcv pinfo_r;
  struct tcp_header_info tcp_hinfo;
  struct ip_header_info ip_hinfo;
  struct sockaddr_in *cl = NULL;
  int len;

  pinfo_r.src = NULL;
  pinfo_r.l_addr = l_addr;
  pinfo_r.data.buf = NULL;

  if ((len = recvPacket (sfd, &pinfo_r, 10)) < 0)
    return TCP_EAGAIN;

  cl = &pinfo_r.dest;
  setTcpHdrInfo (&tcp_hinfo, l_addr->sin_port, cl->sin_port, 0, 1,
                 TCP_SYN | TCP_ACK);
  setIpHdrInfo (&ip_hinfo, TCP_HLEN + IP_HLEN, 8548, l_addr->sin_addr.s_addr,
                cl->sin_addr.s_addr);
  pinfo_s.data.buf = NULL;
  pinfo_s.data.size = 0;
  pinfo_s.src = l_addr;
  pinfo_s.dest = cl;
  pinfo_s.th_info = &tcp_hinfo;
  pinfo_s.iph_info = &ip_hinfo;

  pinfo_r.src = cl;

  int flag_send = 0;

  for (int i = 0; !flag_send && i < MAX_REPEAT_SEND_PACKET; i++)
    {
      if ((len = sendPacket (sfd, &pinfo_s)) != (IP_HLEN + TCP_HLEN))
        {
          if (len == PACKET_EAGAIN || len >= 0)
            continue;
          else
            return TCP_ECALL;
        }
      if ((len = recvPacket (sfd, &pinfo_r, 8)) < 0)
        {
          if (len == PACKET_EAGAIN)
            continue;
          else
            return TCP_ECALL;
        }
      flag_send = 1;
    }
  if (!flag_send)
    return TCP_EAGAIN;
  if (pinfo_r.flags != TCP_ACK)
    return TCP_EFLAG;
  memcpy (result, &pinfo_r.dest, sizeof (struct sockaddr_in));
  return 0;
}

int
tcpSend (int sfd, char *buf, size_t size, struct sockaddr_in *l_addr,
         struct sockaddr_in *dest, msg_type_t t)
{
  if (l_addr == NULL || dest == NULL)
    return TCP_EARG;

  struct packet_info_snd pinfo_s;
  struct packet_info_rcv pinfo_r;
  struct tcp_header_info tcp_hinfo;
  struct ip_header_info ip_hinfo;
  int tot_len = TCP_HLEN + IP_HLEN + (size > DATA_LEN ? DATA_LEN : size);
  uint8_t flags;

  switch (t)
    {
    case MSG:
      flags = TCP_ACK | TCP_PSH;
      break;
    default:
      flags = TCP_FIN;
    }
  setTcpHdrInfo (&tcp_hinfo, l_addr->sin_port, dest->sin_port, 0, 0, flags);
  setIpHdrInfo (&ip_hinfo, tot_len, 850, l_addr->sin_addr.s_addr,
                dest->sin_addr.s_addr);
  pinfo_s.data.size = size;
  pinfo_s.data.buf = buf;
  pinfo_s.src = l_addr;
  pinfo_s.dest = dest;
  pinfo_s.th_info = &tcp_hinfo;
  pinfo_s.iph_info = &ip_hinfo;
  pinfo_r.src = dest;
  pinfo_r.l_addr = l_addr;
  pinfo_r.data.buf = NULL;
  pinfo_r.data.size = size;

  int flag_send = 0;
  int len_send, len_recv;

  if (t == EXIT)
    {
      if ((len_send = sendPacket (sfd, &pinfo_s)) < 0)
        return len_send;
      if ((len_recv = recvPacket (sfd, &pinfo_r, 1)) < 0)
        return len_recv;
      return 0;
    }
  for (int i = 0; !flag_send && i < MAX_REPEAT_SEND_PACKET; i++)
    {
      if ((len_send = sendPacket (sfd, &pinfo_s)) < 0)
        {
          if (len_send == PACKET_EAGAIN)
            continue;
          else
            return TCP_ECALL;
        }
      if ((len_recv = recvPacket (sfd, &pinfo_r, 8)) < 0)
        {
          if (len_recv == PACKET_EAGAIN)
            continue;
          else
            return TCP_ECALL;
        }
      flag_send = 1;
    }
  if (!flag_send)
    return TCP_EAGAIN;
  return 0;
}

int
tcpRecv (int sfd, char *buf, size_t size, struct sockaddr_in *l_addr,
         struct sockaddr_in *src)
{
  if (buf == NULL || l_addr == NULL || src == NULL)
    return TCP_EARG;

  struct packet_info_snd pinfo_s;
  struct packet_info_rcv pinfo_r;
  struct tcp_header_info tcp_hinfo;
  struct ip_header_info ip_hinfo;
  int tot_len = TCP_HLEN + IP_HLEN;
  int len_send, len_recv, flag_send = 0;

  pinfo_r.data.buf = buf;
  pinfo_r.data.size = size;
  pinfo_r.src = src;
  pinfo_r.l_addr = l_addr;

  for (int i = 0; !flag_send && i < MAX_REPEAT_SEND_PACKET; i++)
    {
      if ((len_recv = recvPacket (sfd, &pinfo_r, 10)) < 0)
        {
          if (len_recv == PACKET_EAGAIN)
            continue;
          else
            return TCP_ECALL;
        }
      flag_send = 1;
    }
  if (!flag_send)
    return TCP_EAGAIN;
  switch (pinfo_r.flags)
    {
    case (TCP_ACK | TCP_PSH):
      tcp_hinfo.flags = TCP_ACK | TCP_PSH;
      break;
    case (TCP_FIN):
      tcp_hinfo.flags = TCP_ACK;
      break;
    default:
      tcp_hinfo.flags = TCP_RST;
    }
  setTcpHdrInfo (&tcp_hinfo, l_addr->sin_port, src->sin_port, 0, 0,
                 tcp_hinfo.flags);
  setIpHdrInfo (&ip_hinfo, tot_len, 851, l_addr->sin_addr.s_addr,
                src->sin_addr.s_addr);
  pinfo_s.data.size = 0;
  pinfo_s.data.buf = NULL;
  pinfo_s.src = l_addr;
  pinfo_s.dest = src;
  pinfo_s.th_info = &tcp_hinfo;
  pinfo_s.iph_info = &ip_hinfo;
  if ((len_send = sendPacket (sfd, &pinfo_s)) < 0)
    if (len_send != PACKET_EAGAIN)
      return TCP_ECALL;
  return pinfo_r.data.len;
}
