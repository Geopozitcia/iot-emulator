#define _DEFAULT_SOURCE
#include "packet.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#define SIZE_WIN MTU

static double
wtime ()
{
  struct timeval t;
  gettimeofday (&t, NULL);
  return (double)t.tv_sec + (double)t.tv_usec * 1E-6;
}

static int
setIpHeader (struct iphdr *iph, struct ip_header_info *inf)
{
  if (iph == NULL || inf == NULL)
    return -1;
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = htons (inf->total_len);
  iph->id = htons (inf->id);
  iph->frag_off = 0;
  iph->ttl = 16;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0;
  iph->saddr = inf->saddr;
  iph->daddr = inf->daddr;
  return 0;
}

static int
setTcpHeader (struct tcphdr *tcph, struct tcp_header_info *inf)
{
  if (tcph == NULL || inf == NULL)
    return -1;
  tcph->th_sport = inf->src_port;
  tcph->th_dport = inf->dst_port;
  tcph->th_seq = htonl (inf->seq);
  tcph->th_ack = htonl (inf->ack);
  tcph->th_off = 5;
  tcph->th_flags = inf->flags;
  tcph->th_win = htons (SIZE_WIN);
  tcph->th_sum = 0;
  tcph->th_urp = 0;
  return 0;
}

int
checkIph (struct iphdr *iph, struct sockaddr_in *src, struct sockaddr_in *dest)
{
  if (iph == NULL || dest == NULL || iph->version != 4
      || iph->protocol != IPPROTO_TCP)
    return -1;
  if (src == NULL)
    {
      if (iph->daddr != dest->sin_addr.s_addr)
        return -1;
    }
  else
    {
      if (iph->saddr != src->sin_addr.s_addr
          || iph->daddr != dest->sin_addr.s_addr)
        return -1;
    }
  return 0;
}

int
checkTcph (struct tcphdr *tcph, struct sockaddr_in *src,
           struct sockaddr_in *dest)
{
  if (tcph == NULL || dest == NULL)
    return -1;
  if (src == NULL)
    {
      if (tcph->th_dport != dest->sin_port || tcph->th_flags != TCP_SYN)
        return -1;
    }
  else
    {
      if (tcph->th_dport != dest->sin_port || tcph->th_sport != src->sin_port)
        return -1;
    }
  return 0;
}

static uint16_t
csum (uint16_t *ptr, int nbytes)
{
  uint16_t oddbyte, answer;
  long sum = 0;

  while (nbytes > 1)
    {
      sum += *ptr++;
      nbytes -= 2;
    }
  if (nbytes == 1)
    {
      oddbyte = 0;
      *((uint8_t *)&oddbyte) = *(uint8_t *)ptr;
      sum += oddbyte;
    }
  sum = (sum >> 16) + (sum & 0xffff);
  sum = sum + (sum >> 16);
  answer = (uint16_t)~sum;

  return answer;
}

int
sendPacket (int sfd, struct packet_info_snd *pinfo)
{
  if (pinfo == NULL)
    return PACKET_EARG;

  char buf[MTU] = { 0 };
  struct iphdr *iph = (struct iphdr *)buf;
  struct tcphdr *tcph = (struct tcphdr *)(buf + IP_HLEN);
  ssize_t msg_len;
  char *data = (buf + IP_HLEN + TCP_HLEN);
  int data_len = 0;

  if (pinfo->data.buf != NULL)
    {
      memcpy (data, pinfo->data.buf,
              pinfo->data.size > DATA_LEN ? DATA_LEN : pinfo->data.size);
      data_len = strlen (data) + 1;
    }
  setTcpHeader (tcph, pinfo->th_info);
  setIpHeader (iph, pinfo->iph_info);
  tcph->th_sum = csum ((uint16_t *)tcph, data_len + TCP_HLEN);
  iph->check = csum ((uint16_t *)iph, data_len + TCP_HLEN + IP_HLEN);

  if ((msg_len
       = sendto (sfd, buf, ntohs (iph->tot_len), 0,
                 (struct sockaddr *)pinfo->dest, sizeof (struct sockaddr_in)))
      == -1)
    {
      if (errno == EAGAIN)
        return PACKET_EAGAIN;
      return PACKET_ECALL;
    }
  return msg_len;
}

int
recvPacket (int sfd, struct packet_info_rcv *res, int timeval)
{
  if (res == NULL || res->l_addr == NULL || timeval <= 0)
    return PACKET_EARG;

  char recv_buf[MTU] = { 0 };
  struct iphdr *iph = (struct iphdr *)recv_buf;
  struct tcphdr *tcph = (struct tcphdr *)(recv_buf + IP_HLEN);
  char *data = (recv_buf + IP_HLEN + TCP_HLEN);
  size_t data_len;
  ssize_t msg_len;
  double end_time = wtime () + timeval;
  res->data.len = 0;

  while (1)
    {
      while ((msg_len = recvfrom (sfd, recv_buf, MTU - 1, 0, NULL, NULL))
             == -1)
        {
          if (wtime () >= end_time)
            return PACKET_EAGAIN;
          if (errno == EAGAIN)
            {
              struct timespec ping;
              ping.tv_sec = 0;
              ping.tv_nsec = 1000;
              nanosleep (&ping, NULL);
              continue;
            }
          else
            return PACKET_ECALL;
        }
      if (wtime () >= end_time)
        return PACKET_EAGAIN;
      if (checkIph (iph, res->src, res->l_addr) == -1)
        continue;
      if (checkTcph (tcph, res->src, res->l_addr) == -1)
        continue;
      int ip_header_len = iph->ihl * 4;
      int tcp_header_len = tcph->th_off * 4;
      data_len = msg_len - ip_header_len - tcp_header_len;
      if (csum ((uint16_t *)tcph, TCP_HLEN + data_len) != 0)
        return PACKET_EAGAIN;
      if (csum ((uint16_t *)iph, TCP_HLEN + IP_HLEN + data_len) != 0)
        return PACKET_EAGAIN;
      break;
    }
  if (res->data.buf != NULL)
    {
      data_len = res->data.size > data_len ? data_len : res->data.size;
      strncpy (res->data.buf, data, data_len);
      res->data.len = data_len;
    }
  res->flags = tcph->th_flags;
  res->seq = ntohl (tcph->th_seq);
  res->ack = ntohl (tcph->th_ack);
  if (res->src == NULL)
    {
      memset (&res->dest, 0, sizeof (struct sockaddr_in));
      res->dest.sin_addr.s_addr = iph->saddr;
      res->dest.sin_family = AF_INET;
      res->dest.sin_port = tcph->th_sport;
    }
  return msg_len;
}