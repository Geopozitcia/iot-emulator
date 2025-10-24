#include <arpa/inet.h>
#include <broadcast.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "encrypt.h"
#include "temperature_sensor.h"

#define BROADCAST_ADDR "255.255.255.255"

#define BUF_SIZE 50

#define MSG_SEND_CL "{\"ask\": \"WHO S\"}"
#define MSG_SEND_SV "{\"ans\": \"Im S\"}"

#define TV_SEC 2

#define handle_error(msg, retval)                                             \
  do                                                                          \
    {                                                                         \
      write (STDERR_FILENO, msg, strlen (msg));                               \
      write (STDERR_FILENO, "\n", 1);                                         \
      return retval;                                                          \
    }                                                                         \
  while (0)

/*
заполняет структуру struct sockaddr_in.
Если есть ошибка - возвращает -1, иначе 0.
*/
static int
fillSockaddrIn (struct sockaddr_in *sin, char *addr, unsigned short port)
{
  if (sin == NULL || addr == NULL)
    return -1;
  memset (sin, 0, sizeof (struct sockaddr_in));
  if (inet_pton (AF_INET, addr, &sin->sin_addr) <= 0)
    return -1;
  sin->sin_family = AF_INET;
  sin->sin_port = htons (port);
  return 0;
}

/*
Создает сокет, устанавливает разрешение на широковещательную рассылку.
Отправляет пакет на широковещательный адрес (BROADCAST_ADDR:BROADCAST_PORT).
Если есть ответ от сервера, то клиент напрямую получает пакет от сервера.
Если ответа нет, то recvfrom ожидает 2 секунды и повторно отправляет пакет на
широковещательный адрес. Максимум отправленных пакетов на широковещательный
адрес: 5. После функция завершается. Функция возвращает 0 и записывает данные в
sv_addr и sv_port, если есть данные от сервера, иначе -1 и выводит ошибку в
терминал.
*/
int
recvDataServer (const char *l_addr, char *sv_addr, uint16_t *sv_port,
                int fl_crypt)
{
  if (l_addr == NULL || sv_addr == NULL || sv_port == NULL)
    return -1;

  int sfd;
  struct timeval tv;
  struct sockaddr_in brd, sv, cl;
  socklen_t sv_len;
  ssize_t msg_len;
  char buf[BUF_SIZE], buf1[BUF_SIZE], buf2[BUF_SIZE], buf3[BUF_SIZE];
  int count_send = 0;
  int en = 1;

  if ((sfd = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    handle_error ("recv_data_server: socket", -1);

  srand (time (NULL));
  memset (&cl, 0, sizeof (struct sockaddr_in));
  if (inet_pton (AF_INET, l_addr, &cl.sin_addr) < 0)
    handle_error ("recv_data_server: inet pton", -1);
  cl.sin_port = 45000 + rand () % 10000;
  cl.sin_family = AF_INET;
  if (bind (sfd, (struct sockaddr *)&cl, sizeof (struct sockaddr_in)) == -1)
    handle_error ("recv_data_server: bind", -1);

  tv.tv_sec = TV_SEC;
  tv.tv_usec = 0;

  if (setsockopt (sfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof (tv)) == -1)
    handle_error ("recv_data_server: setsockopt timeval", -1);

  if (setsockopt (sfd, SOL_SOCKET, SO_BROADCAST, &en, sizeof (en)) == -1)
    handle_error ("recv_data_server: setsockopt broadcast", -1);

  if (fillSockaddrIn (&brd, BROADCAST_ADDR, SERVER_PORT) == -1)
    handle_error ("recv_data_server: fill sockaddr in broadcast", -1);

  if (fl_crypt)
    {
      memcpy (buf, MSG_SEND_CL, strlen (MSG_SEND_CL) + 1);
      if (Encrypt (buf, strlen (buf), buf1, sizeof (buf1)) == -1)
        handle_error ("recv_data_server: error encrypt", -1);
    }
  else
    memcpy (buf1, MSG_SEND_CL, strlen (MSG_SEND_CL) + 1);

  while (1)
    {
      if (sendto (sfd, buf1, strlen (buf1), 0, (struct sockaddr *)&brd,
                  sizeof (brd))
          == -1)
        handle_error ("recv_data_server: sendto", -1);
      sv_len = sizeof (struct sockaddr_in);
      msg_len
          = recvfrom (sfd, buf2, BUF_SIZE, 0, (struct sockaddr *)&sv, &sv_len);
      buf2[msg_len] = '\0';
      if (msg_len == -1)
        count_send++;
      else if (fl_crypt)
        {
          if (Decrypt (buf2, strlen (buf2), buf3, sizeof (buf3)) == -1)
            continue;
          if (strcmp (buf3, MSG_SEND_SV) == 0)
            break;
        }
      else if (strcmp (buf2, MSG_SEND_SV) == 0)
        break;
      if (count_send == 5)
        handle_error ("recv_data_server: timeout", -1);
    }
  if (inet_ntop (AF_INET, &sv.sin_addr, sv_addr, 16) == NULL)
    handle_error ("recv_data_server: inet ntop", -1);
  *sv_port = ntohs (sv.sin_port);
  shutdown (sfd, SHUT_RDWR);
  return 0;
}

/*
Создает 2 сокета: 1 - для обработки широковещательных пакетов,
2 - для отправки данных от сервера к клиенту.
1 сокет принимает пакеты от широковещательного адреса. Если
есть пакет, то принимает пакет и обрабатывает его. Если пакет
подходит по условию, то 2 сокет (сервер) отправляет MSG_SEND_SV клиенту.
Совместим с pthread_create.
*/
void *
sendDataServer (void *data)
{
  if (data == NULL)
    return NULL;

  struct brd_thread_info *tinfo = (struct brd_thread_info *)data;
  char *sv_addr = tinfo->addr;
  uint16_t sv_port = tinfo->port;
  int fl_crypt = tinfo->fl_crypt;

  int sfd, sfd_brd;
  struct sockaddr_in brd, sv, cl;
  socklen_t cl_len;
  ssize_t msg_len;
  char buf[BUF_SIZE], buf1[BUF_SIZE];
  char *buf_ptr = fl_crypt ? buf1 : buf;

  if ((sfd_brd = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    handle_error ("send_data_server: socket broadcast", NULL);
  if ((sfd = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    handle_error ("send_data_server: socket server", NULL);

  if (fillSockaddrIn (&brd, BROADCAST_ADDR, SERVER_PORT) == -1)
    handle_error ("send_data_server: fill sockaddr in broadcast", NULL);

  if (bind (sfd_brd, (struct sockaddr *)&brd, sizeof (brd)) == -1)
    handle_error ("send_data_server: bind broadcast", NULL);

  if (fillSockaddrIn (&sv, sv_addr, sv_port) == -1)
    handle_error ("send data server: fill sockaddr in server", NULL);

  if (bind (sfd, (struct sockaddr *)&sv, sizeof (sv)) == -1)
    handle_error ("send_data_server: bind server", NULL);

  while (1)
    {
      cl_len = sizeof (struct sockaddr_in);
      msg_len = recvfrom (sfd_brd, buf, BUF_SIZE, 0, (struct sockaddr *)&cl,
                          &cl_len);
      if (msg_len == -1)
        handle_error ("send_data_server: recvfrom", NULL);
      if (fl_crypt)
        {
          if (Decrypt (buf, strlen (buf), buf1, sizeof (buf1)) == -1)
            continue;
        }
      else if (strcmp (buf_ptr, MSG_SEND_CL) != 0)
        continue;
      if (fl_crypt)
        {
          if (Encrypt (buf1, strlen (buf1), buf, sizeof (buf)) == -1)
            handle_error ("send_data_server: encrypt", NULL);
        }
      else
        memcpy (buf, MSG_SEND_SV, strlen (MSG_SEND_SV));

      if (sendto (sfd, buf, strlen (buf) + 1, 0, (struct sockaddr *)&cl,
                  cl_len)
          == -1)
        handle_error ("send_data_server: sendto", NULL);
    }
  return NULL;
}
