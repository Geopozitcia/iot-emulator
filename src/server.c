#define _GNU_SOURCE

#include "server.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <tcp.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "devices.h"
#include "encrypt.h"
#include "jparce.h"
#include "packet.h"
#include "ring_buffer.h"
#include "serverUdps.h"
#include "tcp.h"
#include "temperature_sensor.h"

#define MAX_PACKET_PAYLOAD_SIZE 1024

device_t devices_udp[MAX_DEVICE] = { 0 };
device_t devices_tcp[MAX_DEVICE] = { 0 };
time_t udp_last_receive[MAX_DEVICE] = { 0 };
pthread_mutex_t mutex_udp = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_tcp = PTHREAD_MUTEX_INITIALIZER;

void
lock_udp_devices ()
{
  pthread_mutex_lock (&mutex_udp);
}
void
unlock_udp_devices ()
{
  pthread_mutex_unlock (&mutex_udp);
}

void
lock_tcp_devices ()
{
  pthread_mutex_lock (&mutex_tcp);
}
void
unlock_tcp_devices ()
{
  pthread_mutex_unlock (&mutex_tcp);
}

static ring_buffer_t log_buffer;
static int buffer_initialized = 0;

void
init_log_buffer (void)
{
  if (!buffer_initialized)
    {
      ring_buffer_init (&log_buffer);
      buffer_initialized = 1;
    }
}

void
lock_proto_devices (proto_type proto)
{
  if (proto == TCP)
    {
      lock_tcp_devices ();
    }
  else if (proto == UDP)
    {
      lock_udp_devices ();
    }
}

void
unlock_proto_devices (proto_type proto)
{
  if (proto == TCP)
    {
      unlock_tcp_devices ();
    }
  else if (proto == UDP)
    {
      unlock_udp_devices ();
    }
}

int udp_socket = -1;
int tcp_socket_sender = -1;
int shutdown_flag = 0;
char *logfile = "log/server.log";

void
sigHandle (int sig)
{
  (void)sig;
  shutdown_flag = 1;
}

/*Закрывает все сокеты ждет завершения потоков, очищает файл статистики*/
void
closeServer ()
{
  disconnectAllTcp ();
  disconnectAllUdp ();

  close (udp_socket);
  close (tcp_socket_sender);

  pthread_cancel (
      tid_accepter_TCP); /*т.к функция accept занимает некоторый timeout*/
  pthread_join (tid_accepter_TCP, NULL);
  pthread_join (tid_handler_udp, NULL);
  pthread_join (stats_tid, NULL);
  pthread_join (tid_monitor, NULL);

  FILE *f = fopen ("log/statistic.info",
                   "w"); // отчищаем statistic.info при отключении
  if (f)
    {
      fclose (f);
    }
  write (1, "\n", 1);
}

/*обработчик всех входящих tcp соединений*/
void *
accepterTCP (void *arg)
{
  (void)arg;
  int tcp_socket_accepter = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);
  if (tcp_socket_accepter == -1)
    {
      exit (EXIT_FAILURE);
    }
  int one = 1;
  setsockopt (tcp_socket_accepter, IPPROTO_IP, IP_HDRINCL, &one, sizeof (one));
  struct sockaddr_in cli;

  struct pollfd fd[1];
  fd[0].fd = tcp_socket_accepter;
  fd[0].events = POLLIN;

  while (!shutdown_flag)
    {
      if (poll (fd, 1, 20) < 1)
        {
          continue;
        }
      if (tcpAccept (tcp_socket_accepter, &l_addr, &cli))
        {
          continue;
        }
      char buff[MAX_PACKET_PAYLOAD_SIZE];
      int size_buff;
      if ((size_buff
           = tcpRecv (tcp_socket_accepter, buff, sizeof (buff), &l_addr, &cli))
          < 0)
        {
          continue;
        }
      char json_decr[MAX_JSON_SIZE];
      char *json = buff;
      if (is_enc)
        {
          if (Decrypt (buff, size_buff, json_decr, MAX_JSON_SIZE))
            {
              logg (logfile, "cannot decrypt msg\n");
              continue;
            }
          json = json_decr;
        }

      char buff_type[15];
      device_type type;
      if (jGetVal (json, "type", buff_type))
        { /*все пакеты cmd имеют тип читаем его*/
          continue;
        }
      if (getTypeFromStr (buff_type, &type))
        {
          continue;
        }
      char dev_name[32];
      if (jGetVal (json, "dev", dev_name) != 0)
        {
          continue; // Устройство должно иметь имя
        }
      char cmd[30];
      if (jGetVal (json, "cmd", cmd))
        {
          continue;
        }
      if (strcmp (C_MSG, cmd) == 0)
        {
          connectionDevice (cli, type, dev_name, TCP);
        }
    }
  close (tcp_socket_accepter);
  return NULL;
}

/*
функция принимает в себя 2 указателя:
1. Нультерминированная строка
2. Массив в который должна поместиться зашифрованная строка в случае шифрования

Функция выбирает необходимо ли шифрование (is_enc) и в зависимости от этого
выбирает на какую строку будет указывать dst_str
*/
int
chooseEncrMsg (char *clear_msg, char *encr_msg, size_t len_encr_msg,
               char **dst_str)
{
  if (clear_msg == NULL || encr_msg == NULL || dst_str == NULL)
    {
      return -1;
    }
  *dst_str = clear_msg;
  if (is_enc)
    {
      if (Encrypt (clear_msg, strlen (clear_msg), encr_msg, len_encr_msg))
        {
          logg (logfile, "cannot encr msg\n");
          return -1;
        }
      *dst_str = encr_msg;
    }
  return 0;
}

/*
На воход получает 2 указателя.
clear_msg - исходная строка
decr_msg - уже выделенный пользователем указатель, сюда записывается
расшифрованное значение в случае необходимости
Функция выбирает необходимо ли дешифровать (is_enc) данные и в зависимости от
этого выбирает на какую строку будет указывать dst_str
*/
int
chooseDecrypMsg (char *clear_msg, size_t len_clear_msg, char *decr_msg,
                 size_t len_decr_msg, char **dst_str)
{
  *dst_str = clear_msg;
  if (is_enc)
    {
      if (Decrypt (clear_msg, len_clear_msg, decr_msg, len_decr_msg))
        {
          logg (logfile, "cannot decrypt msg\n");
          return -1;
        }
      *dst_str = decr_msg;
    }
  return 0;
}

/*
Функция отправляет отправляет LC по id просьбу о включении или выключении
лампочки. Получает ответ от LC - текущую маску.
Успех - 0
Неудача - -1
*/
int
getLightId (int id, int numberLight, int is_on)
{
  lock_tcp_devices ();
  int id_dev = 0;
  int target_fd = -1;
  struct sockaddr_in target_client;
  for (int i = 0; i != MAX_DEVICE; i++)
    {
      if (id_dev == id && devices_tcp[i].is_connected == 1)
        {
          target_fd = devices_tcp[i].tcp_fd;
          target_client = devices_tcp[i].client;
          break;
        }
      if (devices_tcp[i].is_connected)
        {
          id_dev++;
        }
    }
  unlock_tcp_devices ();

  if (target_fd == -1)
    {
      return -1;
    }

  char json[MAX_JSON_SIZE + 1];
  snprintf (json, sizeof (json),
            "{\"cmd\": \"set_light\", \"id\": %d, \"state\": \"%s\"}",
            numberLight, (is_on == 1) ? "on" : "off");

  char json_encr[MAX_PACKET_PAYLOAD_SIZE];
  char *send_msg = NULL;
  if (chooseEncrMsg (json, json_encr, MAX_PACKET_PAYLOAD_SIZE, &send_msg))
    return -1;

  if (tcpSend (target_fd, send_msg, strlen (send_msg), &l_addr, &target_client,
               MSG))
    return -1;

  int buf_len;
  if ((buf_len
       = tcpRecv (target_fd, json, sizeof (json), &l_addr, &target_client))
      < 0)
    return -1;
  char rec_msg_dec[MAX_JSON_SIZE];
  char *rec_msg = NULL;

  if (chooseDecrypMsg (json, buf_len, rec_msg_dec, MAX_JSON_SIZE, &rec_msg))
    return -1;

  if (jsonManager (rec_msg, target_client, TCP) == -1)
    return -1;
  return 0;
}

/*функция для чтения символа с консоли*/
int
readFromCons ()
{
  int index = 0;
  char ch;
  int result = 0;
  int sign = 1;

  while (read (STDIN_FILENO, &ch, 1) == 1)
    {
      if (index == 0 && isspace (ch))
        {
          continue;
        }

      if (index == 0 && ch == '-')
        {
          sign = -1;
          index++;
          continue;
        }

      if (ch >= '0' && ch <= '9')
        {
          result = result * 10 + (ch - '0');
          index++;
        }
      else
        {
          break;
        }
    }

  return result * sign;
}

/*вывод всех TCP девайсов (Light Controller)*/
void
printTCPdevices ()
{
  int id = 0;
  lock_tcp_devices ();
  for (int i = 0; i != MAX_DEVICE; i++)
    {
      char buffer[256];
      if (devices_tcp[i].is_connected != 0)
        {
          snprintf (buffer, sizeof (buffer), "id - %d, name - %s, mask - %u\n",
                    id, devices_tcp[i].dev_name, devices_tcp[i].light_mask);
          write (1, buffer, strlen (buffer));
          id++;
        }
    }
  unlock_tcp_devices ();
}

/*вывод всех UDP девайсов (Temperature Sensor)*/
void
printUDPdevices ()
{
  int id = 0;
  lock_udp_devices ();
  for (int i = 0; i != MAX_DEVICE; i++)
    {
      char buffer[256];
      if (devices_udp[i].is_connected != 0)
        {
          snprintf (buffer, sizeof (buffer),
                    "id - %d, name - %s, temp - %.1f\n", id,
                    devices_udp[i].dev_name, devices_udp[i].temperature);
          write (1, buffer, strlen (buffer));
        }
    }
  unlock_udp_devices ();
}

/*
Функция получает очередной пакет из udp_socket
в случае если пакет предназначается программе передат json файл в jsonManager
пакет не принадлежит программе - 1
успех - 0
неудача - -1
*/
int
getUdpPacket ()
{
  char packet[MAX_PACKET_PAYLOAD_SIZE];
  struct sockaddr_in client;
  socklen_t client_len = sizeof (client);
  if (recvfrom (udp_socket, packet, sizeof (packet), 0,
                (struct sockaddr *)&client, &client_len)
      == -1)
    {
      shutdown_flag = 1;
      return -1;
    }
  struct udphdr *udph;
  struct iphdr *iph;
  char *payload;
  getPacketElements (packet, &iph, &udph, &payload);
  if (ntohs (udph->dest) != SERVER_PORT)
    return 1;
  client.sin_port = udph->source;
  int payload_len = ntohs (udph->len) - UDP_HDR_LEN;
  payload[payload_len] = '\0';
  char payloadDecr[MAX_PACKET_PAYLOAD_SIZE];
  char *json = NULL;
  if (chooseDecrypMsg (payload, payload_len, payloadDecr,
                       MAX_PACKET_PAYLOAD_SIZE, &json))
    return -1;
  jsonManager (json, client, UDP);
  return 0;
}

/*
Функция обрабатывает FIN пакеты от клиентов.
В случае Fin пакета происходит отключение ус-ва и ответа пакетом ACK
возвращаемые значения:
0 - успех
остальное - неуспех/пакет не предназначен для отключения
*/
int
getTcpPacketDisconeccted (int tcp_socket_disconnecter)
{
  char packet[MAX_PACKET_PAYLOAD_SIZE];
  struct sockaddr_in client;
  socklen_t client_len = sizeof (client);
  if (recvfrom (tcp_socket_disconnecter, packet, sizeof (packet), 0, &client,
                &client_len)
      == -1)
    {
      shutdown_flag = 1;
      return -1;
    }
  struct iphdr *iph = (struct iphdr *)packet;
  struct tcphdr *tcph = (struct tcphdr *)(packet + iph->ihl * 4);
  char *payload = (char *)(packet + iph->ihl * 4 + tcph->doff * 4);
  int payload_len = ntohs (iph->tot_len) - (iph->ihl * 4 + tcph->doff * 4);
  client.sin_addr.s_addr = iph->saddr;
  client.sin_port = tcph->source;
  if (ntohs (tcph->dest) != SERVER_PORT || !(tcph->th_flags & TH_FIN))
    return 1;
  if (payload_len <= 0)
    return 1;
  payload[payload_len] = '\0';
  char payload_decr[MAX_PACKET_PAYLOAD_SIZE];
  char *json = NULL;
  if (chooseDecrypMsg (payload, payload_len, payload_decr,
                       MAX_PACKET_PAYLOAD_SIZE, &json))
    return -1;
  if (parse (json))
    return -1;
  char buffer[256];
  if (jGetVal (json, "cmd", buffer))
    return -1;
  if (strcmp (buffer, "CC") != 0)
    return -1;
  if (jGetVal (json, "type", buffer))
    return -1;
  if (strcmp (buffer, "LC") != 0)
    return -1;
  if (disconnectionDevice (client, TCP))
    return -1;
  int tot_len = TCP_HLEN + IP_HLEN;

  struct packet_info_snd pinfo_s;
  struct tcp_header_info tcp_hinfo;
  struct ip_header_info ip_hinfo;
  tcp_hinfo.flags = TCP_ACK;
  setTcpHdrInfo (&tcp_hinfo, l_addr.sin_port, tcph->source, 0, 0,
                 tcp_hinfo.flags);
  setIpHdrInfo (&ip_hinfo, tot_len, 851, l_addr.sin_addr.s_addr, iph->saddr);
  pinfo_s.data.size = 0;
  pinfo_s.data.buf = NULL;
  pinfo_s.src = &l_addr;
  pinfo_s.dest = &client;
  pinfo_s.th_info = &tcp_hinfo;
  pinfo_s.iph_info = &ip_hinfo;
  int len_send = sendPacket (tcp_socket_disconnecter, &pinfo_s);
  if (len_send < 0)
    {
      return -1;
    }
  return 0;
}

/*Принимает TCP и UDP трафик
UDP - весь траффик связанный с подключением/отключением получением данных от
ус-в TCP - траффик на отключение ус-в
*/
void *
getterPackets (void *arg)
{
  (void)arg;
  udp_socket = socket (AF_INET, SOCK_RAW, IPPROTO_UDP);
  if (udp_socket == -1)
    {
      shutdown_flag = 1;
      exit (-1);
    }
  int tcp_socket_disconnecter = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);
  if (tcp_socket_disconnecter == -1)
    {
      shutdown_flag = 1;
      exit (-1);
    }
  int one = 1;
  if (setsockopt (tcp_socket_disconnecter, IPPROTO_IP, IP_HDRINCL, &one,
                  sizeof (one))
      < 0)
    {
      close (tcp_socket_disconnecter);
      shutdown_flag = 1;
      exit (1);
    }

  struct pollfd fds[2];
  fds[0].fd = udp_socket;
  fds[0].events = POLL_IN;
  fds[1].fd = tcp_socket_disconnecter;
  fds[1].events = POLL_IN;

  while (!shutdown_flag)
    {
      if (poll (fds, 2, 20) < 1)
        {
          continue;
        }
      for (int i = 0; i != 2; i++)
        {
          if (i == 0 && fds[i].revents == POLL_IN) /*обработка udp сообщений*/
            {
              getUdpPacket ();
            }
          else if (i == 1 && fds[i].revents == POLL_IN)
            { /*обработка TCP траффика на отключение*/
              getTcpPacketDisconeccted (tcp_socket_disconnecter);
            }
        }
    }
  return 0;
}

void *
stats_writer_thread (void *arg)
{
  (void)arg;
  while (!shutdown_flag)
    {
      lock_udp_devices ();
      lock_tcp_devices ();

      FILE *f = fopen ("log/statistic.info", "w");
      if (f)
        {
          for (int i = 0; i != MAX_DEVICE; i++)
            {
              if (devices_udp[i].is_connected)
                {
                  fprintf (f, "TS %s %.1f\n", devices_udp[i].dev_name,
                           devices_udp[i].temperature);
                }
              if (devices_tcp[i].is_connected)
                {
                  fprintf (f, "LC %s %u\n", devices_tcp[i].dev_name,
                           devices_tcp[i].light_mask);
                }
            }
          fclose (f);
        }
      else
        {
          logg (logfile, "Cannot open statistic.info for writing\n");
        }

      unlock_tcp_devices ();
      unlock_udp_devices ();

      if (buffer_initialized)
        {
          ring_buffer_write_to_file (&log_buffer, logfile);
        }

      for (int i = 0; i < 50 && !shutdown_flag; i++) /*задержка 5 сек*/
        {
          usleep (100000); // 100 ms
        }
    }
  return NULL;
}

void *
monitor_udp_devices (void *arg)
{
  (void)arg;
  while (!shutdown_flag)
    {
      sleep (1);
      time_t now = time (NULL);
      lock_udp_devices ();
      for (int i = 0; i != MAX_DEVICE; i++)
        {
          if (devices_udp[i].is_connected && now - udp_last_receive[i] > 6)
            {
              char log_msg[100];
              snprintf (log_msg, sizeof (log_msg), "TS %s not answering\n",
                        devices_udp[i].dev_name);
              logg (logfile, log_msg);
              devices_udp[i].is_connected = 0;
            }
        }
      unlock_udp_devices ();
    }
  return NULL;
}

void
update_last_receive (struct sockaddr_in client)
{
  lock_udp_devices ();
  for (int i = 0; i != MAX_DEVICE; i++)
    {
      if (devices_udp[i].is_connected
          && memcmp (&devices_udp[i].client, &client,
                     sizeof (struct sockaddr_in))
                 == 0)
        {
          udp_last_receive[i] = time (NULL);
          break;
        }
    }
  unlock_udp_devices ();
}

/*
отправляет команду отключения TCP ус-ву (Light Controller)
в случае успеха возвращает 0
*/
int
sendCCtoTcp (int fd, struct sockaddr_in client)
{
  char command[] = "{\"cmd\": \"CC\", \"type\": \"serv\"}";
  char command_encr[MAX_PACKET_PAYLOAD_SIZE];
  char *send_msg = command;
  if (chooseEncrMsg (command, command_encr, MAX_PACKET_PAYLOAD_SIZE,
                     &send_msg))
    return -1;
  return tcpSend (fd, send_msg, strlen (send_msg), &l_addr, &client, EXIT);
}

/*
отправляет команду отключения UDP ус-ву (Temperature Sensor)
в случае успеха возвращает 0
*/
int
sendCCtoUdp (struct sockaddr_in client)
{
  char command[] = "{\"cmd\": \"CC\", \"type\": \"serv\"}";
  char command_encr[MAX_PACKET_PAYLOAD_SIZE];
  char *send_msg = command;
  if (chooseEncrMsg (command, command_encr, MAX_PACKET_PAYLOAD_SIZE,
                     &send_msg))
    return -1;
  int packet_size = strlen (send_msg) + UDP_HDR_LEN;
  char packet[MAX_PACKET_PAYLOAD_SIZE];
  setDefaultUdp ((struct udphdr *)packet, packet_size,
                 ntohs (client.sin_port));
  memcpy (packet + sizeof (struct udphdr), send_msg, strlen (send_msg) + 1);
  return sendto (udp_socket, packet, packet_size, 0, &client, sizeof (client));
}

/*
Всем ус-вам tcp отсылает сигнал их отключения, закрывает все связанные с ними
сокеты и подключения.
 */
void
disconnectAllTcp ()
{
  lock_tcp_devices ();
  for (int i = 0; i != MAX_DEVICE; i++)
    {
      if (!devices_tcp[i].is_connected)
        continue;
      sendCCtoTcp (devices_tcp[i].tcp_fd, devices_tcp[i].client);
      close (devices_tcp[i].tcp_fd);
      devices_tcp[i].is_connected = 0;
    }
  unlock_tcp_devices ();
}

void
disconnectAllUdp ()
{
  lock_udp_devices ();
  for (int i = 0; i != MAX_DEVICE; i++)
    {
      if (!devices_udp[i].is_connected)
        continue;
      sendCCtoUdp (devices_udp[i].client);
      devices_udp[i].is_connected = 0;
    }
  unlock_udp_devices ();
}

/*Заполняет все глобальные переменные, создаёт сокеты, потоки*/
int
serverInit ()
{
  l_addr.sin_addr.s_addr = inet_addr (SERVER_IP);
  l_addr.sin_port = htons (SERVER_PORT);
  l_addr.sin_family = AF_INET;

  udp_socket = socket (AF_INET, SOCK_RAW, IPPROTO_UDP);
  tcp_socket_sender = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);
  if (tcp_socket_sender == -1)
    {
      return -1;
    }
  int one = 1;
  setsockopt (tcp_socket_sender, IPPROTO_IP, IP_HDRINCL, &one, sizeof (one));
  int flags = fcntl (tcp_socket_sender, F_GETFL);
  if (fcntl (tcp_socket_sender, F_SETFL, flags | O_NONBLOCK) == -1)
    return -1;
  signal (SIGINT, sigHandle);
  pthread_create (&tid_accepter_TCP, NULL, accepterTCP, NULL);
  pthread_create (&tid_handler_udp, NULL, getterPackets, NULL);
  pthread_create (&stats_tid, NULL, stats_writer_thread, NULL);
  pthread_create (&tid_monitor, NULL, monitor_udp_devices, NULL);
  return 0;
}

/*Предоставление пользователю интерфес взаимодействия с системой*/
void
UserInterface ()
{
  write (1, "chose command:\n", 16);
  write (1, "1. Get all TCP devices\n", 24);
  write (1, "2. Get all UDP devices\n", 24);
  write (1, "3. Set light for controller\n", 29);
  write (1, "4. exit\n", 9);
  write (1, "your choiсe: ", 15);
  int choiсe = readFromCons ();
  switch (choiсe)
    {
    case 1:
      write (1, "\n", 1);
      printTCPdevices ();
      write (1, "\n", 1);
      break;
    case 2:
      write (1, "\n", 1);
      printUDPdevices ();
      write (1, "\n", 1);
      break;
    case 3:
      write (1, "\n", 1);
      printTCPdevices ();
      write (1, "choose id: ", 12);
      int id = readFromCons ();
      write (1, "choose num light: ", 19);
      int num = readFromCons ();
      write (1, "on - 1, off - 0: ", 18);
      int is_on = readFromCons ();
      getLightId (id, num, is_on);
      break;
    case 4:
      shutdown_flag = 1;
      break;
    }
}

int
main (int argc, char *argv[])
{
  int opt;
  int a_flag_exist = 0;
  struct in_addr sa;
  while ((opt = getopt (argc, argv, "a:e")) != -1)
    {
      switch (opt)
        {
        case 'e':
          is_enc = 1;
          break;
        case 'a':
          if (inet_pton (AF_INET, optarg, &(sa.s_addr)) <= 0)
            return -1;
          strncpy (SERVER_IP, optarg, strlen (optarg));
          a_flag_exist = 1;
          break;
        case '?':
          logg (logfile, "inncorect arguments\n");
          return -1;
        }
    }
  if (!a_flag_exist)
    {
      logg (logfile, "Need flag -a!\n");
      return -1;
    }
  if (serverInit ())
    {
      logg (logfile, "cannot init server\n");
      return -1;
    }
  while (!shutdown_flag)
    UserInterface ();

  closeServer ();
  return 0;
}

/*отправка клиенту сообщение IM S*/
int
sendDeclare (struct sockaddr_in client)
{
  char im_s_msg[] = "{\"ans\": \"Im S\"}";
  char im_s_msg_enc[MAX_PACKET_PAYLOAD_SIZE];
  char *send_msg = NULL;
  if (chooseEncrMsg (im_s_msg, im_s_msg_enc, MAX_PACKET_PAYLOAD_SIZE,
                     &send_msg))
    return -1;
  size_t size_msg = strlen (send_msg);
  int packet_size = size_msg + UDP_HDR_LEN;
  char packet[MAX_PACKET_PAYLOAD_SIZE];
  setDefaultUdp ((struct udphdr *)packet, packet_size,
                 ntohs (client.sin_port));
  char *ans = packet + sizeof (struct udphdr);
  memcpy (ans, send_msg, strlen (send_msg));
  if (sendto (udp_socket, &packet, packet_size, 0, (struct sockaddr *)&client,
              sizeof (client))
      == -1)
    {
      return -1;
    }
  logg (logfile, "send IM_S\n");
  return 0;
}

/*Проверяет есть ли уже подключенный клиент*/
int
unical_cli (struct sockaddr_in client, proto_type proto)
{
  device_t *devices = NULL;
  if (proto == UDP)
    {
      devices = (device_t *)devices_udp;
    }
  else if (proto == TCP)
    {
      devices = (device_t *)devices_tcp;
    }
  else
    {
      return -1;
    }
  lock_proto_devices (proto);
  int result = 0;
  for (int i = 0; i != MAX_DEVICE; i++)
    {
      if (devices[i].is_connected
          && memcmp (&devices[i].client, &client, sizeof (struct sockaddr_in))
                 == 0)
        {
          unlock_proto_devices (proto);
          result = 1;
          break;
        }
    }
  unlock_proto_devices (proto);
  return result;
}

int
connectionDevice (struct sockaddr_in client, device_type type, char *dev_name,
                  const proto_type proto)
{
  if (unical_cli (client, proto))
    {
      return -1;
    }
  device_t *devices = NULL;
  if (proto == TCP)
    {
      devices = (device_t *)devices_tcp;
    }
  else if (proto == UDP)
    {
      devices = (device_t *)devices_udp;
    }
  else
    {
      return -1;
    }
  lock_proto_devices (proto);
  for (int i = 0; i != MAX_DEVICE; i++)
    {
      if (devices[i].is_connected == 0)
        {
          devices[i].is_connected = 1;
          devices[i].type = type;
          devices[i].client = client;
          devices[i].light_mask = 0;
          devices[i].temperature = -1;

          /*Сохраняем имя устройства для логов*/
          strncpy (devices[i].dev_name, dev_name,
                   sizeof (devices[i].dev_name) - 1);
          snprintf (devices[i].dev_name, sizeof (devices[i].dev_name), "%s",
                    dev_name);
          if (proto == TCP)
            {
              devices[i].tcp_fd = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);
              if (devices[i].tcp_fd == -1)
                {
                  unlock_tcp_devices ();
                  return -1;
                }
              int one = 1;
              setsockopt (devices[i].tcp_fd, IPPROTO_IP, IP_HDRINCL, &one,
                          sizeof (one));
              int flags = fcntl (devices[i].tcp_fd, F_GETFL);
              if (fcntl (devices[i].tcp_fd, F_SETFL, flags | O_NONBLOCK) == -1)
                {
                  unlock_tcp_devices ();
                  return -1;
                }
            }
          char log_msg[100];
          const char *type_str = (type == TS) ? "TS" : "LC";
          snprintf (log_msg, sizeof (log_msg), "connect device %s (%s)\n",
                    dev_name, type_str);
          logg (logfile, log_msg);

          unlock_proto_devices (proto);

          return 0;
        }
    }
  unlock_proto_devices (proto);
  return 1; /*Все занято*/
}

int
disconnectionDevice (struct sockaddr_in client, proto_type proto)
{
  // Ищем устройство по адресу клиента, независимо от его статуса
  // подключения

  device_t *devices = NULL;
  if (proto == UDP)
    {
      devices = (device_t *)devices_udp;
    }
  else if (proto == TCP)
    {
      devices = (device_t *)devices_tcp;
    }
  else
    {
      return -1;
    }
  lock_proto_devices (proto);
  for (int i = 0; i != MAX_DEVICE; i++)
    {
      if (memcmp (&devices[i].client, &client, sizeof (struct sockaddr_in))
          == 0)
        {
          device_type type
              = devices[i].type; // сохраняем тип устройства перед очисткой
          devices[i].is_connected = 0;

          char log_msg[100];
          const char *type_str = (type == TS) ? "TS" : "LC";
          snprintf (log_msg, sizeof (log_msg), "disconnect device %s (%s)\n",
                    devices[i].dev_name, type_str);
          logg (logfile, log_msg);
          unlock_proto_devices (proto);
          return 0;
        }
    }

  char log_msg[100] = "disconnect device (TS) (device not found)\n";
  logg (logfile, log_msg);
  unlock_proto_devices (proto);
  return -1;
}

int
getTypeFromStr (char *str, device_type *type)
{
  if (str == NULL || type == NULL)
    {
      return -1;
    }
  if (!strcmp (LC_MSGS, str))
    {
      *type = LC;
      return 0;
    }
  else if (!strcmp (TS_MSGS, str))
    {
      *type = TS;
      return 0;
    }
  return -1;
}

/*
устанавливает клиенту значение температуры со строки temp
0 - удачно
-1 - неудачно
*/
int
setTemp (struct sockaddr_in client, char *temp)
{
  float temperature = atof (temp);
  lock_udp_devices ();
  /* ищем устройство по адресу клиента*/
  for (int i = 0; i != MAX_DEVICE; i++)
    {
      if (memcmp (&devices_udp[i].client, &client, sizeof (struct sockaddr_in))
          == 0)
        {
          if (!devices_udp[i].is_connected) /*ус-во не подключенно*/
            {
              continue;
            }
          devices_udp[i].temperature = temperature;
          udp_last_receive[i] = time (NULL);

          char log_msg[100];
          snprintf (log_msg, sizeof (log_msg),
                    "get temperature from %s: %.1f\n", devices_udp[i].dev_name,
                    temperature);
          logg (logfile, log_msg);

          if (temperature > 34.5) // температура отключения
            {
              sendAllAccident ();
            }

          unlock_udp_devices ();
          return 0;
        }
    }

  /*если не найдено, создаем временную запись для логирования*/
  char log_msg[100];
  snprintf (log_msg, sizeof (log_msg),
            "get temperature from unregistered device: %.1f\n", temperature);
  logg (logfile, log_msg);
  unlock_udp_devices ();
  return -1;
}

/*Высылает всем подключенным TCP ус-вам accident сигнал, чтобы они отключили
 * свои лампы*/
void
sendAllAccident ()
{
  lock_tcp_devices ();
  for (int i = 0; i != MAX_DEVICE; i++)
    {
      if (!devices_tcp[i].is_connected)
        continue;
      sendAccidentToTcp (devices_tcp[i].tcp_fd, devices_tcp[i].client);
      char rec_msg[MAX_PACKET_PAYLOAD_SIZE];
      int size_rec_msg;
      if ((size_rec_msg
           = tcpRecv (devices_tcp[i].tcp_fd, rec_msg, sizeof (rec_msg),
                      &l_addr, &devices_tcp[i].client))
          < 0)
        {
          devices_tcp[i].is_connected = 0;
          continue;
        }
      char msg_decr[MAX_PACKET_PAYLOAD_SIZE];
      char *json = rec_msg;
      if (chooseDecrypMsg (rec_msg, size_rec_msg, msg_decr,
                           MAX_PACKET_PAYLOAD_SIZE, &json))
        continue;
      if (parse (json))
        {
          logg (logfile, "cannot parse geting info\n");
          devices_tcp[i].is_connected = 0;
          continue;
        }
      unlock_tcp_devices ();
      if (jsonManager (json, devices_tcp[i].client, TCP))
        {
          devices_tcp[i].is_connected = 0;
          continue;
        }
      lock_tcp_devices ();
    }
  unlock_tcp_devices ();
}

int
sendAccidentToTcp (int fd, struct sockaddr_in client)
{
  char command[] = "{\"cmd\": \"accident\"}";
  char command_encr[MAX_PACKET_PAYLOAD_SIZE];
  char *send_msg = NULL;
  if (chooseEncrMsg (command, command_encr, MAX_PACKET_PAYLOAD_SIZE,
                     &send_msg))
    return -1;
  return tcpSend (fd, send_msg, strlen (send_msg), &l_addr, &client, EXIT);
}

int
setLight (struct sockaddr_in client, char *light)
{
  uint32_t light_mask;
  errno = 0;
  char *endptr = NULL;
  unsigned long tmp = strtoul (light, &endptr, 10);
  if (endptr == light || *endptr != '\0' || errno != 0 || tmp > UINT32_MAX)
    {
      char log_msg[128];
      snprintf (log_msg, sizeof (log_msg),
                "getLight: invalid new_state value from client: %s\n", light);
      logg (logfile, log_msg);
      return -1;
    }
  light_mask = (uint32_t)tmp;

  lock_tcp_devices ();
  /* поиск устройства */
  for (int i = 0; i != MAX_DEVICE; i++)
    {
      if (memcmp (&devices_tcp[i].client, &client, sizeof (struct sockaddr_in))
          == 0)
        {
          if (!devices_tcp[i].is_connected)
            {
              continue;
            }
          /* devices_tcp[i].light_mask должен быть uint32_t */
          devices_tcp[i].light_mask = light_mask;

          char log_msg[100];
          snprintf (log_msg, sizeof (log_msg), "get light mask from %s: %u\n",
                    devices_tcp[i].dev_name, light_mask);
          logg (logfile, log_msg);
          unlock_tcp_devices ();
          return 0;
        }
    }

  /*если не найдено, создаем временную запись для логирования*/
  char log_msg[128];
  snprintf (log_msg, sizeof (log_msg),
            "get light mask from unregistered device: %u\n", light_mask);
  logg (logfile, log_msg);
  unlock_tcp_devices ();
  return -1;
}

int
jsonManager (char *json, struct sockaddr_in client, proto_type proto)
{
  if (parse (json))
    {
      return -1;
    }
  char buffer[256];
  if (jGetVal (json, "ask", buffer) == 0)
    {
      if (strcmp (WHO_S_MSG, buffer) == 0)
        { /*обработка сообщение WHO S*/
          if (sendDeclare (client) != 0)
            {
              return -1;
            }
        }
    }
  else if (jGetVal (json, "cmd", buffer) == 0)
    {
      char buff_type[15];
      device_type type;
      if (jGetVal (json, "type", buff_type))
        { /*все пакеты cmd имеют тип читаем его*/
          return -1;
        }
      if (getTypeFromStr (buff_type, &type))
        {
          return -1;
        }

      if (strcmp (PING_MSG, buffer) == 0)
        {
          char dev_name[32];
          if (jGetVal (json, "dev", dev_name) == 0)
            {
              if (unical_cli (client, proto) == 0)
                {
                  connectionDevice (client, type, dev_name, proto);
                }
            }
          // Формируем ответ pong
          char ans_json[64];
          snprintf (ans_json, sizeof (ans_json),
                    "{\"cmd\": \"%s\", \"type\": \"serv\"}", PONG_MSG);

          char ans_enc[128];
          char *send_msg = NULL;
          if (chooseEncrMsg (ans_json, ans_enc, sizeof (ans_enc), &send_msg))
            return -1;
          // Отправляем pong обратно датчику
          int packet_size = strlen (send_msg) + UDP_HDR_LEN;
          char packet[MAX_PACKET_PAYLOAD_SIZE];
          setDefaultUdp ((struct udphdr *)packet, packet_size,
                         ntohs (client.sin_port));
          memcpy (packet + sizeof (struct udphdr), send_msg,
                  strlen (send_msg) + 1);

          if (sendto (udp_socket, packet, packet_size, 0,
                      (struct sockaddr *)&client, sizeof (client))
              == -1)
            {
              logg (logfile, "failed to send pong\n");
              return -1;
            }

          logg (logfile, "send pong to temperature sensor\n");
          if (type == TS)
            {
              update_last_receive (client);
            }
          return 0;
        }

      if (strcmp (C_MSG, buffer) == 0)
        {
          char dev_name[32];
          if (jGetVal (json, "dev", dev_name) != 0)
            {
              return -1; // Устройство должно иметь имя
            }
          connectionDevice (client, type, dev_name, proto);
        }
      else if (strcmp (CC_MSG, buffer) == 0)
        {
          disconnectionDevice (client, proto);
        }
      else if (strcmp (SEND_MSG, buffer) == 0
               || strcmp (RESEND_MSG, buffer) == 0)
        {
          char dev_name[32];
          if (jGetVal (json, "dev", dev_name) == 0)
            {
              if (unical_cli (client, proto) == 0)
                {
                  connectionDevice (client, type, dev_name, proto);
                }
            }
          char val[15];
          if (type == TS)
            {
              if (jGetVal (json, "val", val) == 0)
                {
                  setTemp (client, val);
                  update_last_receive (client);
                }
            }
          else if (type == LC)
            {
              if (jGetVal (json, "new_state", val) == 0)
                {
                  setLight (client, val);
                }
            }
        }
    }
  return 0;
}

void
logg (const char *path, char *str)
{
  if (str == NULL)
    {
      return;
    }
  if (!buffer_initialized)
    {
      init_log_buffer ();
    }

  ring_buffer_push (&log_buffer, str);
  if (path == NULL)
    {
      write (1, str, strlen (str));
      return;
    }
}