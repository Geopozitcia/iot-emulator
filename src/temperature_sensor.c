#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <temperature_sensor.h>
#include <time.h>
#include <unistd.h>

#include "encrypt.h"

static int sock = -1;
static struct sockaddr_in server_addr, bc_addr;
static volatile sig_atomic_t shutdown_flag = 0;
static char device_name[32] = "temp1";
int client_port = 0; // 0 - не указан порт, он будет рандомизирован

unsigned short
udp_checksum (const char *buf, size_t len, in_addr_t src_addr,
              in_addr_t dest_addr)
{
  unsigned long sum = 0;
  struct udp_pseudo_header
  {
    in_addr_t src_addr;
    in_addr_t dest_addr;
    unsigned char zero;
    unsigned char protocol;
    unsigned short length;
  } pseudo_header;

  pseudo_header.src_addr = src_addr;
  pseudo_header.dest_addr = dest_addr;
  pseudo_header.zero = 0;
  pseudo_header.protocol = IPPROTO_UDP;
  pseudo_header.length = htons (len);

  unsigned short *ptr = (unsigned short *)&pseudo_header;
  for (size_t i = 0; i < sizeof (pseudo_header) / 2; i++)
    {
      sum += ntohs (ptr[i]);
      if (sum > 0xFFFF)
        {
          sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

  ptr = (unsigned short *)buf;
  while (len > 1)
    {
      sum += ntohs (*ptr++);
      if (sum > 0xFFFF)
        {
          sum = (sum & 0xFFFF) + (sum >> 16);
        }
      len -= 2;
    }

  if (len > 0)
    {
      sum += ntohs ((*(unsigned char *)ptr) << 8);
      if (sum > 0xFFFF)
        {
          sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

  return (unsigned short)(~sum);
}

void
sigint_handler (int sig)
{
  (void)sig;
  shutdown_flag = 1;
}

void
log_message (const char *msg, size_t len)
{
  write (STDERR_FILENO, msg, len);
  write (STDERR_FILENO, "\n", 1);
}

void
build_json (char *buf, const char *cmd, double val)
{
  char temp_str[16];
  if (strcmp (cmd, "send") == 0 || strcmp (cmd, "resend") == 0)
    {
      snprintf (temp_str, sizeof (temp_str), "%.1f", val);
      snprintf (
          buf, BUFFER_SIZE,
          "{\"type\": \"TS\", \"cmd\": \"%s\", \"dev\": \"%s\", \"val\": %s}",
          cmd, device_name, temp_str);
    }
  else
    {
      snprintf (buf, BUFFER_SIZE,
                "{\"type\": \"TS\", \"cmd\": \"%s\", \"dev\": \"%s\"}", cmd,
                device_name);
    }
}

ssize_t
send_udp_packet (const char *data, size_t data_len,
                 struct sockaddr_in *dest_addr)
{
  char packet[BUFFER_SIZE];
  struct udphdr *udph = (struct udphdr *)packet;

  udph->source = htons (client_port);
  udph->dest = htons (SERVER_PORT);
  udph->len = htons (sizeof (struct udphdr) + data_len);
  udph->check = 0;

  memcpy (packet + sizeof (struct udphdr), data, data_len);

  in_addr_t src_ip = INADDR_ANY;
  in_addr_t dst_ip = dest_addr->sin_addr.s_addr;
  udph->check = udp_checksum (packet, sizeof (struct udphdr) + data_len,
                              src_ip, dst_ip);

  return sendto (sock, packet, sizeof (struct udphdr) + data_len, 0,
                 (struct sockaddr *)dest_addr, sizeof (*dest_addr));
}

void
send_connect ()
{
  char json_buf[BUFFER_SIZE];
  char buf_enc[BUFFER_SIZE];
  build_json (json_buf, "C", 0.0);
  char *send_msg = json_buf;
  if (is_enc)
    {
      if (Encrypt (json_buf, strlen (json_buf), buf_enc, sizeof (buf_enc)))
        {
          log_message ("cannot enc msg", 15);
          return;
        }
      send_msg = buf_enc;
    }
  ssize_t sent = send_udp_packet (send_msg, strlen (send_msg), &server_addr);
  if (sent >= 0)
    {
      log_message (json_buf, strlen (json_buf));
    }
}

void
send_disconnect ()
{
  char json_buf[BUFFER_SIZE];
  build_json (json_buf, "CC", 0.0);
  char buff_enc[BUFFER_SIZE];
  char *send_msg = json_buf;
  size_t msg_len = strlen (json_buf);
  if (is_enc)
    {
      if (Encrypt (json_buf, strlen (json_buf), buff_enc, sizeof (buff_enc)))
        {
          log_message ("cannot encrypt msg", 19);
          return;
        }
      send_msg = buff_enc;
      msg_len = strlen (buff_enc);
    }
  ssize_t sent = send_udp_packet (send_msg, msg_len, &server_addr);
  if (sent >= 0)
    {
      log_message (json_buf, strlen (json_buf));
      log_message ("Sent disconnect", 14);
    }
}

void
send_ping ()
{
  char json_buf[BUFFER_SIZE];
  char buf_enc[BUFFER_SIZE];

  snprintf (json_buf, sizeof (json_buf),
            "{\"type\": \"TS\", \"cmd\": \"ping\", \"dev\": \"%s\"}",
            device_name);

  char *send_msg = json_buf;
  size_t msg_len = strlen (json_buf);

  if (is_enc)
    {
      if (Encrypt (json_buf, msg_len, buf_enc, sizeof (buf_enc)))
        {
          log_message ("cannot enc ping msg", 20);
          return;
        }
      send_msg = buf_enc;
      msg_len = strlen (buf_enc);
    }

  ssize_t sent = send_udp_packet (send_msg, msg_len, &server_addr);
  if (sent >= 0)
    {
      log_message ("Ping sent to server", 18);
    }
}

static volatile sig_atomic_t received_pong = 0;

void *
listener_thread (void *arg)
{
  (void)arg;
  char recv_buf[BUFFER_SIZE];
  struct sockaddr_in from_addr;
  socklen_t from_len = sizeof (from_addr);

  while (!shutdown_flag)
    {
      struct timeval tv = { 1, 0 }; // Timeout for recvfrom
      setsockopt (sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof (tv));

      ssize_t recv_len = recvfrom (sock, recv_buf, BUFFER_SIZE, 0,
                                   (struct sockaddr *)&from_addr, &from_len);
      if (recv_len <= 0)
        continue;

      struct iphdr *iph = (struct iphdr *)recv_buf;
      size_t ip_header_len = iph->ihl * 4;
      if (recv_len < ip_header_len + sizeof (struct udphdr))
        continue;

      struct udphdr *udph = (struct udphdr *)(recv_buf + ip_header_len);
      char *payload = recv_buf + ip_header_len + sizeof (struct udphdr);
      size_t payload_len = recv_len - ip_header_len - sizeof (struct udphdr);

      if (htons (udph->source) != SERVER_PORT)
        continue;

      payload[payload_len] = '\0';

      char decrypted[BUFFER_SIZE];
      char *json = payload;
      if (is_enc)
        {
          if (Decrypt (payload, payload_len, decrypted, sizeof (decrypted))
              == 0)
            {
              json = decrypted;
            }
        }

      if (strstr (json, "\"cmd\": \"CC\""))
        {
          log_message ("Received CC from server", 25);
          shutdown_flag = 1;
          break;
        }

      if (strstr (json, "\"cmd\": \"pong\""))
        {
          received_pong = 1;
          log_message ("Received pong from server", 26);
          continue;
        }
    }

  return NULL;
}

int
find_server ()
{
  char who_server[] = "{\"ask\": \"WHO S\"}";
  char encrypted_who_server[25];
  int retries = 0;
  char *msg_for_send = who_server;
  if (is_enc)
    {
      if (Encrypt (who_server, strlen (who_server) + 1, encrypted_who_server,
                   sizeof (encrypted_who_server)))
        {
          log_message ("Cannot encrypt msg", 18);
          return -1;
        }
      msg_for_send = encrypted_who_server;
    }
  int len_msg = strlen (msg_for_send);

  while (retries < 5 && !shutdown_flag)
    {
      ssize_t sent = send_udp_packet (msg_for_send, len_msg, &bc_addr);
      if (sent < 0)
        {
          log_message ("Broadcast send failed", 19);
          sleep (RETRY_DELAY);
          retries++;
          continue;
        }
      log_message (who_server, strlen (who_server));

      char recv_buf[BUFFER_SIZE];
      struct sockaddr_in from_addr;
      socklen_t from_len = sizeof (from_addr);

      struct timeval tv = { 2, 0 };
      setsockopt (sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof (tv));

      ssize_t recv_len = recvfrom (sock, recv_buf, BUFFER_SIZE, 0,
                                   (struct sockaddr *)&from_addr, &from_len);

      if (recv_len > 0)
        {
          struct iphdr *iph = (struct iphdr *)recv_buf;
          size_t ip_header_len = iph->ihl * 4;

          if (ip_header_len + sizeof (struct udphdr) > (size_t)recv_len)
            {
              continue;
            }

          struct udphdr *udph = (struct udphdr *)(recv_buf + ip_header_len);
          char *payload = recv_buf + ip_header_len + sizeof (struct udphdr);
          size_t payload_len
              = recv_len - ip_header_len - sizeof (struct udphdr);

          if (payload_len > 0 && htons (udph->source) == SERVER_PORT)
            {
              payload[payload_len] = '\0';
              char payload_decrypt[BUFFER_SIZE];
              char *rec_data = payload;
              if (is_enc)
                {
                  if (Decrypt (payload, payload_len, payload_decrypt,
                               BUFFER_SIZE))
                    {
                      log_message ("Cannot dcrypt msg", 18);
                      continue;
                    }
                  rec_data = payload_decrypt;
                }
              if (strstr (rec_data, "{\"ans\": \"Im S\"}") != NULL)
                {
                  server_addr = from_addr;
                  server_addr.sin_port = htons (SERVER_PORT);

                  char port_msg[50];
                  snprintf (port_msg, sizeof (port_msg),
                            "Server found on port %d",
                            ntohs (server_addr.sin_port));
                  log_message (port_msg, strlen (port_msg));
                  return 0;
                }
            }
        }
      retries++;
      sleep (RETRY_DELAY);
    }

  log_message ("Server search failed", 19);
  return -1;
}

int
main (int argc, char *argv[])
{
  srand (time (NULL) + getpid ());

  if (argc > 1)
    {
      int opt;
      while ((opt = getopt (argc, argv, "n:ep:")) != -1)
        {
          switch (opt)
            {
            case 'n':
              strncpy (device_name, optarg, strlen (optarg) + 1);
              break;
            case 'e':
              is_enc = 1;
              break;
            case 'p':
              client_port = atoi (optarg);
              if (client_port < 1024 || client_port > 65535)
                {
                  log_message ("Invalid port (must be 1024-65535)", 33);
                  return 1;
                }
              break;
            case '?':
              log_message ("неизвестная опция", 34);
              break;
            }
        }
    }

  if (client_port == 0)
    {
      client_port = 1025 + rand () % (65535 - 1025 + 1);
    }

  char port_log[50];
  snprintf (port_log, sizeof (port_log), "Using client port: %d", client_port);
  log_message (port_log, strlen (port_log));

  signal (SIGINT, sigint_handler);

  sock = socket (AF_INET, SOCK_RAW, IPPROTO_UDP);
  if (sock < 0)
    {
      log_message ("Raw socket creation failed (need root?)", 33);
      return 1;
    }

  struct sockaddr_in client_addr;
  memset (&client_addr, 0, sizeof (client_addr));
  client_addr.sin_family = AF_INET;
  client_addr.sin_port = htons (client_port);
  client_addr.sin_addr.s_addr = INADDR_ANY;

  if (bind (sock, (struct sockaddr *)&client_addr, sizeof (client_addr)) < 0)
    {
      log_message ("Bind failed", 10);
      close (sock);
      return 1;
    }

  int broadcast = 1;
  setsockopt (sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof (broadcast));

  memset (&bc_addr, 0, sizeof (bc_addr));
  bc_addr.sin_family = AF_INET;
  bc_addr.sin_port = htons (SERVER_PORT);
  inet_pton (AF_INET, BROADCAST_ADDR, &bc_addr.sin_addr);

  while (find_server () < 0 && !shutdown_flag)
    {
      sleep (RETRY_DELAY);
    }

  if (shutdown_flag)
    {
      close (sock);
      return 0;
    }

  send_connect ();

  pthread_t tid;
  pthread_create (&tid, NULL, listener_thread, NULL);
  pthread_detach (tid);

  static double buffered_temps[10];
  int buffer_count = 0;
  int packet_counter = 0;
  time_t last_pong_time = time (NULL);
  bool server_available = true;

  // Основной цикл
  while (!shutdown_flag)
    {
      double temp
          = TEMP_MIN + (double)rand () / RAND_MAX * (TEMP_MAX - TEMP_MIN);

      struct timespec ts_delay = { 0, SEND_DELAY_MS };
      nanosleep (&ts_delay, NULL);

      packet_counter++;
      if (packet_counter >= 5) // Пинг каждые 5 пакетов
        {
          received_pong = 0;
          send_ping ();
          time_t start = time (NULL);
          while (difftime (time (NULL), start) < 1.0 && !received_pong
                 && !shutdown_flag)
            {
              usleep (100000); // 0.1 сек
            }

          if (received_pong)
            {
              server_available = true;
              last_pong_time = time (NULL);
            }
          else
            {
              server_available = false;
              if (difftime (time (NULL), last_pong_time) >= 10)
                {
                  log_message (
                      "Server unreachable for 10 seconds, shutting down", 46);
                  shutdown_flag = 1;
                  break;
                }
            }
          packet_counter = 0;
        }

      if (server_available)
        {
          // Сервер доступен, отправляем текущий пакет
          char json_buf[BUFFER_SIZE];
          char buff_enc[BUFFER_SIZE];
          build_json (json_buf, "send", temp);
          log_message (json_buf, strlen (json_buf));

          char *send_msg = json_buf;
          size_t msg_len = strlen (json_buf);
          if (is_enc)
            {
              if (Encrypt (json_buf, msg_len, buff_enc, sizeof (buff_enc)))
                {
                  log_message ("cannot encrypt msg", 18);
                  continue;
                }
              send_msg = buff_enc;
              msg_len = strlen (buff_enc);
            }

          ssize_t sent = send_udp_packet (send_msg, msg_len, &server_addr);
          if (sent < 0)
            {
              log_message ("Send failed, buffering packet", 28);
              if (buffer_count < 10)
                {
                  buffered_temps[buffer_count++] = temp;
                }
              else
                {
                  log_message ("Buffer overflow, discarding packet", 34);
                }
            }

          if (buffer_count > 0)
            {
              for (int i = 0; i < buffer_count; i++)
                {
                  build_json (json_buf, "resend", buffered_temps[i]);
                  log_message (json_buf, strlen (json_buf));

                  char *resend_msg = json_buf;
                  size_t resend_len = strlen (json_buf);
                  if (is_enc)
                    {
                      if (Encrypt (json_buf, resend_len, buff_enc,
                                   sizeof (buff_enc)))
                        {
                          log_message ("cannot encrypt resend msg", 24);
                          continue;
                        }
                      resend_msg = buff_enc;
                      resend_len = strlen (buff_enc);
                    }

                  sent
                      = send_udp_packet (resend_msg, resend_len, &server_addr);
                  if (sent < 0)
                    {
                      log_message ("Resend failed", 13);
                      // Оставляем пакет в буфере
                      memmove (buffered_temps, buffered_temps + i,
                               (buffer_count - i) * sizeof (double));
                      buffer_count -= i;
                      break;
                    }
                }
              if (sent >= 0)
                {
                  buffer_count = 0; // Очищаем буфер после успешной отправки
                }
            }
        }
      else
        {
          // Сервер недоступен, буферизуем пакет
          if (buffer_count < 10)
            {
              buffered_temps[buffer_count++] = temp;
              char log_buf[50];
              snprintf (log_buf, sizeof (log_buf),
                        "Server unavailable, buffering temp %.1f", temp);
              log_message (log_buf, strlen (log_buf));
            }
          else
            {
              log_message ("Buffer overflow, discarding packet", 34);
            }

          // Проверяем сервер каждые 2 пакета
          if (buffer_count >= 2)
            {
              received_pong = 0;
              send_ping ();
              time_t start = time (NULL);
              while (difftime (time (NULL), start) < 1.0 && !received_pong
                     && !shutdown_flag)
                {
                  usleep (100000);
                }

              if (received_pong)
                {
                  server_available = true;
                  last_pong_time = time (NULL);
                  // Отправляем все буферизованные пакеты
                  for (int i = 0; i < buffer_count; i++)
                    {
                      char json_buf[BUFFER_SIZE];
                      char buff_enc[BUFFER_SIZE];
                      build_json (json_buf, "resend", buffered_temps[i]);
                      log_message (json_buf, strlen (json_buf));

                      char *resend_msg = json_buf;
                      size_t resend_len = strlen (json_buf);
                      if (is_enc)
                        {
                          if (Encrypt (json_buf, resend_len, buff_enc,
                                       sizeof (buff_enc)))
                            {
                              log_message ("cannot encrypt resend msg", 24);
                              continue;
                            }
                          resend_msg = buff_enc;
                          resend_len = strlen (buff_enc);
                        }

                      ssize_t sent = send_udp_packet (resend_msg, resend_len,
                                                      &server_addr);
                      if (sent < 0)
                        {
                          log_message ("Resend failed", 13);
                          memmove (buffered_temps, buffered_temps + i,
                                   (buffer_count - i) * sizeof (double));
                          buffer_count -= i;
                          break;
                        }
                    }
                  if (send >= 0)
                    {
                      buffer_count
                          = 0; // Очищаем буфер после успешной отправки
                    }
                }
            }
        }

      sleep (1);
    }

  send_disconnect ();
  close (sock);
  return 0;
}