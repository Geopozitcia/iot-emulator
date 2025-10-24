#include <arpa/inet.h>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <broadcast.h>
#include <encrypt.h>
#include <jparce.h>
#include <tcp.h>

#define DATA_SIZE 436
#define TOKEN_JSON_SIZE 32
#define BUF_SIZE 16

#define handle_error(msg)                                                     \
  do                                                                          \
    {                                                                         \
      write (STDERR_FILENO, msg, strlen (msg));                               \
      return -1;                                                              \
    }                                                                         \
  while (0)

#define print_message(msg) write (STDOUT_FILENO, msg, strlen (msg))

typedef enum
{
  LIGHT_ON,
  LIGHT_OFF,
  LIGHT_ACCIDENT,
} state_light_t;

typedef enum
{
  SIGINT_DATA_SET,
  SIGINT_DATA_GET,
} sigint_act_t;

/* формирует сообщение формата json. */
static int
buildJson (char *dest, const char *cmd, const char *dev, const char *state)
{
  if (dest == NULL || cmd == NULL || (dev != NULL && state != NULL))
    return -1;
  strcpy (dest, "{\"type\": \"LC\", \"cmd\": \"");
  strcat (dest, cmd);
  strcat (dest, "\"");

  if (dev != NULL)
    {
      strcat (dest, ", \"dev\": \"");
      strcat (dest, dev);
      strcat (dest, "\"");
    }
  if (state != NULL)
    {
      strcat (dest, ", \"status\": \"ok\", \"new_state\": ");
      strcat (dest, state);
    }
  strcat (dest, "}");
  return 0;
}

/* записывает данные для обработки сигнала sigint.
addr[0] хранит локальные данные, addr[1] хранит данные сервера.
SIGINT_DATA_SET берет данные аргументов и сохраняет.
SIGINT_DATA_SET берет сохраненные данные и загружает в аргументы.
Если функция завершилась успешно, то возвращает 0, иначе -1. */
static int
dataHandlerSigintCtl (int *sfd, struct sockaddr_in *addr[2], int *fl_crypt,
                      sigint_act_t act)
{
  if (sfd == NULL || addr[0] == NULL || addr[1] == NULL || fl_crypt == NULL)
    return -1;
  if (*sfd < 0 || *fl_crypt < 0)
    return -1;

  static int sock_fd, flag_crypt;
  static struct sockaddr_in local_addr, server_addr;
  static int flag_init = 0;

  switch (act)
    {
    case SIGINT_DATA_SET:
      if (flag_init)
        return -1;
      memcpy (&local_addr, addr[0], sizeof (struct sockaddr_in));
      memcpy (&server_addr, addr[1], sizeof (struct sockaddr_in));
      sock_fd = *sfd;
      flag_crypt = *fl_crypt;
      flag_init = 1;
      break;
    default:
      if (!flag_init)
        return -1;
      memcpy (addr[0], &local_addr, sizeof (struct sockaddr_in));
      memcpy (addr[1], &server_addr, sizeof (struct sockaddr_in));
      *sfd = sock_fd;
      *fl_crypt = flag_crypt;
      break;
    }
  return 0;
}

/* обрабатывает сигнал sigint и выходит из программы. */
static void
sigintHandler (int sig __attribute__ ((unused)))
{
  print_message ("\nLight controller: exit.\n");

  char data[50];
  char data_encrypt[50];
  char *data_send = data;
  int sfd, fl_crypt;
  struct sockaddr_in addr[2];
  struct sockaddr_in *ptr[2] = { &addr[0], &addr[1] };

  buildJson (data, "CC", NULL, NULL);
  if (dataHandlerSigintCtl (&sfd, ptr, &fl_crypt, SIGINT_DATA_GET) != -1)
    {
      if (fl_crypt)
        {
          Encrypt (data, strlen (data), data_encrypt, DATA_SIZE);
          data_send = data_encrypt;
        }
      if (tcpSend (sfd, data_send, strlen (data_send), &addr[0], &addr[1],
                   EXIT)
          < 0)
        print_message ("Error exit: error sending message to server.\n");
    }
  exit (EXIT_SUCCESS);
}

/* устанавливает состояние светильников. */
static int
setStateLight (long id, state_light_t state, uint32_t *result)
{
  static uint32_t light = 0;

  switch (state)
    {
    case LIGHT_ACCIDENT:
      light = 0;
      break;
    case LIGHT_ON:
    case LIGHT_OFF:
      if (id < 0 || id > 31)
        break;
      switch (state)
        {
        case LIGHT_ON:
          light |= (1 << id);
          break;
        default:
          light &= ~(1 << id);
        }
    }
  *result = light;
  return 0;
}

/* создает неблокирующий raw сокет.
Если ф-я завершилась успешно, то возвращает 0, иначе -1. */
static int
createRawSocket ()
{
  int sfd;
  int one = 1;

  if ((sfd = socket (AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    return -1;
  if (setsockopt (sfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof (one)) == -1)
    return -1;
  int flags = fcntl (sfd, F_GETFL);
  if (fcntl (sfd, F_SETFL, flags | O_NONBLOCK) == -1)
    return -1;
  return sfd;
}

/* заполняет структуру sockaddr_in.
Если произошла ошибка преобразования ip адреса, то возвращает -1, иначе 0. */
static int
fillSockaddrIn (struct sockaddr_in *sin, const char *addr, uint16_t port)
{
  if (sin == NULL || addr == NULL)
    return -1;

  memset (sin, 0, sizeof (struct sockaddr_in));
  sin->sin_port = htons (port);

  if (inet_pton (AF_INET, addr, &sin->sin_addr) <= 0)
    return -1;

  sin->sin_family = AF_INET;
  return 0;
}

/* принимает данные от сервера. От аргумента fl_crypt дешифрует
полученные данные от сервера. Если данные соответствуют json
формату, то данные обрабатываются и выполняются в зависимости от
команды, иначе обрабатывает ошибка и выход контроллера света.  */
static int
handlerLightController (int sfd, char *data[2], struct sockaddr_in *addr[2],
                        int fl_crypt)
{
  if (data == NULL || data[0] == NULL || data[1] == NULL)
    handle_error ("Light controller: buffers are not set.\n");
  if (addr == NULL || addr[0] == NULL || addr[1] == NULL)
    handle_error ("Light controller: addresses not established.\n");

  char value[TOKEN_JSON_SIZE];
  char number[BUF_SIZE];
  char *data_ptr = fl_crypt ? data[1] : data[0];
  uint32_t state_light;
  int retval;

  while (1)
    {
      while ((retval = tcpRecv (sfd, data[0], DATA_SIZE - 1, addr[0], addr[1]))
             < 0)
        {
          if (retval == TCP_EAGAIN)
            continue;
          else
            handle_error ("Light controller: tcpRecv.\n");
        }
      data[0][retval] = '\0';
      if (fl_crypt)
        if (Decrypt (data[0], retval, data[1], DATA_SIZE) == -1)
          handle_error ("Light controller: cannot decrypt message.\n");
      if (jGetVal (data_ptr, "cmd", value) == -1)
        handle_error (
            "Light controller: jGetVal error (handlerLightController).\n");

      print_message ("get data from server: ");
      print_message (data_ptr);
      print_message ("\n");

      if (strcmp (value, "accident") == 0)
        {
          setStateLight (0, LIGHT_ACCIDENT, &state_light);
          sprintf (number, "%u", state_light);
          buildJson (data_ptr, "send", NULL, number);
        }
      else if (strcmp (value, "CC") == 0)
        {
          break;
        }
      else if (strcmp (value, "set_light") == 0)
        {
          long id;
          state_light_t state;

          jGetVal (data_ptr, "id", value);
          id = strtol (value, NULL, 10);
          jGetVal (data_ptr, "state", value);
          if (strcmp (value, "on") == 0)
            state = LIGHT_ON;
          else
            state = LIGHT_OFF;
          setStateLight (id, state, &state_light);
          sprintf (number, "%u", state_light);
          buildJson (data_ptr, "send", NULL, number);
        }
      else
        {
          buildJson (data_ptr, "CC", NULL, NULL);
          if (fl_crypt)
            if (Encrypt (data_ptr, strlen (data_ptr), data[0], DATA_SIZE)
                == -1)
              handle_error ("cannot encr msg");
          tcpSend (sfd, data[0], strlen (data[0]), addr[0], addr[1], EXIT);
          handle_error ("Light controller: recv unknown command.\n");
        }
      if (parse (data_ptr) == -1)
        handle_error ("Light controller: error parse json for send data.\n");

      print_message ("send to server: ");
      print_message (data_ptr);
      print_message ("\n");

      if (fl_crypt)
        if (Encrypt (data_ptr, strlen (data_ptr), data[0], DATA_SIZE) == -1)
          handle_error ("Light controller: cannot encrypt msg\n");
      if (tcpSend (sfd, data[0], strlen (data[0]), addr[0], addr[1], MSG) < 0)
        handle_error ("Light controller: send command to the server.\n");
    }
  print_message ("The server closed the connection.\n");
  return 0;
}

/* запуск контроллера света. Создается сырой сокет, ищется сервер в сети,
выполняется соединение к серверу, сохранение данных для обработки сигнала
sigint. Если произошла ошибка, то возвращается -1 и выводится ошибка, иначе
0.*/
static int
runLightController (const char *argv[2], int fl_crypt)
{
  if (argv == NULL || argv[0] == NULL || argv[1] == NULL || fl_crypt < 0)
    handle_error ("Light controller: error argv is empty.\n");

  char sv_addr[16];
  uint16_t sv_port;

  print_message ("Search server...\n");
  if (recvDataServer (argv[0], sv_addr, &sv_port, fl_crypt) == -1)
    handle_error ("Light controller: error recv data from the server.\n");
  print_message ("Server found!\n");

  int sfd;
  struct sockaddr_in sv, l_addr;
  struct sockaddr_in *addr_ptr[2] = { &l_addr, &sv };
  char data[DATA_SIZE];
  char json[DATA_SIZE];
  char *data_ptr[2] = { data, json };
  char *send_ptr = fl_crypt ? data : json;

  if ((sfd = createRawSocket ()) == -1)
    handle_error ("Light controller: error create raw socket.\n");

  if (fillSockaddrIn (&sv, sv_addr, sv_port) == -1)
    handle_error ("Light controller: error fill sockaddr_in for server.\n");
  srand (time (NULL));
  if (fillSockaddrIn (&l_addr, argv[0], 45000 + rand () % 10000) == -1)
    handle_error (
        "Light controller: error fill sockaddr_in for local addr.\n");

  print_message ("Connect to server...\n");
  if (tcpConnect (sfd, &l_addr, &sv) < 0)
    handle_error ("Light controller: error connection to the server.\n");

  dataHandlerSigintCtl (&sfd, addr_ptr, &fl_crypt, SIGINT_DATA_SET);

  buildJson (json, "C", argv[1], NULL);
  if (parse (json) == -1)
    handle_error ("Light controller: error parse json for connect.\n");

  if (fl_crypt)
    if (Encrypt (json, strlen (json), data, sizeof (data)))
      handle_error ("Light controller: error encrypt msg.\n");
  if (tcpSend (sfd, send_ptr, strlen (send_ptr), &l_addr, &sv, MSG) < 0)
    handle_error (
        "Light controller: error send connect json to the server.\n");
  print_message ("Connect to server success!\n");

  if (handlerLightController (sfd, data_ptr, addr_ptr, fl_crypt) == -1)
    return -1;
  return 0;
}

int
main (int argc, char *argv[])
{
  if (argc != 5 && argc != 6)
    handle_error ("Usage: ./<file_exe> <-a local_addr> <-n dev_name> [-e]\n");

  char *args[2] = { NULL, NULL };
  int opt, fl_crypt = 0;

  while ((opt = getopt (argc, argv, "a:n:e")) != -1)
    {
      switch (opt)
        {
        case 'a':
          args[0] = optarg;
          break;
        case 'n':
          args[1] = optarg;
          break;
        case 'e':
          fl_crypt = 1;
          break;
        default:
          handle_error (
              "Usage: ./<file_exe> <-a local_addr> <-n dev_name> [-e]\n");
        }
    }
  if (args[0] == NULL || args[1] == NULL)
    handle_error ("Usage: ./<file_exe> <-a local_addr> <-n dev_name> [-e]\n");

  print_message ("Light controller: run.\n");

  signal (SIGINT, sigintHandler);

  if (runLightController ((const char **)args, fl_crypt) == -1)
    exit (EXIT_FAILURE);
  exit (EXIT_SUCCESS);
}