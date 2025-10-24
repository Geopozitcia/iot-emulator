#ifndef SERVER_H
#define SERVER_H

#include "devices.h"
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>

#define WHO_S_MSG "WHO S"
#define C_MSG "C"
#define CC_MSG "CC"
#define LC_MSGS "LC"
#define TS_MSGS "TS"
#define SEND_MSG "send"
#define RESEND_MSG "resend"
#define PING_MSG "ping"
#define PONG_MSG "pong"

extern char SERVER_IP[13];

typedef enum proto_type
{
  TCP,
  UDP
} proto_type;

int chooseEncrMsg (char *clear_msg, char *encr_msg, size_t len_encr_msg,
                   char **dst_str);
int chooseDecrypMsg (char *clear_msg, size_t len_clear_msg, char *decr_msg,
                     size_t len_decr_msg, char **dst_str);
int sendDeclare (struct sockaddr_in client);
int unical_cli (struct sockaddr_in client, proto_type proto);
int disconnectionDevice (struct sockaddr_in client, proto_type proto);
int connectionDevice (struct sockaddr_in client, device_type type,
                      char *dev_name, proto_type proto);
int getTypeFromStr (char *str, device_type *type);
int setTemp (struct sockaddr_in client, char *temp);
int jsonManager (char *json, struct sockaddr_in client, proto_type proto);
void logg (const char *path, char *str);
int sendCCtoTcp (int fd, struct sockaddr_in client);
int sendCCtoUdp (struct sockaddr_in client);

void disconnectAllTcp ();
void disconnectAllUdp ();

void sendAllAccident ();
int sendAccidentToTcp (int fd, struct sockaddr_in client);

void UserInterface ();

extern int is_enc;
extern struct sockaddr_in l_addr;
extern pthread_t tid_accepter_TCP, tid_handler_udp, stats_tid, tid_monitor;

#endif