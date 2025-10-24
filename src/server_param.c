#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>

struct sockaddr_in l_addr;
int is_enc = 0;
char SERVER_IP[13];
pthread_t tid_accepter_TCP, tid_handler_udp, stats_tid, tid_monitor;