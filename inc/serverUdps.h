#ifndef SERVER_UDPS_H
#define SERVER_UDPS_H

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>

#define UDP_HDR_LEN 8

void getPacketElements (char *packet, struct iphdr **iph, struct udphdr **udph,
                        char **payload);
void setDefaultUdp (struct udphdr *udph, int packetSize, int clientPort);

#endif