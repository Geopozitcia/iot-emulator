#include <netinet/ip.h>
#include <netinet/udp.h>

#include <server.h>

#include "config.h"

/*обрабатывает отделяя все необходимые заголовочники и само сообщение*/
void
getPacketElements (char *packet, struct iphdr **iph, struct udphdr **udph,
                   char **payload)
{
  *iph = (struct iphdr *)packet;
  int iplen = (*iph)->ihl * 4;
  *udph = (struct udphdr *)(packet + iplen);
  *payload = (char *)(packet + iplen + sizeof (struct udphdr));
}
/*заполняет */
void
setDefaultUdp (struct udphdr *udph, int packetSize, int clientPort)
{
  udph->source = htons (SERVER_PORT);
  udph->dest = htons (clientPort);
  udph->check = 0;
  udph->len = htons (packetSize);
}