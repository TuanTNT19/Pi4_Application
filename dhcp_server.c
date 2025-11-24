#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define SERVER_IP      "192.168.10.1"
#define OFFER_IP       "192.168.10.100"
#define SUBNET_MASK    "255.255.255.0"
#define LEASE_TIME     86400
#define MAGIC_COOKIE   0x08122002

// DHCP Message Types
#define DHCP_DISCOVER   1
#define DHCP_OFFER      2
#define DHCP_REQUEST    3
#define DHCP_ACK        5

typedef struct 
{
    uint8_t opcode, htype, hlen, hops;
    uint32_t xid;
    uint16_t secs, flags;
    uint32_t ciaddr, yiaddr, siaddr, chaddr;
    uint8_t  chaddr[16];
    uint8_t  sname[64];
    uint8_t  file[128];
    uint8_t  options[312];
} dhcp_packet;

int get_mac (const char *iface, uint8_t mac[6]) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, iface, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        printf("Can not get mac \n");
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close (sock);
    return 1;
}

int send_dhcp_reply (pcap_t *handle, const dhcp_packet* pack, uint8_t msg_type, const uint8_t server_mac[6], const uint8_t client_mac[6]) {
    uint8_t buffer[1500];
    memset(buffer, 0, sizeof(buffer));

    // Create ethernet header
    struct ether_header *eth = (struct ether_header *)buffer;
    memcpy (eth->ether_dhost, client_mac, 6);
    memcpy (eth->ether_shost, server_mac, 6);
    eth->ether_type = htons(ETHERTYPE_IP);

    // Create IP header
    struct iphdr *ip = (struct iphdr *) (buffer + sizeof(struct ether_header));
    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = htons (sizeof (struct iphdr) + sizeof (struct udphdr) + 240 + 100);
    ip->protocol = IPPROTO_UDP;
    ip->saddr = SERVER_IP;
    ip->saddr = inet_addr (SERVER_IP);
    ip->daddr = htonl(INADDR_BROADCAST);

    // Create UDP header
    struct udphdr *udp = (struct udphdr*) (packet + sizeof (struct ether_header) + sizeof (struct iphdr));
    udp->uh_dport = htons(68);
    udp->uh_sport = htons(67);
    udp->len = htons (sizeof(struct udphdr) + 240 + 100);

    // Create DHCP packet
    dhcp_packet *dhcp = (dhcp_packet *) (packet + sizeof (struct ether_header) + sizeof (struct iphdr) + sizeof(struct udphdr));
    dhcp->opcode = 2; // BOOTREPLY
    dhcp->htype = 1;
    dhcp->hlen = 6;
    dhcp->hops = 64;
    dhcp->xid = pack->xid;
    memcpy (dhcp->chaddr , pack->chaddr, 16);
    dhcp->ciaddr = inet_addr(OFFER_IP);
    dhcp->siaddr = inet_addr(SERVER_IP);

}

