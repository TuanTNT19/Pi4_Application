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
#define MAGIC_COOKIE   0x63825363

// DHCP Message Types
#define DHCP_DISCOVER   1
#define DHCP_OFFER      2
#define DHCP_REQUEST    3
#define DHCP_ACK        5

typedef struct {
    uint8_t Type;
    uint8_t Lenght;
    char Value[80];
} dhcp_option;

typedef struct 
{
    uint8_t opcode, htype, hlen, hops;
    uint32_t xid;
    uint16_t secs, flags;
    uint32_t ciaddr, yiaddr, siaddr, giaddr;
    uint8_t  chaddr[16];
    uint8_t  sname[64];
    uint8_t  file[128];
    uint32_t magic_cookie;
    dhcp_option  options[312];
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
    uint32_t tmp;

    // Create ethernet header
    struct ether_header *eth = (struct ether_header *)buffer;
    memcpy (eth->ether_dhost, 0xFF, 6);
    memcpy (eth->ether_shost, server_mac, 6);
    eth->ether_type = htons(ETHERTYPE_IP);

    // Create IP header
    struct iphdr *ip = (struct iphdr *) (buffer + sizeof(struct ether_header));
    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = htons (sizeof (struct iphdr) + sizeof (struct udphdr) + 248 + 100);
    ip->protocol = IPPROTO_UDP;
    ip->saddr = inet_addr (SERVER_IP);
    ip->daddr = htonl(INADDR_BROADCAST);

    // Create UDP header
    struct udphdr *udp = (struct udphdr*) (buffer + sizeof (struct ether_header) + ip->ihl * 4);
    udp->uh_dport = htons(68);
    udp->uh_sport = htons(67);
    udp->uh_ulen = htons (sizeof(struct udphdr) + 248 + 100);

    // Create DHCP packet
    dhcp_packet *dhcp = (dhcp_packet *) (buffer + sizeof (struct ether_header) + ip->ihl*4 + sizeof(struct udphdr));
    dhcp->opcode = 2; // BOOTREPLY
    dhcp->htype = 1;
    dhcp->hlen = 6;
    dhcp->hops = 0;
    dhcp->xid = pack->xid;
    dhcp->flags = htons(0x8000);
    memcpy (dhcp->chaddr , pack->chaddr, 16);
    dhcp->yiaddr = inet_addr(OFFER_IP);
    dhcp->siaddr = inet_addr(SERVER_IP);
    dhcp->magic_cookie = htonl(MAGIC_COOKIE);

    dhcp->options[0].Type = 53;
    dhcp->options[0].Lenght = 1;
    dhcp->options[0].Value[0] = msg_type;

    dhcp->options[1].Type = 54;
    dhcp->options[1].Lenght = 4;
    tmp = inet_addr(SERVER_IP);
    memcpy(dhcp->options[1].Value, &tmp, 4);

    dhcp->options[2].Type = 1;
    dhcp->options[2].Lenght = 4;
    tmp = inet_addr(SUBNET_MASK);
    memcpy(dhcp->options[2].Value, &tmp, 4);
    
    dhcp->options[3].Type = 3;
    dhcp->options[3].Lenght = 4;
    tmp = inet_addr(SERVER_IP);
    memcpy(dhcp->options[3].Value, &tmp, 4);

    dhcp->options[4].Type = 51;
    dhcp->options[4].Lenght = 4;
    tmp = htonl(LEASE_TIME);
    memcpy(dhcp->options[4].Value, &tmp, 4);

    dhcp->options[5].Type = 255;
    dhcp->options[5].Lenght = 0;

    int packet_len = sizeof(struct ether_header) + ip->ihl*4 + sizeof (struct udphdr) + 248 + 100;

    printf ("Sending DHCP reply from server: %s, IP offer: %s \n", SERVER_IP, OFFER_IP);
    return pcap_sendpacket(handle, buffer, packet_len);
}

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    pcap_t *handle = (pcap_t*)user;

    uint8_t Server_MAC[6];
    get_mac ("eth0", Server_MAC);

    printf ("packet_handler : See a packet \n");
    struct ether_header *eth = (struct ether_header*) bytes;
    if (eth->ether_type != htons(ETHERTYPE_IP)) {
        printf ("Packet not have IP header\n");
        return ;
    }
    printf ("packet_handler : See a packet with correct ethernet header\n"); 
    if (memcmp(eth->ether_shost, Server_MAC, 6) == 0) {
        printf ("DHCP itself\n");
        return ;
    }

    struct iphdr *ip = (struct iphdr *) (bytes + sizeof(struct ether_header));
    if (ip->protocol != IPPROTO_UDP) {
        printf ("Packet not have UDP header\n");
        return;
    }
    printf ("packet_handler : See a packet with correct ip header\n"); 

    dhcp_packet *dhcp = (dhcp_packet *) (bytes + sizeof(struct ether_header) + ip->ihl*4+ sizeof(struct udphdr));
    for (int i =0; i < 30; i++) {
        if (dhcp->options[i].Type == 53) {
            if (dhcp->options[i].Value[0] == DHCP_DISCOVER) {
                send_dhcp_reply (handle, dhcp, DHCP_OFFER, Server_MAC, dhcp->chaddr);
                printf ("packet_handler: Sent DHCP offer\n");
                break;
            }
            else if (dhcp->options[i].Value[0] == DHCP_REQUEST) {
                send_dhcp_reply (handle, dhcp, DHCP_ACK, Server_MAC, dhcp->chaddr);
                printf ("packet_handler: Sent DHCP ack\n");
                break;
            }
            else {
                printf ("Server not receive any Discover or Request\n");
            }
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("eth0", 65536, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live(%s): %s\n", "eth0", errbuf);
        return 1;
    }

    struct bpf_program fp;
    const char *filter = "udp port 67 or udp port 68";
    if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) < 0) {
        fprintf(stderr, "Lỗi compile filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    if (pcap_setfilter(handle, &fp) < 0) {
        fprintf(stderr, "Lỗi set filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }
    pcap_freecode(&fp); 

    uint8_t mac[6];
    if (get_mac("eth0", mac)) {
        printf("DHCP Server started on eth0 | IP: %s | MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               SERVER_IP, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }    
    printf("Listening for DHCP... (Ctrl+C to stop)\n\n");
    pcap_loop(handle, 0, packet_handler, NULL);
    return 0;
}

