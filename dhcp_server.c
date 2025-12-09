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

#define SERVER_IP       "192.168.10.1"
#define OFFER_IP        "192.168.10.120"
#define SUBNET_MASK     "255.255.255.0"
#define LEASE_TIME      86400
#define MAGIC_COOKIE    0x63825363
#define DHCP_OPTIONS_LENGTH 312

// DHCP Message Types
#define DHCP_DISCOVER   1
#define DHCP_OFFER      2
#define DHCP_REQUEST    3
#define DHCP_ACK        5

typedef struct {
    uint8_t opcode, htype, hlen, hcount;
    uint32_t xid;
    uint16_t secs, flags;
    uint32_t ciaddr, yiaddr, siaddr, giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint32_t magic_cookie;
    uint8_t options[DHCP_OPTIONS_LENGTH];
} dhcp_packet;

uint32_t ip_offer_gen(const char *dhcp_server_ip)
{
    struct in_addr addr;
    inet_aton(dhcp_server_ip, &addr);

    uint32_t ip = ntohl(addr.s_addr);

    uint8_t a = (ip >> 24) & 0xFF;
    uint8_t b = (ip >> 16) & 0xFF;
    uint8_t c = (ip >> 8)  & 0xFF;

    // random host part: 2 → 254
    uint8_t host = (rand() % 253) + 2;   // 2..254

    uint32_t offer_ip = (a << 24) | (b << 16) | (c << 8) | host;

    return htonl(offer_ip);  // trả về dạng network byte order
}

uint8_t get_dhcp_message_type (dhcp_packet *dhcp) {
    uint8_t index = 0;
    uint8_t dhcp_message_code = 0;
    uint8_t len = 0;
    while (index < DHCP_OPTIONS_LENGTH) {
        dhcp_message_code = dhcp->options[index];
        len = dhcp->options[index + 1];
        if (dhcp_message_code == 53 && len == 1) {
            return dhcp->options[index + 2];
        }
        index += (2 + len);
    }
    return -1;
}

int get_mac (char *iface, uint8_t mac[6]) {
    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ);
    int fd = socket (AF_INET, SOCK_DGRAM, 0);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        printf ("Can not get interface MAC\n");
        return -1;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close (fd);
    return 1;
}


uint16_t checksum(uint16_t *buf, int len)
{
    uint32_t sum = 0;
    while (len > 0) {
        sum += *buf++;
        len--;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

int dhcp_send_reply(pcap_t *handle, dhcp_packet *req, uint8_t dhcp_message_type, uint8_t server_mac[6], uint8_t client_mac[6]) {
    uint8_t buffer[1500];
    memset(buffer, 0, sizeof(buffer));

    /* Create Ethernet header */
    struct ether_header *eth = (struct ether_header*)buffer;
    memcpy(eth->ether_dhost, client_mac, 6);
    memcpy(eth->ether_shost, server_mac, 6);
    eth->ether_type = htons(ETHERTYPE_IP);

    /* Create IP header */
    struct iphdr *ip = (struct iphdr*) (buffer + sizeof(struct ether_header));
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->saddr = inet_addr (SERVER_IP);
    ip->daddr =  htonl(INADDR_BROADCAST);
    ip->check = checksum((uint16_t*)ip, sizeof(struct iphdr)/2);

    /* Create UDP header */
    struct udphdr* udp = (struct udphdr*) (buffer + sizeof(struct ether_header) + ip->ihl*4);
    udp->uh_dport = htons(68);
    udp->uh_sport = htons(67);

    /* Create dhcp packet */
    dhcp_packet *dhcp = (dhcp_packet *) (buffer + sizeof(struct ether_header) + ip->ihl*4 + sizeof(struct udphdr));
    dhcp->opcode = 2; // BOOTREPLY
    dhcp->htype = 1; // Ethernet
    dhcp->hlen = 6;
    dhcp->xid = req->xid;
    dhcp->yiaddr = htonl (ip_offer_gen(SERVER_IP));
    dhcp->siaddr = inet_addr (SERVER_IP);
    memcpy(dhcp->chaddr, req->chaddr, 16);
    dhcp->magic_cookie = htonl (MAGIC_COOKIE);
        /* Create dhcp options */
    int index = 0;
    dhcp->options[index++] = 53; // message type
    dhcp->options[index++] = 1;
    dhcp->options[index++] = dhcp_message_type;
    dhcp->options[index++] = 54; // Server Identifier
    dhcp->options[index++] = 4;
    uint32_t ip_server = inet_addr(SERVER_IP);
    memcpy(&dhcp->options[index], &ip_server, 4);
    index +=4;
    dhcp->options[index++] = 1; // Subnet Mask
    dhcp->options[index++] = 4;
    uint32_t mask = inet_addr(SUBNET_MASK);
    memcpy(&dhcp->options[index], &mask, 4);
    index +=4;
    dhcp->options[index++] = 3; // Router
    dhcp->options[index++] = 4;
    uint32_t ip_gw = inet_addr(SERVER_IP);
    memcpy(&dhcp->options[index], &ip_gw, 4);
    index +=4;
    dhcp->options[index++] = 51; // Lease time
    dhcp->options[index++] = 4;
    uint32_t lease_time = htonl(LEASE_TIME);
    memcpy(&dhcp->options, &lease_time, 4);
    index +=4;
    dhcp->options[index++] = 255;

    int dhcp_size = 240 + index;
    udp->uh_ulen = htons(sizeof(struct udphdr) + dhcp_size);
    ip->tot_len = htons(ip->ihl*4 + sizeof(struct udphdr) + dhcp_size);
    int total_len = sizeof(struct ether_header) + ip->ihl*4 + sizeof(struct udphdr) + dhcp_size;

    return pcap_sendpacket(handle, buffer, total_len);
}

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    pcap_t *handle = (pcap_t*)user;
    uint8_t server_mac[6];
    get_mac("eth0", server_mac);
    printf("packet_handler: Start\n");

    struct ether_header *eth = (struct ether_header*)bytes;
    if (eth->ether_type != htons(ETHERTYPE_IP)) {
        return ;
    }
    if (memcmp(eth->ether_shost, server_mac, 6) == 0) {
        printf("DHCP itself\n");
        return;
    }
    printf("packet_handler: Got ethernet header\n");
    struct iphdr *ip = (struct iphdr *)(bytes + sizeof(struct ether_header));
    if (ip->protocol != IPPROTO_UDP) {
        return ;
    }

    printf("packet_handler: Got IP header\n");
    dhcp_packet *dhcp = (dhcp_packet *)(bytes + sizeof(struct ether_header) + ip->ihl*4 + sizeof(struct udphdr));
    uint8_t dhcp_option_message_type = get_dhcp_message_type(dhcp);
    if (dhcp_option_message_type == DHCP_DISCOVER) {
        dhcp_send_reply(handle, dhcp, DHCP_OFFER, server_mac, dhcp->chaddr);
        printf("packet_handler: Sent DHCP Offer\n");
    }
    else if (dhcp_option_message_type == DHCP_REQUEST) {
        dhcp_send_reply(handle, dhcp, DHCP_ACK, server_mac, dhcp->chaddr);
        printf("packet_handler: Sent DHCP ACK\n");
    }
    else {
        return ;
    }
}

int main()
{
    char err[256];
    pcap_t *handle = pcap_open_live("eth0", 65536, 1, 1000, err);
    if (!handle) {
        printf("pcap_open: %s\n", err);
        return 1;
    }

    struct bpf_program fp;
    pcap_compile(handle, &fp, "udp port 67 or udp port 68", 0, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handle, &fp);
    pcap_freecode(&fp);

    uint8_t mac[6];
    get_mac("eth0", mac);

    printf("DHCP Server started (%02X:%02X:%02X:%02X:%02X:%02X)\n",
        mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

    pcap_loop(handle, 0, packet_handler, (u_char*)handle);
    return 0;
}