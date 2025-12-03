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

#define DHCP_CHADDR_LEN 16
#define DHCP_SNAME_LEN  64
#define DHCP_FILE_LEN   128
#define DHCP_OPTIONS_LEN 312  

// typedef struct {
//     uint8_t Type;
//     uint8_t Lenght;
//     char Value[80];
// } dhcp_option;

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

int get_dhcp_message_type(struct dhcp_packet *dhcp)
{
    int i = 0;

    while (i < 312) {
        uint8_t opt = dhcp->options[i];

        if (opt == 0) { // padding
            i++;
            continue;
        }

        if (opt == 255) { // END
            break;
        }

        uint8_t len = dhcp->options[i+1];

        if (opt == 53 && len == 1) {  // Option 53 = DHCP Message Type
            return dhcp->options[i+2];
        }

        i += 2 + len; // nhảy sang option tiếp theo
    }

    return -1; // không tìm thấy
}

int send_dhcp_reply(pcap_t *handle, const dhcp_packet *pack, uint8_t msg_type,
                    const uint8_t server_mac[6], const uint8_t client_mac[6]) 
{
    uint8_t buffer[1500];
    memset(buffer, 0, sizeof(buffer));

    printf("send_dhcp_reply: Start\n");

    /** ------------------- Ethernet Header ------------------- **/
    struct ether_header *eth = (struct ether_header *)buffer;
    memcpy(eth->ether_dhost, client_mac, 6);
    memcpy(eth->ether_shost, server_mac, 6);
    eth->ether_type = htons(ETHERTYPE_IP);
    printf("send_dhcp_reply: Created ethernet header\n");

    /** ------------------- IP Header ------------------- **/
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ether_header));
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->id = htons(0);
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->saddr = inet_addr(SERVER_IP);
    ip->daddr = htonl(INADDR_BROADCAST);

    uint8_t *udp_start = buffer + sizeof(struct ether_header) + sizeof(struct iphdr);

    /** ------------------- UDP Header ------------------- **/
    struct udphdr *udp = (struct udphdr *)udp_start;
    udp->uh_sport = htons(67);
    udp->uh_dport = htons(68);

    /** ------------------- DHCP Header ------------------- **/
    dhcp_packet *dhcp = (dhcp_packet *)(udp_start + sizeof(struct udphdr));
    dhcp->opcode = 2;     // BOOTREPLY
    dhcp->htype  = 1;     // Ethernet
    dhcp->hlen   = 6;
    dhcp->hops   = 0;
    dhcp->xid    = pack->xid;

    dhcp->yiaddr = inet_addr(OFFER_IP);
    dhcp->siaddr = inet_addr(SERVER_IP);
    memcpy(dhcp->chaddr, pack->chaddr, 16);

    dhcp->magic_cookie = htonl(0x63825363);

    /** ------------------- Build DHCP Options ------------------- **/
    uint8_t *opt = dhcp->options;
    int idx = 0;

    // Option 53: DHCP Message Type
    opt[idx++] = 53;
    opt[idx++] = 1;
    opt[idx++] = msg_type;

    // Option 54: Server Identifier
    uint32_t sip = inet_addr(SERVER_IP);
    opt[idx++] = 54;
    opt[idx++] = 4;
    memcpy(&opt[idx], &sip, 4);
    idx += 4;

    // Option 1: Subnet Mask
    uint32_t mask = inet_addr(SUBNET_MASK);
    opt[idx++] = 1;
    opt[idx++] = 4;
    memcpy(&opt[idx], &mask, 4);
    idx += 4;

    // Option 3: Gateway
    uint32_t gw = inet_addr(SERVER_IP);
    opt[idx++] = 3;
    opt[idx++] = 4;
    memcpy(&opt[idx], &gw, 4);
    idx += 4;

    // Option 51: Lease Time
    uint32_t lt = htonl(LEASE_TIME);
    opt[idx++] = 51;
    opt[idx++] = 4;
    memcpy(&opt[idx], &lt, 4);
    idx += 4;

    // End Option
    opt[idx++] = 255;

    printf("send_dhcp_reply: Created dhcp header\n");

    /** ------------------- Calculate Lengths ------------------- **/
    int dhcp_size = 240 + idx;  // 240 byte fixed + options
    int udp_len   = sizeof(struct udphdr) + dhcp_size;
    int ip_len    = sizeof(struct iphdr) + udp_len;
    int total_len = sizeof(struct ether_header) + ip_len;

    udp->uh_ulen = htons(udp_len);
    ip->tot_len  = htons(ip_len);

    printf("Sending DHCP reply from server: %s, IP offer: %s\n",
           SERVER_IP, OFFER_IP);

    /** ------------------- Send Packet ------------------- **/
    return pcap_sendpacket(handle, buffer, total_len);
}

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    pcap_t *handle = (pcap_t*)user;

    uint8_t Server_MAC[6];
    get_mac("eth0", Server_MAC);

    printf("packet_handler: See a packet\n");

    struct ether_header *eth = (struct ether_header*)bytes;
    if (eth->ether_type != htons(ETHERTYPE_IP)) {
        printf("Packet not have IP header\n");
        return;
    }

    if (memcmp(eth->ether_shost, Server_MAC, 6) == 0) {
        printf("DHCP itself\n");
        return;
    }

    struct iphdr *ip = (struct iphdr*)(bytes + sizeof(struct ether_header));
    if (ip->protocol != IPPROTO_UDP) {
        printf("Packet not have UDP header\n");
        return;
    }

    struct udphdr *udp =
        (struct udphdr*)(bytes + sizeof(struct ether_header) + ip->ihl * 4);

    struct dhcp_packet *dhcp =
        (struct dhcp_packet*)(bytes + sizeof(struct ether_header) + ip->ihl * 4 + sizeof(struct udphdr));

    // Parse DHCP Message Type
    int msg_type = get_dhcp_message_type(dhcp);

    if (msg_type == DHCPDISCOVER) {
        printf("packet_handler: This is DHCP Discover\n");
        send_dhcp_reply(handle, dhcp, DHCPOFFER, Server_MAC, dhcp->chaddr);
        return;
    }

    if (msg_type == DHCPREQUEST) {
        printf("packet_handler: This is DHCP Request\n");
        send_dhcp_reply(handle, dhcp, DHCPACK, Server_MAC, dhcp->chaddr);
        return;
    }

    printf("packet_handler: Unknown DHCP message type\n");
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
    pcap_loop(handle, 0, packet_handler, (u_char*)handle);
    return 0;
}

