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
#define DHCP_OPTIONS_LEN 312  

typedef struct {
    uint8_t opcode, htype, hlen, hops;
    uint32_t xid;
    uint16_t secs, flags;
    uint32_t ciaddr, yiaddr, siaddr, giaddr;
    uint8_t  chaddr[16];
    uint8_t  sname[64];
    uint8_t  file[128];
    uint32_t magic_cookie;
    uint8_t  options[DHCP_OPTIONS_LEN];
} dhcp_packet;

/************************************************************
 *                     CHECKSUM
 ***********************************************************/
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

/************************************************************
 *                     GET MAC
 ***********************************************************/
int get_mac(const char *iface, uint8_t mac[6])
{
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, iface, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("Can not get mac");
        close(sock);
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
    return 0;
}

/************************************************************
 *             PARSE DHCP MESSAGE TYPE (OPTION 53)
 ***********************************************************/
int get_dhcp_message_type(dhcp_packet *dhcp)
{
    int i = 0;
    while (i < DHCP_OPTIONS_LEN) {
        uint8_t code = dhcp->options[i];
        uint8_t len = dhcp->options[i+1];
        if (code == 53 && len == 1) {
            return dhcp->options[i+2];
        }
        i += (2 + len);
    }
    return -1;
}

/************************************************************
 *                SEND DHCP OFFER / ACK
 ***********************************************************/
int send_dhcp_reply(pcap_t *handle, const dhcp_packet *req,
                    uint8_t msg_type, const uint8_t server_mac[6], const uint8_t client_mac[6])
{
    uint8_t buffer[1500];
    memset(buffer, 0, sizeof(buffer));

    struct ether_header *eth = (struct ether_header*)buffer;
    struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ether_header));
    struct udphdr *udp =
        (struct udphdr*)(buffer + sizeof(struct ether_header) + sizeof(struct iphdr));
    dhcp_packet *dhcp =
        (dhcp_packet*)((uint8_t*)udp + sizeof(struct udphdr));

    /******************** ETHERNET ********************/
    memcpy(eth->ether_dhost, client_mac, 6);  // broadcast
    memcpy(eth->ether_shost, server_mac, 6);
    eth->ether_type = htons(ETHERTYPE_IP);

    /******************** IP HEADER ********************/
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->id = htons(0);
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->saddr = inet_addr(SERVER_IP);
    ip->daddr = htonl(INADDR_BROADCAST);

    /******************** UDP HEADER ********************/
    udp->uh_sport = htons(67);
    udp->uh_dport = htons(68);

    /******************** DHCP HEADER ********************/
    dhcp->opcode = 2;
    dhcp->htype = 1;
    dhcp->hlen = 6;
    dhcp->xid = req->xid;
    dhcp->yiaddr = inet_addr(OFFER_IP);
    dhcp->siaddr = inet_addr(SERVER_IP);
    memcpy(dhcp->chaddr, req->chaddr, 16);
    dhcp->magic_cookie = htonl(0x63825363);

    /******************** BUILD OPTIONS ********************/
    uint8_t *opt = dhcp->options;
    int idx = 0;

    // DHCP message type
    opt[idx++] = 53;
    opt[idx++] = 1;
    opt[idx++] = msg_type;

    // Server identifier
    uint32_t sip = inet_addr(SERVER_IP);
    opt[idx++] = 54;
    opt[idx++] = 4;
    memcpy(&opt[idx], &sip, 4);
    idx += 4;

    // Subnet mask
    uint32_t mask = inet_addr(SUBNET_MASK);
    opt[idx++] = 1;
    opt[idx++] = 4;
    memcpy(&opt[idx], &mask, 4);
    idx += 4;

    // Router
    uint32_t gw = inet_addr(SERVER_IP);
    opt[idx++] = 3;
    opt[idx++] = 4;
    memcpy(&opt[idx], &gw, 4);
    idx += 4;

    // Lease time
    uint32_t lt = htonl(LEASE_TIME);
    opt[idx++] = 51;
    opt[idx++] = 4;
    memcpy(&opt[idx], &lt, 4);
    idx += 4;

    opt[idx++] = 255;

    int dhcp_size = 240 + idx;
    int udp_len = sizeof(struct udphdr) + dhcp_size;
    int ip_len = ip->ihl*4 + udp_len;
    int total_len = sizeof(struct ether_header) + ip_len;

    udp->uh_ulen = htons(udp_len);
    ip->tot_len = htons(ip_len);

    // /******************** IP CHECKSUM ********************/
    // ip->check = 0;
    // ip->check = checksum((uint16_t*)ip, sizeof(struct iphdr)/2);

    // /******************** UDP CHECKSUM ********************/
    // struct {
    //     uint32_t src, dst;
    //     uint8_t zero;
    //     uint8_t proto;
    //     uint16_t len;
    // } pseudo;

    // pseudo.src = ip->saddr;
    // pseudo.dst = ip->daddr;
    // pseudo.zero = 0;
    // pseudo.proto = IPPROTO_UDP;
    // pseudo.len = udp->uh_ulen;

    // int pseudo_len = sizeof(pseudo) + udp_len;
    // uint8_t *pseudo_buf = malloc(pseudo_len);

    // memcpy(pseudo_buf, &pseudo, sizeof(pseudo));
    // memcpy(pseudo_buf + sizeof(pseudo), udp, udp_len);

    // udp->uh_sum = checksum((uint16_t*)pseudo_buf, pseudo_len/2);
    // free(pseudo_buf);

    return pcap_sendpacket(handle, buffer, total_len);
}

/************************************************************
 *                     PACKET HANDLER
 ***********************************************************/
void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    pcap_t *handle = (pcap_t*)user;
    uint8_t server_mac[6];
    get_mac("eth0", server_mac);

    struct ether_header *eth = (struct ether_header*)bytes;
    if (eth->ether_type != htons(ETHERTYPE_IP)){
        printf ("Packet do not have Ip header\n");
        return ;
    }

    if (memcmp(eth->ether_shost, server_mac, 6) == 0) {
        printf("DHCP itself\n");
        return;
    }

    struct iphdr *ip = (struct iphdr *) (bytes + sizeof(struct ether_header));
    if (ip->protocol != IPPROTO_UDP) {
        printf ("Packet do not have UDP header\n");
        return ;
    }
    
    dhcp_packet *dhcp = (dhcp_packet *) (bytes + sizeof(struct ether_header) + ip->ihl*4 + sizeof(struct udphdr));

    int msg = get_dhcp_message_type(dhcp);

    if (msg == 1) {  // DISCOVER
        printf("[+] DHCP DISCOVER → OFFER\n");
        send_dhcp_reply(handle, dhcp, 2, server_mac, dhcp->chaddr);
    }
    else if (msg == 3) {  // REQUEST
        printf("[+] DHCP REQUEST → ACK\n");
        send_dhcp_reply(handle, dhcp, 5, server_mac, dhcp->chaddr);
    }
}

/************************************************************
 *                     MAIN
 ***********************************************************/
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
