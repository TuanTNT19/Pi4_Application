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


// Helper: IP checksum (standard)
static uint16_t ip_checksum(const void *vdata, size_t length) {
    const uint8_t *data = (const uint8_t *)vdata;
    uint32_t sum = 0;
    while (length > 1) {
        sum += (uint16_t)(data[0] << 8 | data[1]);
        data += 2;
        length -= 2;
    }
    if (length == 1) {
        sum += ((uint16_t)data[0]) << 8;
    }
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum);
}

// Helper: UDP checksum (pseudo-header)
static uint16_t udp_checksum(const struct iphdr *ip, const struct udphdr *udp, const uint8_t *payload, size_t payload_len) {
    uint32_t sum = 0;
    // pseudo header: src(4), dst(4), zero(1), proto(1), udplen(2)
    const uint16_t *ptr;
    // src
    ptr = (const uint16_t *)&ip->saddr;
    sum += ntohs(ptr[0]);
    sum += ntohs(ptr[1]);
    // dst
    ptr = (const uint16_t *)&ip->daddr;
    sum += ntohs(ptr[0]);
    sum += ntohs(ptr[1]);
    // protocol and zero + udp length
    sum += (uint16_t)ip->protocol << 8; // proto in high byte, zero in low byte
    sum += ntohs(udp->uh_ulen);

    // UDP header: source, dest, len, checksum (we add header and payload as 16-bit words)
    // Note: some platforms have different field order; cast to bytes for safety
    const uint8_t *u = (const uint8_t *)udp;
    size_t udp_hdr_len = sizeof(struct udphdr);
    ptr = (const uint16_t *)u;
    for (size_t i = 0; i < udp_hdr_len / 2; ++i) sum += ntohs(ptr[i]);

    // payload
    ptr = (const uint16_t *)payload;
    size_t len = payload_len;
    while (len > 1) {
        sum += ntohs(*ptr++);
        len -= 2;
    }
    if (len == 1) {
        // last odd byte -> high byte of 16-bit
        const uint8_t *last = ((const uint8_t *)payload) + payload_len - 1;
        sum += ((uint16_t)(*last)) << 8;
    }

    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    uint16_t res = (uint16_t)(~sum);
    if (res == 0) return 0xffff; // per RFC, checksum of 0x0000 transmitted as 0xFFFF
    return htons(res);
}

/*
 * send_dhcp_reply: build full ethernet+ip+udp+dhcp packet and send via pcap_sendpacket
 * - handle: pcap handle
 * - pack: pointer to parsed incoming dhcp_packet (we use pack->xid and pack->chaddr)
 * - msg_type: DHCP_OFFER(2) or DHCP_ACK(5)
 * - server_mac: MAC of server (6 bytes)
 * - client_mac: MAC of client (6 bytes) -- if all-zero, we still broadcast
 */
int send_dhcp_reply(pcap_t *handle, const dhcp_packet* pack, uint8_t msg_type,
                    const uint8_t server_mac[6], const uint8_t client_mac[6]) {
    uint8_t buf[1500];
    memset(buf, 0, sizeof(buf));

    uint8_t *ptr = buf;

    // ---------------------------
    // Ethernet header (14 bytes)
    // ---------------------------
    struct ether_header *eth = (struct ether_header *)ptr;
    // For safety, send to broadcast when client may not have MAC resolved for unicast; but client MAC is known in chaddr.
    if (client_mac && !(client_mac[0]==0 && client_mac[1]==0 && client_mac[2]==0 &&
                        client_mac[3]==0 && client_mac[4]==0 && client_mac[5]==0)) {
        memcpy(eth->ether_dhost, client_mac, 6);
    } else {
        memset(eth->ether_dhost, 0xff, 6); // broadcast
    }
    memcpy(eth->ether_shost, server_mac, 6);
    eth->ether_type = htons(ETHERTYPE_IP);
    ptr += sizeof(struct ether_header);

    // ---------------------------
    // IP header (20 bytes, no options)
    // ---------------------------
    struct iphdr *ip = (struct iphdr *)ptr;
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    // will set tot_len later
    ip->id = htons(0x1234);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->saddr = inet_addr(SERVER_IP); // network order
    ip->daddr = htonl(INADDR_BROADCAST); // broadcast
    ip->check = 0;
    ptr += sizeof(struct iphdr);

    // ---------------------------
    // UDP header (8 bytes)
    // ---------------------------
    struct udphdr *udp = (struct udphdr *)ptr;
    udp->uh_sport = htons(67);
    udp->uh_dport = htons(68);
    // will set uh_ulen later
    udp->uh_sum = 0;
    ptr += sizeof(struct udphdr);

    // ---------------------------
    // DHCP/BOOTP fixed header (236 bytes)
    // We'll build as raw bytes to prevent padding issues
    // ---------------------------
    uint8_t *dhcp_start = ptr;
    // BOOTREPLY op (1 byte)
    *ptr++ = 2; // op = BOOTREPLY
    *ptr++ = 1; // htype = Ethernet (1)
    *ptr++ = 6; // hlen = 6
    *ptr++ = 0; // hops = 0

    // xid (4 bytes) -- copy raw 4 bytes from incoming packet to preserve exact bytes
    memcpy(ptr, &pack->xid, 4);
    ptr += 4;

    // secs (2 bytes)
    *ptr++ = 0; *ptr++ = 0;

    // flags (2 bytes)
    *ptr++ = 0; *ptr++ = 0;

    // ciaddr (4)
    memset(ptr, 0, 4); ptr += 4;

    // yiaddr (4) -> offered IP (network order)
    uint32_t yi = inet_addr(OFFER_IP);
    memcpy(ptr, &yi, 4); ptr += 4;

    // siaddr (4) -> server IP
    uint32_t si = inet_addr(SERVER_IP);
    memcpy(ptr, &si, 4); ptr += 4;

    // giaddr (4)
    memset(ptr, 0, 4); ptr += 4;

    // chaddr (16) - client hw address + zeros
    // pack->chaddr expected to be 16 bytes
    memcpy(ptr, pack->chaddr, 16);
    ptr += 16;

    // sname (64)
    memset(ptr, 0, 64); ptr += 64;

    // file (128)
    memset(ptr, 0, 128); ptr += 128;

    // magic cookie (4) - network order
    uint32_t cookie = htonl(MAGIC_COOKIE);
    memcpy(ptr, &cookie, 4); ptr += 4;

    // ---------------------------
    // DHCP options (byte stream)
    // ---------------------------
    uint8_t *opt = ptr;

    // Option 53: DHCP message type
    *opt++ = 53; // code
    *opt++ = 1;  // len
    *opt++ = msg_type; // value (2=OFFER, 5=ACK)

    // Option 54: Server identifier (IP)
    *opt++ = 54;
    *opt++ = 4;
    memcpy(opt, &si, 4); opt += 4;

    // Option 1: Subnet mask
    *opt++ = 1;
    *opt++ = 4;
    uint32_t mask = inet_addr(SUBNET_MASK);
    memcpy(opt, &mask, 4); opt += 4;

    // Option 3: Router (gateway)
    *opt++ = 3;
    *opt++ = 4;
    memcpy(opt, &si, 4); opt += 4;

    // Option 51: IP address lease time
    *opt++ = 51;
    *opt++ = 4;
    uint32_t lt = htonl(LEASE_TIME);
    memcpy(opt, &lt, 4); opt += 4;

    // (Optional) Option 6: DNS - skipped here, add if needed

    // End option
    *opt++ = 255;

    // pad to 4-byte boundary (not strictly necessary)
    while (((opt - dhcp_start) & 3) != 0) {
        *opt++ = 0;
    }

    // update pointer
    ptr = opt;

    // ---------------------------
    // finalize lengths and checksums
    // ---------------------------
    size_t dhcp_len = ptr - dhcp_start; // variable
    size_t udp_len = sizeof(struct udphdr) + dhcp_len;
    size_t ip_len = sizeof(struct iphdr) + udp_len;

    ip->tot_len = htons((uint16_t)ip_len);
    udp->uh_ulen = htons((uint16_t)udp_len);

    // IP checksum
    ip->check = 0;
    ip->check = ip_checksum((void *)ip, sizeof(struct iphdr));

    // UDP checksum (compute over pseudo-header + udp header + data)
    udp->uh_sum = 0;
    udp->uh_sum = udp_checksum(ip, udp, dhcp_start, dhcp_len);

    // total packet size (ethernet + ip + udp + dhcp)
    int packet_len = (int)(sizeof(struct ether_header) + ip_len);

    // send packet
    int r = pcap_sendpacket(handle, buf, packet_len);
    if (r != 0) {
        fprintf(stderr, "pcap_sendpacket failed: %s\n", pcap_geterr(handle));
    } else {
        printf("send_dhcp_reply: Sent %s for XID ", (msg_type == DHCP_OFFER) ? "OFFER" : "ACK");
        // print xid in hex
        uint32_t xid_net;
        memcpy(&xid_net, &pack->xid, 4);
        uint32_t xid_host = ntohl(xid_net);
        printf("0x%08x\n", xid_host);
    }
    return r;
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

    struct udphdr *udp = (struct udphdr*) (bytes + sizeof (struct ether_header) + ip->ihl * 4);
    printf ("packet_handler: udp packet: port source: %d, port des: %d, len: %d\n", ntohl(udp->uh_sport), ntohl(udp->uh_dport), ntohl(udp->uh_ulen));

    dhcp_packet *dhcp = (dhcp_packet *) (bytes + sizeof(struct ether_header) + ip->ihl*4+ sizeof(struct udphdr));
    for (int i =0; i < 30; i++) {
        if (dhcp->options[i].Type == 53) {
            if (dhcp->options[i].Value[0] == DHCP_DISCOVER) {
                printf ("packet_handler: This is DHCP Discover\n");
                send_dhcp_reply (handle, dhcp, DHCP_OFFER, Server_MAC, dhcp->chaddr);
                printf ("packet_handler: Sent DHCP offer\n");
                break;
            }
            else if (dhcp->options[i].Value[0] == DHCP_REQUEST) {
                printf ("packet_handler: This is DHCP request\n");
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
    pcap_loop(handle, 0, packet_handler, (u_char*)handle);
    return 0;
}

