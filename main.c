#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <netinet/in.h>

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int main() {
    int tun_fd, sock_fd;
    char *dev = "tun0";
    struct ifreq ifr;
    char buff[1500];
    struct iphdr *iph;
    struct icmphdr *icmph;
    char *data;
    int len = 44;

    /* Mở thiết bị TUN */
    tun_fd = open("/dev/net/tun", O_RDWR);
    if (tun_fd < 0) {
        perror("Open /dev/net/tun failed");
        return 1;
    }

    /* Cấu hình giao diện TUN */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (ioctl(tun_fd, TUNSETIFF, (void *)&ifr) < 0) {
        perror("ioctl TUNSETIFF");
        close(tun_fd);
        return 1;
    }

    /* Tạo socket raw để gửi gói tin qua wlan0 */
    sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock_fd < 0) {
        perror("socket");
        close(tun_fd);
        return 1;
    }

    /* Tạo và gửi gói ICMP Echo Request từ tun0 đến laptop */
    memset(buff, 0, sizeof(buff));
    iph = (struct iphdr *)buff;
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + len);
    iph->id = 0;
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_ICMP;
    iph->saddr = inet_addr("192.168.2.1"); /* Nguồn: tun0 */
    iph->daddr = inet_addr("192.168.1.101"); /* Đích: laptop */
    iph->check = checksum(iph, sizeof(struct iphdr));

    icmph = (struct icmphdr *)(buff + sizeof(struct iphdr));
    icmph->type = ICMP_ECHO;
    icmph->code = 0;
    icmph->un.echo.id = htons(1234);
    icmph->un.echo.sequence = htons(1);
    data = (char *)(icmph + 1);
    memset(data, 0xAA, len);
    icmph->checksum = checksum(icmph, sizeof(struct icmphdr) + len);

    printf("Sending ICMP Echo Request to 192.168.1.101\n");
    if (write(tun_fd, buff, sizeof(struct iphdr) + sizeof(struct icmphdr) + len) < 0) {
        perror("write");
        close(tun_fd);
        close(sock_fd);
        return 1;
    }

    /* Vòng lặp xử lý gói tin từ tun0 */
    while (1) {
        int n = read(tun_fd, buff, sizeof(buff));
        if (n < 0) {
            perror("read");
            break;
        }

        iph = (struct iphdr *)buff;
        icmph = (struct icmphdr *)(buff + sizeof(struct iphdr));

        /* Xử lý gói ICMP Echo Reply từ 192.168.1.200 đến 192.168.1.101 */
        if (iph->protocol == IPPROTO_ICMP && iph->saddr == inet_addr("192.168.1.200") &&
            iph->daddr == inet_addr("192.168.1.101") && icmph->type == ICMP_ECHOREPLY) {
            printf("Received ICMP Echo Reply from 192.168.1.200 to 192.168.1.101 on tun0\n");

            /* Gửi gói tin qua wlan0 */
            struct sockaddr_in dest;
            memset(&dest, 0, sizeof(dest));
            dest.sin_family = AF_INET;
            dest.sin_addr.s_addr = iph->daddr; /* 192.168.1.101 */
            if (sendto(sock_fd, buff, n, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
                perror("sendto");
                continue;
            }
            printf("Forwarded ICMP Echo Reply to 192.168.1.101 via wlan0\n");
        }

        /* Xử lý ICMP Echo Request từ laptop đến 192.168.2.1 */
        if (iph->protocol == IPPROTO_ICMP && icmph->type == ICMP_ECHO &&
            iph->daddr == inet_addr("192.168.2.1")) {
            printf("Received ICMP Echo Request from %s to 192.168.2.1\n", inet_ntoa(*(struct in_addr *)&iph->saddr));

            /* Tạo ICMP Echo Reply */
            char reply_buff[1500];
            struct iphdr *reply_iph = (struct iphdr *)reply_buff;
            struct icmphdr *reply_icmph = (struct icmphdr *)(reply_buff + sizeof(struct iphdr));
            memcpy(reply_buff, buff, n);
            reply_iph->saddr = iph->daddr; /* Nguồn: 192.168.2.1 */
            reply_iph->daddr = iph->saddr; /* Đích: 192.168.1.101 */
            reply_iph->check = 0;
            reply_iph->check = checksum(reply_iph, sizeof(struct iphdr));
            reply_icmph->type = ICMP_ECHOREPLY;
            reply_icmph->code = 0;
            reply_icmph->checksum = 0;
            reply_icmph->checksum = checksum(reply_icmph, n - sizeof(struct iphdr));

            /* Gửi ICMP Echo Reply qua tun0 */
            if (write(tun_fd, reply_buff, n) < 0) {
                perror("write reply");
                continue;
            }
            printf("Sent ICMP Echo Reply to %s\n", inet_ntoa(*(struct in_addr *)&reply_iph->daddr));
        }

        /* Nhận ICMP Echo Reply từ laptop */
        if (iph->protocol == IPPROTO_ICMP && icmph->type == ICMP_ECHOREPLY &&
            ntohs(icmph->un.echo.id) == 1234 && ntohs(icmph->un.echo.sequence) == 1) {
            printf("Received ICMP Echo Reply from %s\n", inet_ntoa(*(struct in_addr *)&iph->saddr));
        }
    }

    close(tun_fd);
    close(sock_fd);
    return 0;
}