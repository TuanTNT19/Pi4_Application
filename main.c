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

int main(){
    int tun_fd;
    char *dev = "tun0";
    struct ifreq ifr;
    char buff[1500];
    struct iphdr *iph;
    struct icmphdr *icmph;
    char *data;
    int len = 44;

    /* Mở thiết bị TUN */
    tun_fd = open ("/dev/net/tun", O_RDWR);
    if ( tun_fd < 0) {
        printf (" Open /dev/net/tun failed \n");
        return -1;
    }

    /* Cấu hình giao diện TUN 0*/
    memset (&ifr, 0, sizeof (ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;   /* TUN mode, không cần Packet Info */
    /* Gán tun0 vs device file qua ioctl*/
    if (ioctl(tun_fd, TUNSETIFF, (void *)&ifr) < 0) {
        perror("ioctl TUNSETIFF");
        close(tun_fd);
        return 1;
    }

   /* Tạo gói ICMP Echo Request */
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
    iph->saddr = inet_addr("192.168.2.1"); /* IP nguồn của tun0 */
    iph->daddr = inet_addr("192.168.1.102"); /* IP đích, ví dụ IP của wlan0 */
    iph->check = 0;

    icmph = (struct icmphdr *)(buff + sizeof(struct iphdr));
    icmph->type = ICMP_ECHO;
    icmph->code = 0;
    icmph->un.echo.id = htons(1234);
    icmph->un.echo.sequence = htons(1);

    /* Thêm dữ liệu */
    data = (char *)(icmph + 1);
    memset(data, 0xAA, len);
    icmph->checksum = 0;

    /* Tạo 1 gói tin ở tầng 3 vì đang test vs giao diện TUN - giao diện này chuyên xử lý gói tin ở tầng 3*/

    /* Gửi gói tin xuống TUN*/
    printf ("Sending Buffer (ICMP Echo request) to 192.168.1.1\n");
    if (write (tun_fd, buff,sizeof(struct iphdr) + sizeof(struct icmphdr) + len) < 0)
    {
        perror("write");
        close(tun_fd);
        return 1;        
    }

    /* Đọc reply */
    while(1) {
        int n = read (tun_fd, buff, sizeof(buff));
        if (n < 0){
            perror("read");
            break;            
        }

        iph = (struct iphdr *)buff ; /* truy cập trường ip header của buf vừa đọc được*/
        icmph = (struct icmphdr *) (buff +  sizeof (struct iphdr)); /* Truy cập trường icmp header của buf vừa đọc được*/
        /* Kiểm tra */
        if (iph->protocol == IPPROTO_ICMP && icmph->type == ICMP_ECHOREPLY &&
            ntohs(icmph->un.echo.id) == 1234 && ntohs(icmph->un.echo.sequence) == 1) {
            printf("Received ICMP Echo Reply from %s\n", inet_ntoa(*(struct in_addr *)&iph->saddr));
            break;
        }
    }

    close(tun_fd);
    return 0;

}