#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <sys/wait.h>

//Hàm thiết lập IP tĩnh cho giao diện
int set_interface_ip(char *ifname, char *ip, char *netmask) {
    int sock_id = socket (AF_INET, SOCK_DGRAM, 0);
    if ( sock_id < 0) {
        printf ("[ERROR] Can not open socket\n");
        return 0;
    }

    struct ifreq ifr;  // CTDL trên user space dùng để tương tác vs các giao diện mạng qia ioctl
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);    
    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr; // con trỏ addr quản lý vùng nhớ địa chỉ cuả ifr.ifr_addr
    ifr.ifr_addr.sa_family = AF_INET;
    inet_pton(AF_INET, ip, &addr->sin_addr);
    if (ioctl (sock_id, SIOCSIFADDR, &ifr) < 0) {
        printf ("[ERROR] Can not set IP\n");
        return 0;
    }

    addr = (struct sockaddr_in *)&ifr.ifr_netmask;
    ifr.ifr_netmask.sa_family = AF_INET;
    inet_pton (AF_INET, netmask, &addr->sin_addr);
    if (ioctl(sock_id, SIOCSIFNETMASK, &ifr) < 0) {
        printf ("[ERROR] Can not set mask\n");
        return 0;        
    }

    ifr.ifr_flags |= IFF_UP;
    if (ioctl(sock_id, SIOCSIFFLAGS, &ifr) < 0) {
        printf ("[ERROR] Can not set interface up\n");
        return 0;             
    }

    printf ("Interface %s is enabled with IP: %s, Netmask: %s\n", ifname, ip, netmask);

    // LẤy ra MAC để xem thử
    unsigned char mac_addr[6];
    if (ioctl(sock_id, SIOCGIFHWADDR, &ifr) < 0) {
        perror("[ERROR] Can not get MAC address");
        close(sock_id);
        return -1;
    }
    if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
        fprintf(stderr, "[ERROR] Interface %s is not Ethernet/Wi-Fi (sa_family=%d)\n",
                ifname, ifr.ifr_hwaddr.sa_family);
        close(sock_id);
        return -1;
    }
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
    printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           mac_addr[0], mac_addr[1], mac_addr[2],
           mac_addr[3], mac_addr[4], mac_addr[5]);
           
            close (sock_id);
    return 1;
}
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        unsigned int id = ntohl(ph->packet_id);
        printf("Gói tin ID: %u\n", id);

        unsigned char *payload;
        int payload_len = nfq_get_payload(nfa, &payload);
         printf ("CHECKING: payload len: %d\n", payload_len);

        // Ưu tiên kiểm tra header IP (trường hợp không có Ethernet)
        if (payload_len >= sizeof(struct iphdr)) {
            struct iphdr *ip = (struct iphdr *)payload;
            int ip_header_len = ip->ihl * 4; // Độ dài header IP thực tế
            // if (ip->version == 4 && ip->ihl >= 5 && ip_header_len <= payload_len) {
            uint16_t ip_total_len = ntohs(ip->tot_len);
            if (ip_total_len == payload_len) {
                uint32_t host_saddr = ip->saddr;
                uint32_t host_daddr = ip->daddr;
                char *s_ip = (char *)malloc(INET_ADDRSTRLEN);
                char *d_ip = (char *)malloc(INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &host_saddr, s_ip, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &host_daddr, d_ip, INET_ADDRSTRLEN);
                printf("Gói tin Bắt đầu từ header IP tại offset 0, Nguồn: %s, Đích: %s, Độ dài header IP: %d byte, Tổng độ dài IP: %u byte\n",
                       s_ip, d_ip, ip_header_len, ip_total_len);

                if (payload_len >= ip_total_len) {
                    printf("Dữ liệu đầy đủ: %d byte\n", payload_len);
                } else {
                    printf("Dữ liệu không đầy đủ, payload_len: %d, ip_total_len: %u\n",
                           payload_len, ip_total_len);
                }

                // Kiểm tra header Ethernet nếu đủ dài
                if (payload_len >= sizeof(struct ethhdr) + ip_total_len) {
                    struct ethhdr *eth = (struct ethhdr *)payload;
                    if (ntohs(eth->h_proto) == ETH_P_IP) {
                        printf("Có header Ethernet, IP tại offset 14\n");
                        printf("Header Ethernet không khớp IP, h_proto: %04x\n", ntohs(eth->h_proto));
                    }
                }
                free (s_ip);
                free (d_ip);
        } else {
            struct ethhdr *eth = (struct ethhdr *)payload;
            if (ntohs(eth->h_proto) == ETH_P_IP && payload_len >= sizeof(struct ethhdr) + sizeof(struct iphdr)) {
                struct iphdr *ip = (struct iphdr *)(payload + sizeof(struct ethhdr));
                int ip_header_len = ip->ihl * 4;
                if (ip->version == 4 && ip->ihl >= 5 && ip_header_len <= (payload_len - sizeof(struct ethhdr))) {
                    uint16_t ip_total_len = ntohs(ip->tot_len);
                    uint32_t host_saddr = ip->saddr;
                    uint32_t host_daddr = ip->daddr;
                    char *s_ip = (char *)malloc(INET_ADDRSTRLEN);
                    char *d_ip = (char *)malloc(INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &host_saddr, s_ip, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &host_daddr, d_ip, INET_ADDRSTRLEN);
                    printf("Bắt đầu từ header Ethernet, IP tại offset 14, Nguồn: %s, Đích: %s, Độ dài header IP: %d byte, Tổng độ dài IP: %u byte\n",
                           s_ip, d_ip, ip_header_len, ip_total_len);
                    if (payload_len >= sizeof(struct ethhdr) + ip_total_len) {
                        printf("Dữ liệu đầy đủ: %d byte\n", payload_len);
                    } else {
                        printf("Dữ liệu không đầy đủ, payload_len: %d, ip_total_len: %d\n",
                               payload_len, ip_total_len + sizeof(struct ethhdr));
                    }

                    free (s_ip);
                    free (d_ip);
                } else {
                    printf("Header IP không hợp lệ sau Ethernet.\n");
                }
            } else {
                printf("Header Ethernet không phải IP hoặc không đủ dữ liệu, h_proto: %04x\n", ntohs(eth->h_proto));
            }
        }

        return nfq_set_verdict(qh, id, 1, 0, NULL);
    }
    }
    return 0;
}

int main() {
    // struct nfq_handle *h = nfq_open();
    // if (!h) {
    //     perror("Lỗi mở netfilter");
    //     return -1;
    // }
    // printf("Handle opened successfully\n");

    // if (nfq_unbind_pf(h, AF_INET) < 0) {
    //     perror("Lỗi unbind");
    //     nfq_close(h);
    //     return -1;
    // }
    // printf("Unbind successful\n");

    // if (nfq_bind_pf(h, AF_INET) < 0) {
    //     perror("Lỗi bind");
    //     nfq_close(h);
    //     return -1;
    // }
    // printf("Bind successful\n");

    // struct nfq_q_handle *qh = nfq_create_queue(h, 0, &cb, NULL);
    // if (!qh) {
    //     perror("Lỗi tạo queue");
    //     nfq_close(h);
    //     return -1;
    // }
    // printf("Queue created successfully\n");


    // // Set the queue mode to copy packets to userspace
    // if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
    //     fprintf(stderr, "Can't set packet_copy mode\n");
    //     exit(1);
    // }
    
    // int fd = nfq_fd(h);
    // if (fd < 0) {
    //     perror("Lỗi lấy file descriptor");
    //     nfq_destroy_queue(qh);
    //     nfq_close(h);
    //     return -1;
    // }
    // printf("File descriptor: %d\n", fd);

    // char recv_buf[4096];
    // int rv;
    // printf("Bắt đầu bắt bản tin\n");
    // int flags = fcntl(fd, F_GETFL, 0);
    // fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    // while (1) {
    //     rv = recv(fd, recv_buf, sizeof(recv_buf), 0);
    //     if (rv < 0) {
    //         if (errno == EAGAIN || errno == EWOULDBLOCK) {
    //             printf("Chưa có dữ liệu, chờ...\n");
    //             sleep(1); // Chờ 1 giây trước khi thử lại
    //             continue;
    //         }
    //         perror("Lỗi recv");
    //         break;
    //     }
    //     printf("Nhận dữ liệu, kích thước: %d byte\n", rv);
    //     nfq_handle_packet(h, recv_buf, rv);
    // }

    // nfq_destroy_queue(qh);
    // nfq_close(h);
    // return 0;

    printf ("Start setting interface up\n");
    if (set_interface_ip("wlan0", "192.168.2.1", "255.255.255.0")) {
        printf ("Setting OK\n");
        return 1;
    }
    else {
        printf ("Setting failed\n");
        return 0;
    }
}