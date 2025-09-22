#include <stdio.h>
#include <stdlib.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <libnetfilter_queue/linux_nfnetlink_queue.h>
#include <fcntl.h>    
#include <errno.h>   
#include <unistd.h>   

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
                char s_ip[INET_ADDRSTRLEN];
                char d_ip[INET_ADDRSTRLEN];
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
                    char s_ip[INET_ADDRSTRLEN];
                    char d_ip[INET_ADDRSTRLEN];
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

// static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
//     if (!nfa) {
//         printf("Không có dữ liệu gói tin\n");
//         return 0;
//     }
//     struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
//     if (ph) {
//         unsigned int id = ntohl(ph->packet_id);
//         printf("Gói tin ID: %u nhận được\n", id);

//         unsigned char *payload;
//         int payload_len = nfq_get_payload(nfa, &payload);
//         printf("Payload length: %d\n", payload_len);

//         if (payload_len >= sizeof(struct iphdr)) {
//             struct iphdr *ip = (struct iphdr *)payload;
//             int ip_header_len = ip->ihl * 4;
//             if (ip->version == 4 && ip->ihl >= 5 && ip_header_len <= payload_len) {
//                 uint16_t ip_total_len = ntohs(ip->tot_len);
//                 printf("Nguồn: %s, Độ dài header IP: %d, Tổng độ dài IP: %u\n",
//                        inet_ntoa(*(struct in_addr *)&ip->saddr), ip_header_len, ip_total_len);

//                 if (ip->protocol == IPPROTO_ICMP && payload_len >= ip_header_len + sizeof(struct icmphdr)) {
//                     struct icmphdr *icmp = (struct icmphdr *)(payload + ip_header_len);
//                     printf("Gói tin ICMP, Type: %d, Code: %d\n", icmp->type, icmp->code);
//                     if (icmp->type == 8 || icmp->type == 0) {
//                         printf("Bản tin Ping (Echo %s)\n", icmp->type == 8 ? "Request" : "Reply");
//                     }
//                 }
//             } else {
//                 printf("Header IP không hợp lệ\n");
//             }
//         } else {
//             printf("Payload quá ngắn hoặc không chứa header IP\n");
//         }

//         return nfq_set_verdict(qh, id, 1, 0, NULL); // Sử dụng NF_ACCEPT
//     }
//     return 0;
// }

int main() {
    struct nfq_handle *h = nfq_open();
    if (!h) {
        perror("Lỗi mở netfilter");
        return -1;
    }
    printf("Handle opened successfully\n");

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        perror("Lỗi unbind");
        nfq_close(h);
        return -1;
    }
    printf("Unbind successful\n");

    if (nfq_bind_pf(h, AF_INET) < 0) {
        perror("Lỗi bind");
        nfq_close(h);
        return -1;
    }
    printf("Bind successful\n");

    struct nfq_q_handle *qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        perror("Lỗi tạo queue");
        nfq_close(h);
        return -1;
    }
    printf("Queue created successfully\n");


    // Set the queue mode to copy packets to userspace
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "Can't set packet_copy mode\n");
        exit(1);
    }
    
    int fd = nfq_fd(h);
    if (fd < 0) {
        perror("Lỗi lấy file descriptor");
        nfq_destroy_queue(qh);
        nfq_close(h);
        return -1;
    }
    printf("File descriptor: %d\n", fd);

    char recv_buf[4096];
    int rv;
    printf("Bắt đầu bắt bản tin\n");
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    while (1) {
        rv = recv(fd, recv_buf, sizeof(recv_buf), 0);
        if (rv < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                printf("Chưa có dữ liệu, chờ...\n");
                sleep(1); // Chờ 1 giây trước khi thử lại
                continue;
            }
            perror("Lỗi recv");
            break;
        }
        printf("Nhận dữ liệu, kích thước: %d byte\n", rv);
        nfq_handle_packet(h, recv_buf, rv);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}