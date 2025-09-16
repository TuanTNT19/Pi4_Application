#include <stdio.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h> // Thêm để khai báo inet_ntoa
#include <libnetfilter_queue/linux_nfnetlink_queue.h> // Thêm để khai báo NF_ACCEPT

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        unsigned int id = ntohl(ph->packet_id);
        printf("Gói tin ID: %u\n", id);

        unsigned char *payload;
        int payload_len = nfq_get_payload(nfa, &payload);

        // Ưu tiên kiểm tra header IP (trường hợp không có Ethernet)
        if (payload_len >= sizeof(struct iphdr)) {
            struct iphdr *ip = (struct iphdr *)payload;
            int ip_header_len = ip->ihl * 4; // Độ dài header IP thực tế
            if (ip->version == 4 && ip->ihl >= 5 && ip_header_len <= payload_len) {
                uint16_t ip_total_len = ntohs(ip->tot_len);
                printf("Bắt đầu từ header IP tại offset 0, Nguồn: %s, Độ dài header IP: %d byte, Tổng độ dài IP: %u byte\n",
                       inet_ntoa(*(struct in_addr *)&ip->saddr), ip_header_len, ip_total_len);

                if (payload_len >= ip_total_len) {
                    printf("Dữ liệu đầy đủ: %d byte\n", payload_len);
                } else {
                    printf("Dữ liệu không đầy đủ, payload_len: %d, ip_total_len: %u\n",
                           payload_len, ip_total_len);
                }

                // Kiểm tra ICMP (Ping)
                if (ip->protocol == IPPROTO_ICMP && payload_len >= ip_header_len + sizeof(struct icmphdr)) {
                    struct icmphdr *icmp = (struct icmphdr *)(payload + ip_header_len);
                    printf("Gói tin ICMP, Type: %d (0=Reply, 8=Request), Code: %d\n",
                           icmp->type, icmp->code);
                    if (icmp->type == 8 || icmp->type == 0) {
                        printf("Đây là bản tin Ping (Echo %s)\n", icmp->type == 8 ? "Request" : "Reply");
                        // In một phần dữ liệu ICMP nếu có (ví dụ 8 byte đầu)
                        printf("Dữ liệu ICMP đầu tiên: ");
                        for (int i = 0; i < 8 && i < (payload_len - ip_header_len - sizeof(struct icmphdr)); i++) {
                            printf("%02x ", *(payload + ip_header_len + sizeof(struct icmphdr) + i));
                        }
                        printf("\n");
                    }
                }

                // Kiểm tra header Ethernet nếu đủ dài
                if (payload_len >= sizeof(struct ethhdr) + ip_total_len) {
                    struct ethhdr *eth = (struct ethhdr *)payload;
                    if (ntohs(eth->h_proto) == ETH_P_IP) {
                        printf("Có header Ethernet, IP tại offset 14, Nguồn: %s\n",
                               inet_ntoa(*(struct in_addr *)&ip->saddr));
                    } else {
                        printf("Header Ethernet không khớp IP, h_proto: %04x\n", ntohs(eth->h_proto));
                    }
                }
            } else {
                printf("Không phải header IP hợp lệ hoặc độ dài không đủ.\n");
            }
        } else if (payload_len >= sizeof(struct ethhdr)) {
            struct ethhdr *eth = (struct ethhdr *)payload;
            if (ntohs(eth->h_proto) == ETH_P_IP && payload_len >= sizeof(struct ethhdr) + sizeof(struct iphdr)) {
                struct iphdr *ip = (struct iphdr *)(payload + sizeof(struct ethhdr));
                int ip_header_len = ip->ihl * 4;
                if (ip->version == 4 && ip->ihl >= 5 && ip_header_len <= (payload_len - sizeof(struct ethhdr))) {
                    uint16_t ip_total_len = ntohs(ip->tot_len);
                    printf("Bắt đầu từ header Ethernet, IP tại offset 14, Nguồn: %s, Độ dài header IP: %d byte, Tổng độ dài IP: %u byte\n",
                           inet_ntoa(*(struct in_addr *)&ip->saddr), ip_header_len, ip_total_len);
                    if (payload_len >= sizeof(struct ethhdr) + ip_total_len) {
                        printf("Dữ liệu đầy đủ: %d byte\n", payload_len);
                    } else {
                        printf("Dữ liệu không đầy đủ, payload_len: %d, ip_total_len: %u\n",
                               payload_len, ip_total_len + sizeof(struct ethhdr));
                    }

                    // Kiểm tra ICMP (Ping)
                    if (ip->protocol == IPPROTO_ICMP && payload_len >= sizeof(struct ethhdr) + ip_header_len + sizeof(struct icmphdr)) {
                        struct icmphdr *icmp = (struct icmphdr *)(payload + sizeof(struct ethhdr) + ip_header_len);
                        printf("Gói tin ICMP, Type: %d (0=Reply, 8=Request), Code: %d\n",
                               icmp->type, icmp->code);
                        if (icmp->type == 8 || icmp->type == 0) {
                            printf("Đây là bản tin Ping (Echo %s)\n", icmp->type == 8 ? "Request" : "Reply");
                            printf("Dữ liệu ICMP đầu tiên: ");
                            for (int i = 0; i < 8 && i < (payload_len - sizeof(struct ethhdr) - ip_header_len - sizeof(struct icmphdr)); i++) {
                                printf("%02x ", *(payload + sizeof(struct ethhdr) + ip_header_len + sizeof(struct icmphdr) + i));
                            }
                            printf("\n");
                        }
                    }
                } else {
                    printf("Header IP không hợp lệ sau Ethernet.\n");
                }
            } else {
                printf("Header Ethernet không phải IP hoặc không đủ dữ liệu, h_proto: %04x\n", ntohs(eth->h_proto));
            }
        } else {
            printf("Payload quá ngắn: %d byte\n", payload_len);
        }

        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    return 0;
}

int main() {
    struct nfq_handle *h = nfq_open();
    if (!h) {
        perror("Lỗi mở netfilter");
        return -1;
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        perror("Lỗi unbind");
        nfq_close(h);
        return -1;
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        perror("Lỗi bind");
        nfq_close(h);
        return -1;
    }

    struct nfq_q_handle *qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        perror("Lỗi tạo queue");
        nfq_close(h);
        return -1;
    }

    int fd = nfq_fd(h);
    char recv_buf[4096];
    int rv;
    while ((rv = recv(fd, recv_buf, sizeof(recv_buf), 0)) >= 0) {
        nfq_handle_packet(h, recv_buf, rv);
    }
    if (rv < 0) {
        perror("Lỗi recv");
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}