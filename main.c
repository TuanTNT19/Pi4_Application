#include <stdio.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <libnetfilter_queue/linux_nfnetlink_queue.h>

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    if (!nfa) {
        printf("Không có dữ liệu gói tin\n");
        return 0;
    }
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        unsigned int id = ntohl(ph->packet_id);
        printf("Gói tin ID: %u nhận được\n", id);

        unsigned char *payload;
        int payload_len = nfq_get_payload(nfa, &payload);
        printf("Payload length: %d\n", payload_len);

        if (payload_len >= sizeof(struct iphdr)) {
            struct iphdr *ip = (struct iphdr *)payload;
            int ip_header_len = ip->ihl * 4;
            if (ip->version == 4 && ip->ihl >= 5 && ip_header_len <= payload_len) {
                uint16_t ip_total_len = ntohs(ip->tot_len);
                printf("Nguồn: %s, Độ dài header IP: %d, Tổng độ dài IP: %u\n",
                       inet_ntoa(*(struct in_addr *)&ip->saddr), ip_header_len, ip_total_len);

                if (ip->protocol == IPPROTO_ICMP && payload_len >= ip_header_len + sizeof(struct icmphdr)) {
                    struct icmphdr *icmp = (struct icmphdr *)(payload + ip_header_len);
                    printf("Gói tin ICMP, Type: %d, Code: %d\n", icmp->type, icmp->code);
                    if (icmp->type == 8 || icmp->type == 0) {
                        printf("Bản tin Ping (Echo %s)\n", icmp->type == 8 ? "Request" : "Reply");
                    }
                }
            } else {
                printf("Header IP không hợp lệ\n");
            }
        } else {
            printf("Payload quá ngắn hoặc không chứa header IP\n");
        }

        return nfq_set_verdict(qh, id, 1, 0, NULL); // Sử dụng NF_ACCEPT
    }
    return 0;
}

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
    while (1) {
        recv(fd, recv_buf, sizeof(recv_buf), 0);
        printf("Nhận dữ liệu, kích thước: %d byte\n", rv);
        nfq_handle_packet(h, recv_buf, rv);
    }
    if (rv < 0) {
        perror("Lỗi recv");
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}