#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netfilter.h> // Cần libnetfilter-queue
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <net/if.h>
#include <sys/socket.h>

// Hàm xử lý gói tin NAT ( Chuyển tiếp từ eth0 sang wlan0 )
static int cb (struct nfq_q_handle *qh, struct nfgenmsg *nfmsg)