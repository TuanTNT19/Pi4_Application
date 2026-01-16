#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>

#define PR_ERR(str)  printf("[ERROR] failed in %s function\n", str)
#define PR_INF(str)  printf("[INFO] before step %s function \n", str)
// #define MESS_TYPE_INFO   1
// #define MESS_TYPE_IP     2
// #define MESS_TYPE_ROUTE  3
#define BUFSIZE 8192

typedef struct {
    struct nlmsghdr header;
    struct ifinfomsg payload;
} netl_iface_info;

typedef struct {
    struct nlmsghdr header;
    struct ifaddrmsg payload;
} netl_iface_ip;

// typedef struct {
//     struct nlmsghdr header;
//     struct rtmsg payload;
// } netl_iface_route;

typedef struct {
    struct nlmsghdr header;
    struct rtmsg    payload;
    char            attrbuf[256];   // 👈 BẮT BUỘC
} netl_iface_route;

int netl_socket_create();
struct msghdr prepare_mess (void *request, int mess_type);
bool iface_link_show (netl_iface_info *iface_info, int fd);
bool iface_link_show_i (netl_iface_info *iface_info, int fd, int index);
bool iface_set_up_i (netl_iface_info *iface_info, int fd, int index);
bool iface_set_down_i (netl_iface_info *iface_info, int fd, int index);
bool iface_set_MTU_i (netl_iface_info *iface_info, int fd, int index, int mtu);
bool iface_set_ip (netl_iface_ip *iface_ip, int index, char *ip, int fd);
bool iface_del_ip (netl_iface_ip *iface_ip, int index, char *ip, int fd);
bool iface_show_route (netl_iface_route *iface_route, int fd);
bool iface_add_route_normal (netl_iface_route *iface_route, int fd, char *des_ip, char *gw_ip, int index, int prefix_des_len);
bool iface_add_route_default (netl_iface_route *iface_route, int fd, char *gw_ip, int index);
bool iface_del_route (netl_iface_route *iface_route, int fd, char *des_ip, char *gw_ip, int index, int prefix_des_len);


