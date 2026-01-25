#include "interface_tool.h"
#include <net/if.h>


int netl_socket_create() {
    int fd = socket (AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) {
        PR_ERR ("socket");
        return -1;
    }

    struct sockaddr_nl sa = {
        .nl_family = AF_NETLINK,
        .nl_pad = 0,
        .nl_pid = getpid(),
        .nl_groups = RTMGRP_LINK
    };

    if (bind (fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        PR_ERR ("bind");
        close (fd);
        return -1;
    }

    return fd;
}

struct msghdr prepare_mess (void *request, int data_len) {
    static struct sockaddr_nl kernel_addr = {
        .nl_family = AF_NETLINK,
        .nl_pid = 0,
        .nl_groups = 0
    };

    static struct iovec data = {0};
    data.iov_base = request;
    data.iov_len = data_len;


    struct msghdr mess = {0};
    mess.msg_name = &kernel_addr;
    mess.msg_namelen = sizeof(kernel_addr);
    mess.msg_iov = &data;
    mess.msg_iovlen = 1;
    mess.msg_flags = 0;

    return mess;
}

bool iface_link_show (netl_iface_info *iface_info, int fd) {
    iface_info->header.nlmsg_len = NLMSG_LENGTH (sizeof(struct ifinfomsg));
    iface_info->header.nlmsg_type = RTM_GETLINK;
    iface_info->header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK;
    iface_info->header.nlmsg_seq = 1;
    iface_info->header.nlmsg_pid = getpid();

    iface_info->payload.ifi_family = AF_UNSPEC;

    struct msghdr mess = prepare_mess (iface_info, iface_info->header.nlmsg_len);

    if (sendmsg(fd, &mess, 0) < 0 )
    {
        return false;
    }

    return true;
}

bool iface_link_show_i (netl_iface_info *iface_info, int fd, int index) {
    iface_info->header.nlmsg_len = NLMSG_LENGTH (sizeof(struct ifinfomsg));
    iface_info->header.nlmsg_type = RTM_GETLINK;
    iface_info->header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    iface_info->header.nlmsg_seq = 1;
    iface_info->header.nlmsg_pid = getpid();

    iface_info->payload.ifi_family = AF_UNSPEC;
    iface_info->payload.ifi_index = index;

    struct msghdr mess = prepare_mess (iface_info, iface_info->header.nlmsg_len);

    if (sendmsg(fd, &mess, 0) < 0 )
    {
        return false;
    }

    return true;    
}

bool iface_set_up_i (netl_iface_info *iface_info, int fd, int index) {
    iface_info->header.nlmsg_len = NLMSG_LENGTH (sizeof(struct ifinfomsg));
    iface_info->header.nlmsg_type = RTM_SETLINK;
    iface_info->header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    iface_info->header.nlmsg_seq = 1;
    iface_info->header.nlmsg_pid = getpid();

    iface_info->payload.ifi_family = AF_UNSPEC;
    iface_info->payload.ifi_index = index;
    iface_info->payload.ifi_flags = IFF_UP;
    iface_info->payload.ifi_change = IFF_UP;

    struct msghdr mess = prepare_mess (iface_info, iface_info->header.nlmsg_len);

    if (sendmsg(fd, &mess, 0) < 0 )
    {
        return false;
    }

    return true;    

}

bool iface_set_down_i(netl_iface_info *iface_info, int fd, int index) {
    iface_info->header.nlmsg_len = NLMSG_LENGTH (sizeof(struct ifinfomsg));
    iface_info->header.nlmsg_type = RTM_SETLINK;
    iface_info->header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    iface_info->header.nlmsg_seq = 1;
    iface_info->header.nlmsg_pid = getpid();

    iface_info->payload.ifi_family = AF_UNSPEC;
    iface_info->payload.ifi_index = index;
    iface_info->payload.ifi_flags = 0;
    iface_info->payload.ifi_change = IFF_UP;
    
    struct msghdr mess = prepare_mess (iface_info, iface_info->header.nlmsg_len);

    if (sendmsg(fd, &mess, 0) < 0 )
    {
        return false;
    }

    return true;    
}

bool iface_set_MTU_i (netl_iface_info *iface_info, int fd, int index, int mtu) {
    iface_info->header.nlmsg_len = NLMSG_LENGTH (sizeof(struct ifinfomsg));
    iface_info->header.nlmsg_type = RTM_SETLINK;
    iface_info->header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    iface_info->header.nlmsg_seq = 1;
    iface_info->header.nlmsg_pid = getpid();

    iface_info->payload.ifi_family = AF_UNSPEC;
    iface_info->payload.ifi_index = index;

    int attr_len = 0;
    struct rtattr* rta = (struct rtattr*)iface_info->attrbuf;
    rta->rta_len = RTA_ALIGN (RTA_LENGTH (sizeof(int)));
    rta->rta_type = IFLA_MTU;
    *(int *)RTA_DATA (rta) = mtu;
    attr_len += rta->rta_len;

    iface_info->header.nlmsg_len += attr_len;
    
    struct msghdr mess = prepare_mess (iface_info, iface_info->header.nlmsg_len);
    if (sendmsg(fd, &mess, 0) < 0 )
    {
        return false;
    }

    return true;    
}

bool iface_set_ip (netl_iface_ip *iface_ip, int index, char *ip, int fd) {
    struct in_addr addr;
    inet_pton(AF_INET, ip, &addr);

    iface_ip->header.nlmsg_len = NLMSG_LENGTH (sizeof(struct ifaddrmsg));
    iface_ip->header.nlmsg_type = RTM_NEWADDR;
    iface_ip->header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    iface_ip->header.nlmsg_seq = 1;
    iface_ip->header.nlmsg_pid = getpid();

    iface_ip->payload.ifa_family = AF_INET;
    iface_ip->payload.ifa_prefixlen = 24;
    iface_ip->payload.ifa_flags= IFA_F_PERMANENT;
    iface_ip->payload.ifa_scope = RT_SCOPE_UNIVERSE;
    iface_ip->payload.ifa_index = index;

    // IFA_LOCAL
    int attr_len = 0;
    struct rtattr *rta = (struct rtattr *)iface_ip->attrbuf;
    rta->rta_len = RTA_ALIGN (RTA_LENGTH(sizeof(struct in_addr)));
    rta->rta_type = IFA_LOCAL;
    memcpy(RTA_DATA(rta), &addr, sizeof(addr));
    attr_len += rta->rta_len;
    iface_ip->header.nlmsg_len += attr_len;

    struct msghdr mess = prepare_mess (iface_ip, iface_ip->header.nlmsg_len);
    if (sendmsg(fd, &mess, 0) < 0 )
    {
        return false;
    }

    return true; 
}

bool iface_del_ip (netl_iface_ip *iface_ip, int index, char *ip, int fd) {
    struct in_addr addr;
    inet_pton(AF_INET, ip, &addr);

    iface_ip->header.nlmsg_len = NLMSG_LENGTH (sizeof(struct ifaddrmsg));
    iface_ip->header.nlmsg_type = RTM_DELADDR;
    iface_ip->header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    iface_ip->header.nlmsg_seq = 1;
    iface_ip->header.nlmsg_pid = getpid();

    iface_ip->payload.ifa_family = AF_INET;
    iface_ip->payload.ifa_prefixlen = 24;
    iface_ip->payload.ifa_index = index;
    iface_ip->payload.ifa_flags = IFA_F_PERMANENT;
    iface_ip->payload.ifa_scope = RT_SCOPE_UNIVERSE;

    int attr_len = 0;
    struct rtattr *rta = (struct rtattr *)iface_ip->attrbuf;
    rta->rta_len = RTA_ALIGN (RTA_LENGTH(sizeof(struct in_addr)));
    rta->rta_type = IFA_ADDRESS;
    memcpy(RTA_DATA(rta), &addr, sizeof(addr));
    attr_len += rta->rta_len;
    iface_ip->header.nlmsg_len += attr_len;
    
    struct msghdr mess = prepare_mess (iface_ip, iface_ip->header.nlmsg_len);
    if (sendmsg(fd, &mess, 0) < 0 )
    {
        return false;
    }

    return true; 
}

bool iface_show_route (netl_iface_route *iface_route, int fd) {
    iface_route->header.nlmsg_len = NLMSG_LENGTH (sizeof(struct rtmsg));
    iface_route->header.nlmsg_type = RTM_GETROUTE;
    iface_route->header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK;
    iface_route->header.nlmsg_seq = 1;
    iface_route->header.nlmsg_pid = getpid();

    iface_route->payload.rtm_family = AF_UNSPEC;
    struct msghdr mess = prepare_mess (iface_route, iface_route->header.nlmsg_len);
    if (sendmsg(fd, &mess, 0) < 0 )
    {
        return false;
    }

    return true; 
}


bool iface_add_route_normal(netl_iface_route *iface_route, int fd, char *des_ip, char *gw_ip, int index, int prefix_des_len) {
    struct in_addr des_addr;
    inet_pton(AF_INET, des_ip, &des_addr);
    struct in_addr gw_addr;
    inet_pton(AF_INET, gw_ip, &gw_addr); 
    memset(iface_route, 0, sizeof(*iface_route));

    iface_route->header.nlmsg_len = NLMSG_LENGTH (sizeof(struct rtmsg));
    iface_route->header.nlmsg_type = RTM_NEWROUTE;
    iface_route->header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    iface_route->header.nlmsg_seq = 1;
    iface_route->header.nlmsg_pid = getpid();

    iface_route->payload.rtm_family = AF_INET;
    iface_route->payload.rtm_dst_len = prefix_des_len;
    iface_route->payload.rtm_table = RT_TABLE_MAIN;
    iface_route->payload.rtm_protocol = RTPROT_STATIC;
    iface_route->payload.rtm_scope = RT_SCOPE_UNIVERSE;
    iface_route->payload.rtm_type = RTN_UNICAST;

    struct rtattr *rta;
    int attr_len = 0;

    rta = (struct rtattr *)iface_route->attrbuf;
    rta->rta_type = RTA_DST;
    rta->rta_len = RTA_ALIGN (RTA_LENGTH(sizeof(struct in_addr)));
    memcpy(RTA_DATA(rta), &des_addr, sizeof(struct in_addr));
    attr_len += rta->rta_len;

    rta = (struct rtattr *)(iface_route->attrbuf + attr_len);
    rta->rta_type = RTA_GATEWAY;
    rta->rta_len = RTA_ALIGN (RTA_LENGTH(sizeof(struct in_addr)));
    memcpy(RTA_DATA(rta), &gw_addr, sizeof(struct in_addr));
    attr_len += rta->rta_len;
    
    rta = (struct rtattr *)(iface_route->attrbuf + attr_len);
    rta->rta_type = RTA_OIF;
    rta->rta_len = RTA_ALIGN (RTA_LENGTH(sizeof(int)));
    *(int *)RTA_DATA(rta) = index;
    attr_len += rta->rta_len;

    iface_route->header.nlmsg_len += attr_len;

    struct msghdr mess = prepare_mess (iface_route, iface_route->header.nlmsg_len);
    if (sendmsg(fd, &mess, 0) < 0 )
    {
        return false;
    }

    return true; 
}


bool iface_add_route_default (netl_iface_route *iface_route, int fd, char *gw_ip, int index) {
    struct in_addr gw_addr;
    inet_pton(AF_INET, gw_ip, &gw_addr);
    struct in_addr des_addr;
    inet_pton(AF_INET, "0.0.0.0", &des_addr);
    memset(iface_route, 0, sizeof(*iface_route));
    
    iface_route->header.nlmsg_len = NLMSG_LENGTH (sizeof(struct rtmsg));
    iface_route->header.nlmsg_type = RTM_NEWROUTE;
    iface_route->header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_ACK | NLM_F_CREATE ;
    iface_route->header.nlmsg_seq = 1;
    iface_route->header.nlmsg_pid = getpid();

    iface_route->payload.rtm_family = AF_INET;
    iface_route->payload.rtm_dst_len = 0;
    iface_route->payload.rtm_table = RT_TABLE_MAIN;
    iface_route->payload.rtm_protocol = RTPROT_STATIC;
    iface_route->payload.rtm_scope = RT_SCOPE_UNIVERSE;
    iface_route->payload.rtm_type = RTN_UNICAST;

    struct rtattr *rta;
    int attr_len = 0;

    rta = (struct rtattr *)iface_route->attrbuf;
    rta->rta_len = RTA_ALIGN (RTA_LENGTH (sizeof (struct in_addr)));
    rta->rta_type = RTA_DST;
    memcpy(RTA_DATA(rta), &des_addr, sizeof(struct in_addr));
    attr_len += rta->rta_len;

    rta = (struct rtattr *) (iface_route->attrbuf + attr_len);
    rta->rta_len = RTA_ALIGN (RTA_LENGTH (sizeof (struct in_addr)));
    rta->rta_type = RTA_GATEWAY;
    memcpy(RTA_DATA(rta), &gw_addr, sizeof(struct in_addr));
    attr_len += rta->rta_len;

    rta = (struct rtattr *) (iface_route->attrbuf + attr_len);
    rta->rta_len = RTA_ALIGN (RTA_LENGTH (sizeof (int)));
    rta->rta_type = RTA_OIF;
    *(int *) RTA_DATA(rta) = index;
    attr_len += rta->rta_len;

    iface_route->header.nlmsg_len += attr_len;

    struct msghdr mess = prepare_mess (iface_route, iface_route->header.nlmsg_len);
    if (sendmsg(fd, &mess, 0) < 0 )
    {
        return false;
    }

    return true;
}

bool iface_del_route (netl_iface_route *iface_route, int fd, char *des_ip, char *gw_ip, int index, int prefix_des_len) {
    struct in_addr des_addr;
    inet_pton(AF_INET, des_ip, &des_addr);
    struct in_addr gw_addr;
    inet_pton(AF_INET, gw_ip, &gw_addr);
    memset(iface_route, 0, sizeof(*iface_route));

    iface_route->header.nlmsg_len = NLMSG_LENGTH (sizeof(struct rtmsg));
    iface_route->header.nlmsg_type = RTM_DELROUTE;
    iface_route->header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    iface_route->header.nlmsg_seq = 1;
    iface_route->header.nlmsg_pid = getpid();

    iface_route->payload.rtm_family = AF_INET;
    iface_route->payload.rtm_dst_len = prefix_des_len;
    iface_route->payload.rtm_table = RT_TABLE_MAIN;
    iface_route->payload.rtm_protocol = RTPROT_UNSPEC;
    iface_route->payload.rtm_scope = RT_SCOPE_UNIVERSE;
    iface_route->payload.rtm_type = RTN_UNICAST;
    
    int attr_len = 0;
    struct rtattr *rta ;

    rta = (struct rtattr *)iface_route->attrbuf;
    rta->rta_len = RTA_ALIGN (RTA_LENGTH (sizeof (struct in_addr)));
    rta->rta_type = RTA_DST;
    memcpy(RTA_DATA(rta), &des_addr, sizeof(struct in_addr));
    attr_len += rta->rta_len;

    rta = (struct rtattr *) (iface_route->attrbuf + attr_len);
    rta->rta_len = RTA_ALIGN (RTA_LENGTH (sizeof (struct in_addr)));
    rta->rta_type = RTA_GATEWAY;
    memcpy(RTA_DATA(rta), &gw_addr, sizeof(struct in_addr));
    attr_len += rta->rta_len;

    rta = (struct rtattr *) (iface_route->attrbuf + attr_len);
    rta->rta_len = RTA_ALIGN (RTA_LENGTH (sizeof (int)));
    rta->rta_type = RTA_OIF;
    *(int *) RTA_DATA(rta) = index;
    attr_len += rta->rta_len;

    iface_route->header.nlmsg_len += attr_len;

    struct msghdr mess = prepare_mess (iface_route, iface_route->header.nlmsg_len);
    if (sendmsg(fd, &mess, 0) < 0 )
    {
        return false;
    }

    return true;    
}