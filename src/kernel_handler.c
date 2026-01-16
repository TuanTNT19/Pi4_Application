#include "kernel_handler.h"

static int process_mess (struct nlmsghdr *header, int len) {
    if (!NLMSG_OK(header, len)) return -1;

    if (header->nlmsg_type == RTM_NEWLINK) {
        return 1;
    }
    else if (header->nlmsg_type == NLMSG_ERROR) {
        return 2;
    }
    else if (header->nlmsg_type == RTM_NEWROUTE) {
        return 3;
    }
    else if (header->nlmsg_type == NLMSG_DONE) {
        return 0;
    }
    else {
        return -1;
    }
}

void display (int fd) {
    
    char buff[4096];
    char ifname[IFNAMSIZ] = "unknown";
    int len = recv (fd, buff, sizeof(buff), 0);
    int rat_len = 0;
    if (len < 0) {
        printf ("Can not receive any info from kernel\n");
        return ;
    }

    struct nlmsghdr *nlh = (struct nlmsghdr *) buff;
    for (; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len))  {
        int ret = process_mess (nlh, len);
        if (ret == 1) {
            struct ifinfomsg *payload = NLMSG_DATA(nlh);
            struct rtattr *rat = IFLA_RTA (payload);
            rat_len = IFLA_PAYLOAD(nlh);

            for (; RTA_OK (rat, rat_len); rat = RTA_NEXT(rat, rat_len)) {
                if (rat->rta_type == IFLA_IFNAME) {
                    strcpy (ifname, RTA_DATA(rat));
                    break;
                }
            }

                printf ("Basic interface info\n");
                printf ("IFI Family: %d\n", payload->ifi_family);
                printf ("Interface index: %d\n", payload->ifi_index);
                printf ("Interface name: %s\n", ifname);
                if (payload->ifi_flags & IFF_UP) printf ("Status: UP\n");
                else if (payload->ifi_flags & IFF_RUNNING) printf ("Status: RUNNING\n");
                else if (payload->ifi_flags & IFF_LOOPBACK) printf ("Status: LOOPBACK\n");
                else printf ("STATUS: UNKNOW\n");

        }
        else if (ret == 2) {
            struct nlmsgerr *er = NLMSG_DATA(nlh);
            if (er->error != 0) {
                printf("Kernel error: %s (%d)\n",
                    strerror(-er->error),
                    er->error);                
                return false;
            }
        }
        else if (ret == 3) {
            char ip_des[16] = "0.0.0.0";
            char ip_gw[16] = "0.0.0.0";
            struct rtmsg *payload  = NLMSG_DATA(nlh);
            if (payload->rtm_table != RT_TABLE_MAIN) {
                return ;
            }
            struct rtattr *rat = RTM_RTA (payload);
            rat_len = RTM_PAYLOAD(nlh);
            for (; RTA_OK (rat, rat_len); rat = RTA_NEXT(rat, rat_len)) {
                if (rat->rta_type == RTA_DST) {
                    inet_ntop(AF_INET, RTA_DATA(rat), ip_des, INET_ADDRSTRLEN);
                }
                else if (rat->rta_type == RTA_GATEWAY) {
                    struct in_addr gw_addr;
                    memcpy(&gw_addr, RTA_DATA(rat), sizeof(struct in_addr));
                    inet_ntop(AF_INET, RTA_DATA(rat), ip_gw, INET_ADDRSTRLEN);                   
                }
                else if (rat->rta_type == RTA_OIF) {
                    int index;
                    index = *(int *) RTA_DATA(rat);
                    if_indextoname (index, ifname);   
                }
            }
            printf ("Des: %s - GW: %s - Inface: %s \n", ip_des, ip_gw, ifname);
        }
        else if (ret == 0) {
            printf ("End of dump\n");
            return ;
        }
        else {
            return ;
        }
    }
}

