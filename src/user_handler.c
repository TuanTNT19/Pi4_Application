#include "user_handler.h"

void print_help() {
    printf (" ********* User Command: **********\n");
    printf (" *********** 1. my_nl_tool link show\n");
    printf (" *********** 2. my_nl_tool link up \n");
    printf (" *********** 3. my_nl_tool link down \n");
    printf (" *********** 4. my_nl_tool set MTU \n");
    printf (" *********** 5. my_nl_tool addr add \n");
    printf (" *********** 6. my_nl_tool addr del \n");
    printf (" *********** 7. my_nl_tool route show \n");
    printf (" *********** 8. my_nl_tool route add \n");
    printf (" *********** 9. my_nl_tool route del \n");
}

char **parse_func(const char *str, int *count) {
    if (!str || !count || strlen(str) == 0) {
        if (count) *count = 0;
        return NULL;
    }

    char *str_count = strdup(str);  // dùng để đếm
    char *str_parse = strdup(str);  // dùng để parse thật
    if (!str_count || !str_parse) {
        free(str_count);
        free(str_parse);
        *count = 0;
        return NULL;
    }

    /* --------- ĐẾM TOKEN --------- */
    int temp_count = 0;
    char *token = strtok(str_count, " \t\n\r");
    while (token) {
        temp_count++;
        token = strtok(NULL, " \t\n\r");
    }

    if (temp_count == 0) {
        free(str_count);
        free(str_parse);
        *count = 0;
        return NULL;
    }

    /* --------- CẤP PHÁT MẢNG --------- */
    char **words = malloc((temp_count + 1) * sizeof(char *));
    if (!words) {
        free(str_count);
        free(str_parse);
        *count = 0;
        return NULL;
    }

    /* --------- PARSE THẬT --------- */
    int i = 0;
    token = strtok(str_parse, " \t\n\r");
    while (token) {
        words[i] = strdup(token);
        if (!words[i]) {
            for (int j = 0; j < i; j++)
                free(words[j]);
            free(words);
            free(str_count);
            free(str_parse);
            *count = 0;
            return NULL;
        }
        i++;
        token = strtok(NULL, " \t\n\r");
    }

    words[i] = NULL;
    *count = i;

    free(str_count);
    free(str_parse);
    return words;
}

/* Hàm giải phóng bộ nhớ sau khi dùng */
void free_parsed_words(char **words, int count) {
    if (!words) return;
    for (int i = 0; i < count; i++) {
        free(words[i]);
    }
    free(words);
}

const char *extract_ip_from_cidr(const char *cidr) {
    if (!cidr) return NULL;

    static char ip_buf[INET6_ADDRSTRLEN];  // Buffer tĩnh để trả về (thread-safe nếu không đa luồng)

    // Tìm vị trí dấu '/'
    const char *slash = strchr(cidr, '/');
    if (!slash) {
        // Không có prefix → toàn bộ là IP
        strncpy(ip_buf, cidr, sizeof(ip_buf) - 1);
        ip_buf[sizeof(ip_buf) - 1] = '\0';
        return ip_buf;
    }

    // Có '/' → copy phần trước dấu '/'
    size_t ip_len = slash - cidr;
    if (ip_len >= sizeof(ip_buf)) {
        return NULL;  // IP quá dài
    }

    strncpy(ip_buf, cidr, ip_len);
    ip_buf[ip_len] = '\0';

    return ip_buf;
}

void action_handle (char **word, int count, int socket_fd) {
    printf ("check : %s %s %s \n", word[0], word[1], word[2]);
    if (!strcmp (word[0], "link")) {
        netl_iface_info my_iface_info;
        if (!strcmp (word[1], "show")) {
            if (count == 2) {
            // my_nl_tool link show
                if ( iface_link_show (&my_iface_info, socket_fd) ) {
                    printf (" ******* Get all interfaces info OK ! *******\n");
                    return ;
                }
                else {
                    printf (" ******* Get all interfaces info FAILED ! *******\n");
                    return ;                    
                }
            }
            //my_nl_tool link show <iface>
            int i = if_nametoindex (word[2]);
            if (i == 0) {
                printf ("Can not detect interface %s\n", word[2]);
                return ;
            }

            if (iface_link_show_i (&my_iface_info, socket_fd, i)) {
                printf (" ******* Get interface info OK ! *******\n");
                return ;                        
            }
            else {
                printf (" ******* Get interface info FAILED ! *******\n");
                return ;   
            }
        }

        else if (!strcmp (word[1], "up")) {
            if (count < 3) {
                printf ("You have not provide interface !\n");
                return ;
            }
            //my_nl_tool link up <iface>
            int i = if_nametoindex (word[2]);
            if (i == 0) {
                printf ("Can not detect interface %s\n", word[2]);
                return ;                    
            }
            if (iface_set_up_i (&my_iface_info, socket_fd, i)) {
                printf (" ******* UP interface OK ! *******\n");
                return ;                        
            }
            else {
                printf (" ******* UP interface FAILED ! *******\n");
                return ;   
            }                    
        }

        else if (!strcmp (word[1], "down")) {
            if (count < 3) {
                printf ("You have not provide interface !\n");
                return ;
            }
            //my_nl_tool link down <iface>
            int i = if_nametoindex (word[2]);
            if (i == 0) {
                printf ("Can not detect interface %s\n", word[2]);
                return ;                    
            }
            if (iface_set_down_i (&my_iface_info, socket_fd, i)) {
                printf (" ******* DOWN interface OK ! *******\n");
                return ;                        
            }
            else {
                printf (" ******* DOWN interface FAILED ! *******\n");
                return ;   
            }                    
        }
        else if (!strcmp (word[1],"mtu")) {
            if (count < 3) {
                printf ("You have not provide interface !\n");
                return ;                
            }
            //my_nl_tool link mtu <iface> <mtu>
            int i = if_nametoindex (word[2]);
            if (i == 0) {
                printf ("Can not detect interface %s\n", word[2]);
                return ;                        
            }
            if (iface_set_MTU_i (&my_iface_info, socket_fd, i, atoi (word[3]))) {
                printf (" ******* SET MTU OK ! *******\n");
                return ;                        
            }
            else {
                printf (" ******* SET MTU FAILED ! *******\n");
                return ;   
            }                       
        }
        else {
            printf ("Incorrect command !");
            return ;
        }
    }

    if (!strcmp (word[0], "addr")) {
        netl_iface_ip my_netl_ip;
        if (!strcmp (word[1], "add")) {
            if (count < 4) {
                printf ("Incorrect command !");
                return ;
            }
            // my_nl_tool addr add <IP/24> dev <iface>
            char *ip = extract_ip_from_cidr(word[2]);
            int i = if_nametoindex (word[4]);
            if ( i == 0) {
                printf ("Can not detect interface %s\n", word[4]);
                return ;                     
            }
            if (iface_set_ip(&my_netl_ip, i, ip, socket_fd)){
                printf (" ******* SET IP interface OK ! *******\n");
                return ;                        
            }
            else {
                printf (" ******* SET IP interface FAILED! *******\n");
                return ;                   
            }
        }
        else if (!strcmp (word[1], "del")) {
            if (count < 4) {
                printf ("Incorrect command !");
                return ;
            }
            // my_nl_tool addr del <IP/24> dev <iface>
            char *ip = extract_ip_from_cidr(word[2]);
            int i = if_nametoindex (word[4]);
            if ( i == 0) {
                printf ("Can not detect interface %s\n", word[4]);
                return ;                     
            }
            if (iface_del_ip(&my_netl_ip, i, ip, socket_fd)){
                printf (" ******* DEL IP interface OK ! *******\n");
                return ;                        
            }
            else {
                printf (" ******* DEL IP interface FAILED! *******\n");
                return ;                   
            }            
        }
        else {
            printf ("Incorrect command !");
            return ;            
        }
    }

    else if (!strcmp (word[0], "route")) {
        netl_iface_route my_netl_route;
        if (!strcmp (word[1], "show")){
            if (count < 2) {
                printf ("Incorrect command !");
                return ;
            }
            // my_nl_tool route show
            if (iface_show_route(&my_netl_route, socket_fd)) {
                printf (" ******* SHOW all interface route OK ! *******\n");
                return;
            }
            else {
                printf (" ******* SHOW all interface route FAILED ! *******\n");
                return;                
            }
        }
        else if (!strcmp (word[1], "add")) {
            if (count < 7) {
                printf ("Incorrect command !");
                return ;
            }
            char gw_ip[16];
            strcpy (gw_ip, word[4]);
            int i = if_nametoindex (word[6]);
            if (! strcmp (word[2], "default")) {
                // my_nl_tool route add default via <gw_ip> dev <iface>
                if (iface_add_route_default (&my_netl_route, socket_fd, gw_ip, i)) {
                    printf (" ******* ADD interface route OK ! *******\n");
                    return ;
                }
                else {
                    printf (" ******* ADD interface route FAILED ! *******\n");
                    return ;                    
                }
            }
            else {
                //my_nl_tool route add <des_ip> via <gw_ip> dev <iface>     
                char des_ip[16];
                strcpy (des_ip, word[2]);
                if (iface_add_route_normal (&my_netl_route, socket_fd, des_ip, gw_ip, i, 32)) {
                    printf (" ******* ADD interface route OK ! *******\n");
                    return;
                }
                else {
                    printf (" ******* ADD interface route FAILED ! *******\n");
                    return;                
                }
            }
        }

        else if (!strcmp (word[1], "del")) {
           if (count < 7) {
                printf ("Incorrect command !");
                return ;
            }
            //my_nl_tool route del <des_ip> via <gw_ip> dev <iface>
            char des_ip[16];
            strcpy (des_ip, word[2]);
            char gw_ip[16];
            strcpy (gw_ip, word[4]);
            int i = if_nametoindex (word[6]);   
            if (iface_del_route (&my_netl_route, socket_fd, des_ip, gw_ip, i, 32)) {
                printf (" ******* DEL interface route OK ! *******\n");
                return;                
            }  
            else {
                printf (" ******* DEL interface route FAILED ! *******\n");
                return;
            }                   
        }
        else {
            printf ("Incorrect command !");
            return ;            
        }
    }
    else {
        printf ("Incorrect command !");
        return ;            
    }

    close(socket_fd);
}