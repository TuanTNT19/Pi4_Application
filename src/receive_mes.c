#include "receive_mes.h"

void SocketUdp_Configure(int *ser_fd, struct sockaddr_in *ser_addr, int port){
    *ser_fd = socket (AF_INET, SOCK_DGRAM, 0);
    if (*ser_fd < 0){
        PR_ERR ("SocketUdp_Open");
        PR_ERR ("socket");
        return ;
    }

    ser_addr->sin_family = AF_INET;
    ser_addr->sin_port = htons(port);
    ser_addr->sin_addr.s_addr = INADDR_ANY;

    if (bind(*ser_fd, (struct sockaddr *) ser_addr, sizeof(struct sockaddr_in)) < 0){
        PR_ERR ("SocketUdp_Open");
        PR_ERR("bind");
        return ;
    }
}

void Authen_Check(int ser_fd, struct sockaddr_in *cli_addr)
{
    char token[10];
    socklen_t len = sizeof (struct sockaddr_in);
    int n = 0;

    while(1)
    {
        n = recvfrom (ser_fd, token, 10, 0, (struct sockaddr *) cli_addr, &len);
        if (n < 0){
            PR_ERR ("Authen_Check");
            PR_ERR ("recvfrom");
            return ;
        }
        token[n] = '\0';
        if (!strncmp (CONNECT_TOKEN, token, 7)) {
            int cli_port;
            char cli_ip[20];
            cli_port = ntohs (cli_addr->sin_port);
            inet_ntop (AF_INET, &cli_addr->sin_addr.s_addr, cli_ip, 20);
            printf ("--->Got connection from client at IP: %s - Port: %d \n", cli_ip, cli_port);
            sendto(ser_fd, "1", 1, 0, (struct sockaddr *)cli_addr, len);
            break; 
        }
        else {
            printf ("!!! Wrong Token ---> Can not connect to client\n");
            sendto(ser_fd, "0", 1, 0, (struct sockaddr *)cli_addr, len);
        }
    }
}

int Mes_Receive(int ser_fd, struct sockaddr_in *cli_addr, char *mess) {
    socklen_t len = sizeof (struct sockaddr_in);
    int n = recvfrom (ser_fd, mess, 50, 0, (struct sockaddr *) cli_addr, &len);
    if (n <= 0) {
        PR_ERR ("Mes_Receive");
        PR_ERR ("recvfrom");
        return 0;
    }
    mess[n] = '\0';
    
    return n;
}
