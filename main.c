#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/socket.h>      
#include <netinet/in.h>     
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>

#define CONNECT_TOKEN "Tuan08*"
#define PR_ERR(str)  printf ("!!! Error in %s function\n", str)

int ser_fd;
char *message_r;
char *token;

void sig_handler()
{
    printf("========= QUICK TURN OFF ========\n");
    close (ser_fd);
    free(message_r);
    free(token);
    exit(EXIT_SUCCESS);
}

int main(){
    struct sockaddr_in ser_addr, cli_addr;
    socklen_t len = sizeof (struct sockaddr_in);
    int ser_port;
    message_r = malloc (20);
    token = malloc (10);
    bool ret = false;

    if (signal(SIGINT,sig_handler) == SIG_ERR)
    {
        printf("Can not handler SIGINT\n");
    }

    printf ("Enter your server port you want to open : ");
    fflush(stdout);
    scanf ("%d", &ser_port);
    getchar();

    ser_fd = socket (AF_INET, SOCK_DGRAM, 0);
    if (ser_fd < 0){
        PR_ERR ("socket");
    }

    ser_addr.sin_family = AF_INET;
    ser_addr.sin_port = htons(ser_port);
    ser_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(ser_fd, (struct sockaddr *) &ser_addr, sizeof(struct sockaddr_in)) < 0){
        PR_ERR("bind");
    }

    while (1){
        int n = recvfrom (ser_fd, token, 20, 0, (struct sockaddr *) &cli_addr, &len);
        token[n] = '\0';
        if (!strncmp (CONNECT_TOKEN, token, 7)) {
            int cli_port;
            char cli_ip[20];
            cli_port = ntohs (cli_addr.sin_port);
            inet_ntop (AF_INET, &cli_addr.sin_addr.s_addr, cli_ip, 20);
            printf ("--->Got connection from client at IP: %s - Port: %d \n", cli_ip, cli_port);
            sendto(ser_fd, "1", 1, 0, (struct sockaddr *)&cli_addr, len);
            break; 
        }
        else {
            printf ("!!! Wrong Token ---> Can not connect to client\n");
            sendto(ser_fd, "0", 1, 0, (struct sockaddr *)&cli_addr, len);
        }
    }

    while (1){
        recvfrom (ser_fd, message_r, 20, 0, (struct sockaddr *) &cli_addr, &len);
        printf ("Message Receive from client : %s\n", message_r);
    }

    return 0;
    
}