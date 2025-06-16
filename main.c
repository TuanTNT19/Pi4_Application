#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/socket.h>      
#include <netinet/in.h>     
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>

#define CONNECT_TOKEN "Tuan08*"
#define PR_ERR(str)  printf ("!!! Error in %s function\n", str)

typedef struct client_info{
    int number;
    struct sockaddr_in cli_addr;
} client_info;

client_info *client;
int ser_fd;
socklen_t len;
char *token;
pthread_t *thread_id;

void sig_handler()
{
    printf("========= QUICK TURN OFF ========\n");
    close (ser_fd);
    free(token);
    free(thread_id);
    free(client);
    exit(EXIT_SUCCESS);
}

static void *mess_handle(void *para)
{
    client_info *client = (client_info *)para;
    int c;
    int Port;
    char IP[20];
    char mess[20];
    Port = ntohs (client->cli_addr.sin_port);
    inet_ntop (AF_INET, &client->cli_addr.sin_addr, IP, 20);

    while(1){
        c = recvfrom(ser_fd, mess, sizeof(mess), 0,
                         (struct sockaddr *)&client->cli_addr, &len);
        mess[c] = '\0';
        printf("***** Client %d at IP %s and Port %d *****\n", client->number, IP, Port);
        printf ("Message : %s\n", mess);
        printf ("             *********             \n");
    }
}

int main(){
    struct sockaddr_in ser_addr;
    len = sizeof (struct sockaddr_in);
    int ser_port;
    int cli_number = 0;
    token = malloc (10);
    client = malloc (5 * sizeof(client_info));
    thread_id = malloc (5 * sizeof(pthread_t));

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
        int n = recvfrom (ser_fd, token, 10, 0, (struct sockaddr *)&client[cli_number].cli_addr, &len);
        token[n] = '\0';
        if (!strncmp (CONNECT_TOKEN, token, 7)) {
            int cli_port;
            char cli_ip[20];
            client[cli_number].number = cli_number + 1;
            cli_port = ntohs (client[cli_number].cli_addr.sin_port);
            inet_ntop (AF_INET, &client[cli_number].cli_addr.sin_addr.s_addr, cli_ip, 20);
            printf ("--->Got connection from client %d at IP: %s - Port: %d \n", cli_number + 1, cli_ip, cli_port);
            sendto(ser_fd, "1", 1, 0, (struct sockaddr *)&client[cli_number].cli_addr, len);
            pthread_create(&thread_id[cli_number], NULL, &mess_handle, &client[cli_number]);
            cli_number ++;
        }
    }

    return 0;
    
}