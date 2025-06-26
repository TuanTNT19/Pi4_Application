#include "receive_mes.h"
#include "ssd1306.h"
#include <signal.h>

int server_fd;
struct sockaddr_in server_addr, client_addr;
int port;
char *message;

void sig_handler()
{
    printf("========= QUICK TURN OFF ========\n");
    close (server_fd);
    free(message);
    exit(EXIT_SUCCESS);
}

int main() {
    message = malloc (50);

    if (signal(SIGINT,sig_handler) == SIG_ERR)
    {
        printf("Can not handler SIGINT\n");
    }

    printf ("Enter your server port you want to open : ");
    fflush(stdout);
    scanf ("%d", &port);
    getchar();

    SocketUdp_Configure (&server_fd, &server_addr, port);
    Authen_Check (server_fd, &client_addr);

    while (1)
    {
        int n = Mes_Receive(server_fd, &client_addr, message);
        Mes_Receive(server_fd, &client_addr, message + n);
        printf ("Message receive : %s\n", message);
        
    }
}