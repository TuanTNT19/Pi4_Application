#include "receive_mes.h"
#include "ssd1306.h"
#include <signal.h>

int server_fd;
struct sockaddr_in server_addr, client_addr;
int port;
char *message, *mes_display;
int col, line;
int fd;

void sig_handler()
{
    printf("========= QUICK TURN OFF ========\n");
    close (server_fd);
    close (fd);
    free(message);
    free(mes_display);
    exit(EXIT_SUCCESS);
}

int main() {
    message = malloc (50);
    mes_display = malloc (45);
    
    fd = SSD1306_OpenDevFile (SSD1306_DEV_FILE);

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
        printf ("Message receive : %s\n", message);
        SSD1306_Clear(fd);
        sscanf (message, "%d %d %[^\n]", &line, &col, mes_display);
        printf ("line %d col %d mes_display %s\n", line, col, mes_display);
        SSD1306_PrintString (fd, line, col, mes_display);
    }
}