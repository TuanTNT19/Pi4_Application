#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>      
#include <netinet/in.h>     
#include <arpa/inet.h>

#define LED_DEVICE_PATH "/dev/my_led23_device"

int ser_fd, dev_fd;
struct sockaddr_in ser_addr;
int PC_Port;
char *PC_IP;
char *message;

// Signal handler function
void sig_handler()
{
    printf("========= QUICK TURN OFF ========\n");
    free (message);
    free (PC_IP);
    close (ser_fd);
    close (dev_fd);
    exit(EXIT_SUCCESS);
}

// Clear the terminal
void clrscr() {
    system("clear");
    return;
}

int read_func(int fd, char *msg){
    return read(fd, msg, 20);
}

int main(){
    PC_IP = malloc(20);
    message = malloc(20);

// Signal Ctrl C register
    if (signal(SIGINT,sig_handler) == SIG_ERR)
    {
        printf("Can not handler SIGINT\n");
    }

    printf("Enter PC IP: ");
    fflush(stdout);
    fgets(PC_IP, 20, stdin);
    PC_IP[strcspn(PC_IP, "\n")] = '\0'; // Xóa \n
    printf("Enter PC Port: "); 
    fflush(stdout);
    scanf("%d", &PC_Port);
    getchar(); 

    dev_fd = open(LED_DEVICE_PATH, O_RDWR);
    if (dev_fd < 0) {
        perror("Failed to open device");
        sig_handler();
        return -1;
    }

    ser_fd = socket(AF_INET, SOCK_STREAM, 0);

    ser_addr.sin_port = htons(PC_Port);
    ser_addr.sin_family = AF_INET;
    inet_pton(AF_INET, PC_IP, &ser_addr.sin_addr.s_addr);

    int ret = connect(ser_fd, (struct sockaddr *)&ser_addr, sizeof(ser_addr));
    if (ret  < 0){
        printf("=== ERROR ===: Can not connect to PC\n");
        sig_handler();
        return -1;
    }

    printf("=========== Connected with PC =========== \n");

    while (1) {
        if (read_func (ser_fd, message) < 0){
            printf("=== ERROR ===: Can not read message from PC\n");
        }
        if (message[0] == '1'){
            int re = write (dev_fd, "1", 1);
            if (re == -1)
            {
                printf("=== ERROR ===: Can not write 1 to device file\n");
            }
        }
        else if (message[0] == '0'){
            int re = write (dev_fd, "0", 1);
            if (re == -1)
            {
                printf("=== ERROR ===: Can not write 0 to device file\n");
            }
        }
        else if (message[0] == 'q'){
            printf ("Disconnect with PC !\n");
            break;
        }
        else {
            break;
        }
    }

    free (message);
    free (PC_IP);
    close (ser_fd);
    close (dev_fd);

    return 0;

}