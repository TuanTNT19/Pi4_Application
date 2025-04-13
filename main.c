#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define LED_DEVICE_PATH "/dev/my_led23_device"

int fd;

// Clear the terminal
void clrscr() {
    system("clear");
    return;
}

int main() {
    char *chosen = malloc(10 * sizeof(char));
    fd = open(LED_DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        perror("Failed to open device");
        return 1;
    }

    while(1){
        do
        {
            printf("1. Led ON\n");
            printf("0. Led OFF\n");
            printf("q. Quit Program\n");
            printf("Enter your chosen: ");
            fgets(chosen, 10, stdin);
            if (chosen[0] != '1' && chosen[0] != '0' && chosen[0] != 'q'){
                printf("Invalid chosen !! Do again \n");
            }
        } while (chosen[0] != '1' && chosen[0] != '0' && chosen[0] != 'q');

        if (chosen[0] == '1'){
            int ret = write (fd, "1", 1);
            if (ret == -1)
            {
                printf("Can not write 1\n");
            }
        }
        else if (chosen[0] == '0'){
            int ret = write (fd, "0", 1);
            if (ret == -1)
            {
                printf("Can not write 0\n");
            }            
        }
        else {
            break;
        }
    }

    close (fd);
    return 0;
}