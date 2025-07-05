# include "ssd1306.h"

int SSD1306_OpenDevFile(char *file_path){
    int fd = open(file_path, O_WRONLY);
    if (fd < 0){
        PR_ERR("SSD1306_Clear");
        printf (">>>> Please check device file in /dev/ !!!!\n");
        return -1;
    }
    return fd;
}
void SSD1306_Clear(int fd) {
    int ret = write(fd, "clear", sizeof("clear"));
    if (ret <= 0) {
        PR_ERR("SSD1306_Clear");
        return ;
    }
}

void SSD1306_SetCursor(int fd, int line, int col){
    char buff[15];
    const char *cmd = "cursor";
    sprintf (buff, "%s %d %d", cmd, col, line);
    
    int ret = write(fd, buff, sizeof(buff));
    if (ret <= 0) {
        PR_ERR("SSD1306_SetCursor");
        return ;
    }
}

void SSD1306_SetString(int fd, char *mes) {
    int ret = write(fd, mes, strlen(mes));
    if (ret <= 0) {
        PR_ERR("SSD1306_SetString");
        return ;
    }
}

void SSD1306_PrintString(int fd, int line, int col, char *mes) {
    SSD1306_SetCursor(fd, line, col);
    SSD1306_SetString(fd, mes);
}