# include "ssd1306.h"

void SSD1306_Clear(int fd) {
    int ret = write(fd, "clear", sizeof("clear"));
    if (ret <= 0) {
        PR_ERR("SSD1306_Clear");
        return ;
    }
}

void SSD1306_SetCursor(int fd, int line, int col){
    char buff[10];
    const char *cmd = "cursor";
    sprintf (buff, "%s %d %d", cmd, line, col);
    
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