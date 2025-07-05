#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h> 

#define PR_ERR(str)  printf ("!!! Error in %s function\n", str)
#define SSD1306_DEV_FILE    "/dev/my_device_ssd"

int SSD1306_OpenDevFile(char *file_path);
void SSD1306_Clear(int fd);
void SSD1306_SetCursor(int fd, int line, int col);
void SSD1306_SetString(int fd, char *mes);
void SSD1306_PrintString(int fd, int line, int col, char *mes);