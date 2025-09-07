#include "file_handle.h"

void extract_data(char *line, char *temp_str, char *humidity_str, char *city_name, char *status) {
    char *pos;

    // Trích xuất city name
    pos = strstr(line, "\"name\":\"");
    if (pos) {
        pos += 8; // Bỏ qua "\"name\":\""
        char *end = strchr(pos, '"');
        if (end) {
            int len = end - pos;
            strncpy(city_name, pos, len);
            city_name[len] = '\0';
        }
    }

    // Trích xuất temp
    pos = strstr(line, "\"temp\":");
    if (pos) {
        pos += 7; // Bỏ qua "\"temp\":"
        char *end = strpbrk(pos, ",}");
        if (end) {
            int len = end - pos;
            strncpy(temp_str, pos, len);
            temp_str[len] = '\0';
        }
    }

    // Trích xuất humidity
    pos = strstr(line, "\"humidity\":");
    if (pos) {
        pos += 11; // Bỏ qua "\"humidity\":"
        char *end = strpbrk(pos, ",}");
        if (end) {
            int len = end - pos;
            strncpy(humidity_str, pos, len);
            humidity_str[len] = '\0';
        }
    }

    // Trích xuất status
    pos = strstr(line, "\"description\":");
    if (pos) {
        pos += 14; // Bỏ qua "\"description\":"
        char *end = strpbrk(pos, ",}");
        if (end) {
            int len = end - pos;
            strncpy(status, pos, len);
            status[len] = '\0';
        }
    }
}

char *get_last_line(FILE *fp) {
    if (fp == NULL) {
        return NULL;
    }

    char *last_line = NULL;
    char buffer[BUFFER_SIZE];
    size_t len = 0;

    while (fgets(buffer, BUFFER_SIZE, fp) != NULL) {
        len = strlen(buffer);
        if (last_line) free(last_line);
        last_line = strdup(buffer);
    }

    return last_line;
}

void get_data(char *temp_str, char *humidity_str, char *city_name, char *status) {
    FILE *fp = fopen(FILENAME, "r");
    if (fp == NULL) {
        perror("Error opening file");
        sleep(5);
        printf("ERROR: Retrying to get weather data...\n");
    }

    char *last_line = get_last_line(fp);
    fclose(fp); // Đóng file sau khi đọc

    if (last_line) {
        extract_data(last_line, temp_str, humidity_str, city_name, status);
        free(last_line);
    } else {
        sleep(5); // Chờ nếu file trống
    }
}