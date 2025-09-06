#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FILENAME "weather_response.txt"
#define BUFFER_SIZE 4096

void extract_data(char *line, char *temp_str, char *humidity_str, char *city_name, char *status);
char *get_last_line(FILE *fp) ;
void get_data(char *temp_str, char *humidity_str, char *city_name, char *status);