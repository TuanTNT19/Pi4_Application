#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <curl/curl.h>

#define WEATHER_SERVER_LINK "http://api.openweathermap.org/data/2.5/weather?q=Hanoi,vn&appid=b2ae43a1bc001705637aa0c78a24f41d&units=metric"
#define KEY_NUMBER 3
#define OUTPUT_FILE "weather_response.txt" 
#define HEADER_FILE "weather_headers.txt"  

typedef struct {
    char key[23];
    char value[25];
} http_header;

size_t output_callback(void *ptr, size_t size, size_t nmemb, int *fd);
size_t header_callback(void *ptr, size_t size, size_t nmemb, int *fd);
bool http_setup_request_line (CURL **curl, char *path);
void http_setup_header(CURL *curl, struct curl_slist **header_list, http_header *header, int total_key );
void print_headers(struct curl_slist *list);
void http_data_prepare(CURL **curl, struct curl_slist **header_list, http_header *header, int *body_fp, int *header_fp) ;
void http_post(CURL *curl);