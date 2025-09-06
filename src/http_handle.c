# include "http_handle.h"

size_t output_callback(void *ptr, size_t size, size_t nmemb, int *fd) {
    size_t realsize = size * nmemb;
    size_t w = write (*fd, ptr, realsize);
    if ( w = realsize ) {
        const char newline[] = "\n";
        write(*fd, newline, 1);        
    }
    return w; 
}

size_t header_callback(void *ptr, size_t size, size_t nmemb, int *fd) {
    size_t realsize = size * nmemb;
    size_t w = write (*fd, ptr, realsize);
    return w;
}

bool http_setup_request_line (CURL **curl, char *path) {
    *curl = curl_easy_init();
    if (*curl == NULL) {
        printf ("ERROR: Can not init http by curl \n");
        return false;
    }

    // Set http path for request line in http request message
    CURLcode URL_RET = curl_easy_setopt (*curl, CURLOPT_URL, path);
    if (CURLE_OK != URL_RET) {
        printf("ERROR: Can not setup path for http request line\n");
        return false;
    } 

    return true;
}

void http_setup_header(CURL *curl, struct curl_slist **header_list, http_header *header, int total_key ) {
    for (int i = 0; i < total_key; i++) {
        char *str = (char *)malloc (50 * sizeof (char));
        sprintf (str, "%s: %s", header[i].key, header[i].value);
        *header_list = curl_slist_append (*header_list, str);
        free (str);
    }

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, *header_list);
}


// Hàm in các phần tử trong header_list
void print_headers(struct curl_slist *list) {
    int index = 0;
    while (list != NULL) {
        printf("Header [%d]: %s\n", index++, list->data);
        list = list->next;
    }
}

void http_data_prepare(CURL **curl, struct curl_slist **header_list, http_header *header, int *body_fp, int *header_fp) {
    if (!http_setup_request_line(curl, WEATHER_SERVER_LINK)) {
        return; // Thoát nếu khởi tạo thất bại
    }

    strcpy(header[0].key, "User-Agent");
    strcpy(header[0].value, "tnt19_weather_tracking");
    strcpy(header[1].key, "Accept");
    strcpy(header[1].value, "application/json");
    strcpy(header[2].key, "Connection");
    strcpy(header[2].value, "close");
    http_setup_header(*curl, header_list, header, KEY_NUMBER);
    print_headers(*header_list);

    curl_easy_setopt(*curl, CURLOPT_WRITEFUNCTION, output_callback);
    curl_easy_setopt(*curl, CURLOPT_WRITEDATA, body_fp);
    curl_easy_setopt(*curl, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(*curl, CURLOPT_HEADERDATA, header_fp);
}

void http_post(CURL *curl) {
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    } else {
        printf("Data has been written to %s and %s\n", OUTPUT_FILE, HEADER_FILE);
    }
}