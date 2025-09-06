# include "http_handle.h"
# include "file_handle.h"

int main() {
    CURL *my_curl = NULL;
    struct curl_slist *my_header_list = NULL;
    http_header *my_header = (http_header *) malloc (KEY_NUMBER * (sizeof(http_header)));
    char *temp_str = (char *)malloc (10 * sizeof (char));
    char *humidity_str = (char *)malloc (10 * sizeof (char));
    char *city_name = (char *)malloc (50 * sizeof (char));
    char *status = (char *)malloc (50 * sizeof (char));

    int output_fd = open (OUTPUT_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    int header_fd = open (HEADER_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    
    if (output_fd < 0 || header_fd < 0) {
        printf ("ERROR: Can not open file \n");
        return -1;
    }

    http_data_prepare (&my_curl, &my_header_list, my_header, &output_fd, &header_fd);
    print_headers(my_header_list); 
    while (1) {
        http_post (my_curl);
        get_data(temp_str, humidity_str, city_name, status);
        printf("City: %s, Temp: %s, Humidity: %s, Status: %s\n", city_name, temp_str, humidity_str, status);
        sleep (3);
    }

    // Đóng file descriptor
    close(output_fd);
    close(header_fd);
    curl_easy_cleanup(my_curl);
    curl_slist_free_all(my_header_list);
    free(my_header);    

    return 0;

}