# include "http_handle.h"
# include "file_handle.h"
# include "ssd1306.h"
# include <signal.h>

#define SSD1306_DEV_FILE    "/dev/my_device_ssd"

CURL *my_curl = NULL;
struct curl_slist *my_header_list = NULL;
http_header *my_header;
char *temp_str;
char *humidity_str;
char *city_name;
char *status;
int ssd1306_fd;
int output_fd;
int header_fd;

bool dns_setting() {
    int result = system("/usr//bin/set_dns");
    if (result == -1) {
        printf("ERROR: Can not setting dns");
        return false;
    }
    return true;
}

void sig_handler()
{
    printf("========= QUICK TURN OFF ========\n");
    SSD1306_Clear(ssd1306_fd);
    SSD1306_PrintString (ssd1306_fd, 4, 9, "SHUT DOWN");
    close(output_fd);
    close(header_fd);
    close(ssd1306_fd);
    curl_easy_cleanup(my_curl);
    curl_slist_free_all(my_header_list);
    free(my_header);   
    free (temp_str);
    free (humidity_str);
    free (city_name);
    free (status); 
}

int main() {
    ssd1306_fd = SSD1306_OpenDevFile (SSD1306_DEV_FILE);
    my_header = (http_header *) malloc (KEY_NUMBER * (sizeof(http_header)));
    temp_str = (char *)malloc (10 * sizeof (char));
    humidity_str = (char *)malloc (10 * sizeof (char));
    city_name = (char *)malloc (50 * sizeof (char));
    status = (char *)malloc (50 * sizeof (char));

    if (signal(SIGINT,sig_handler) == SIG_ERR)
    {
        printf("Can not handler SIGINT\n");
    }

    if (!dns_setting()) {
        return -1;
    }

    output_fd = open (OUTPUT_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    header_fd = open (HEADER_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    
    if (output_fd < 0 || header_fd < 0) {
        printf ("ERROR: Can not open file \n");
        return -1;
    }

    http_data_prepare (&my_curl, &my_header_list, my_header, &output_fd, &header_fd);
    print_headers(my_header_list); 

    SSD1306_Clear(ssd1306_fd);
    SSD1306_PrintString (ssd1306_fd, 1, 5, "Weather Tracking APP");
    while (1) {
        char *t_str = (char *) malloc (50 * (sizeof (char)));
        http_post (my_curl);
        get_data(temp_str, humidity_str, city_name, status);
        printf("City: %s, Temp: %s, Humidity: %s, Status: %s\n", city_name, temp_str, humidity_str, status);
        sprintf (t_str, "City     : %s", city_name);
        SSD1306_PrintString (ssd1306_fd, 3, 6, t_str);
        sprintf (t_str, "Humidity : %s", humidity_str);
        SSD1306_PrintString (ssd1306_fd, 4, 6, t_str);
        sprintf (t_str, "Temp     : %s", temp_str);
        SSD1306_PrintString (ssd1306_fd, 5, 6, t_str);
        sprintf (t_str, " %s", status);
        SSD1306_PrintString (ssd1306_fd, 6, 6, t_str);
        free (t_str);
        sleep (3);
    }

    // Đóng file descriptor
    close(output_fd);
    close(header_fd);
    curl_easy_cleanup(my_curl);
    curl_slist_free_all(my_header_list);
    free(my_header);    
    free (temp_str);
    free (humidity_str);
    free (city_name);
    free (status);

    return 0;

}