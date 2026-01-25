#include <pthread.h>
#include "interface_tool.h"
#include "kernel_handler.h"
#include "user_handler.h"

int socket_fd;
char user_str[4096] = {0};

void *func1 (void *arg) {
    char *str= (char *)arg;
    int count = 0;
    char **user_cmd = parse_func (str, &count);
    action_handle (user_cmd, count, socket_fd);
    free_parsed_words(user_cmd, count);
    return NULL;
}

void *func2 (void *arg) {
    while (1) {
        display(socket_fd);
        sleep(1);
    }
}

int main(int argc, char *argv[]) {
    pthread_t thr1;
    pthread_t thr2;
    socket_fd = netl_socket_create();

    for (int i = 1; i < argc; i++) {
        sprintf (user_str, "%s %s", user_str, argv[i]);
    }

    pthread_create(&thr1, NULL, func1, user_str);
    pthread_create(&thr2, NULL, func2, NULL);
    pthread_join(thr1, NULL);
    sleep (3);
    pthread_cancel(thr2);
    return 0;
}