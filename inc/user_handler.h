#pragma once

#include "interface_tool.h"

void print_help();
char **parse_func(const char *str, int *count);
/* Hàm giải phóng bộ nhớ sau khi dùng */
void free_parsed_words(char **words, int count);
const char *extract_ip_from_cidr(const char *cidr);
void action_handle (char **word, int count, int socket_fd) ;