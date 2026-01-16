#pragma once

#include <stdio.h>
#include <stdbool.h> 
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>

static int process_mess (struct nlmsghdr *header, int len);
void display (int fd);

