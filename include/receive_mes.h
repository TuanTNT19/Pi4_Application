#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/socket.h>      
#include <netinet/in.h>     
#include <arpa/inet.h>
#include <unistd.h>

#define CONNECT_TOKEN "Tuan08*"
#define PR_ERR(str)  printf ("!!! Error in %s function\n", str)

void SocketUdp_Configure(int *ser_fd, struct sockaddr_in *ser_addr, int port);
void Authen_Check(int ser_fd, struct sockaddr_in *cli_addr);
int Mes_Receive(int ser_fd, struct sockaddr_in *cli_addr, char *mess);
