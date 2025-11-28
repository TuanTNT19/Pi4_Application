all: dhcp_server

dhcp_server:
	$(CC) $(CFLAGS) -o dhcp_server dhcp_server.o -lpcap

clean:
	rm -f dhcp_server dhcp_server.o

%.o: %.c
	$(CC) $(CFLAGS) -c $<