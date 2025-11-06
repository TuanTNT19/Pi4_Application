all: ARP_Proxy

ARP_Proxy:
	$(CC) $(CFLAGS) -o ARP_Proxy ARP_Proxy.cpp

clean:
	rm -f ARP_Proxy ARP_Proxy.o

%.o: %.c
	$(CC) $(CFLAGS) -c $<