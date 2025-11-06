all: ARP_Proxy

ARP_Proxy:
	$(CXX) $(CXXFLAGS) -o ARP_Proxy ARP_Proxy.cpp -ltins -lpthread

clean:
	rm -f ARP_Proxy ARP_Proxy.o

%.o: %.c
	$(CXX) $(CXXFLAGS) -c $<