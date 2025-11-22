all: dhcp_server

dhcp_server:
	$(CXX) $(CXXFLAGS) -o dhcp_server dhcp_server.cpp -ltins

clean:
	rm -f dhcp_server dhcp_server.o

%.o: %.c
	$(CXX) $(CXXFLAGS) -c $<