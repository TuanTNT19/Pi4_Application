all: my_nl_tool

my_nl_tool: 
	$(CC) $(CFLAGS) main.c src/* -I./inc -o my_ip -pthread
clean:
	rm -f my_ip 

%.o: %.c
	$(CC) $(CFLAGS) -c $<
