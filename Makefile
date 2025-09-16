all: main

main: 
	$(CC) $(CFLAGS) main.c  -o main -lnetfilter_queue -lcurl
clean:
	rm -f main 

%.o: %.c
	$(CC) $(CFLAGS) -c $<