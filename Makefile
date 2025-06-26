all: main

main: 
	$(CC) $(CFLAGS) -I./include -o main main.c src/*

clean:
	rm -f main main.o

%.o: %.c
	$(CC) $(CFLAGS) -c $<
