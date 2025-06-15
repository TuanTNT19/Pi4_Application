all: main

main: main.o
	$(CC) $(CFLAGS) -o main main.o

clean:
	rm -f main main.o

%.o: %.c
	$(CC) $(CFLAGS) -c $<
