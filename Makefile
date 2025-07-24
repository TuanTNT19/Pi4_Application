all: tun_app

tun_app: main.o
	$(CC) $(CFLAGS) -o tun_app main.o

clean:
	rm -f tun_app main.o

%.o: %.c
	$(CC) $(CFLAGS) -c $<