all: ssd1306_handle

ssd1306_handle:
	$(CC) $(CFLAGS) -I./include -o ssd1306_handle main.c src/*

clean:
	rm -f ssh1306_handle ssd1306_handle.o

%.o: %.c
	$(CC) $(CFLAGS) -c $<
