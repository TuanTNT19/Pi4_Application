CC = aarch64-openwrt-linux-musl-gcc
CFLAGS = -Wall -I$(STAGING_DIR)/usr/include

all: main

main: main.c
	$(CC) $(CFLAGS) main.c -o main $(LDFLAGS) -lnetfilter_queue -lcurl

clean:
	rm -f main