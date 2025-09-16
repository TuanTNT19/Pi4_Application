CC = aarch64-openwrt-linux-musl-gcc
CFLAGS = -Wall -I$(STAGING_DIR)/usr/include
LDFLAGS = -L$(STAGING_DIR)/usr/lib -lnetfilter_queue -lcurl

all: main

main: main.c
	$(CC) $(CFLAGS) main.c -o main $(LDFLAGS)

clean:
	rm -f main