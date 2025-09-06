all: weather_track

weather_track: 
	$(CC) $(CFLAGS) weather_track.c src/* -I./inc -o weather_track -lcurl
clean:
	rm -f weather_track 

%.o: %.c
	$(CC) $(CFLAGS) -c $<