all:
	gcc main.c src/* -I./inc -o main -pthread
clean: 
	rm -rf main
