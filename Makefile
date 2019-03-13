server:
	nasm -f elf64 -o server.o server.s
	ld server.o -o server

clean:
	rm -f server.o server
