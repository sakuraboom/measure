daemon: daemon.c
	gcc daemon.c -lsqlite3 -o daemon
write:test_write.c
	gcc test_write.c -o test_write
read:test_read.c
	gcc test_read.c -o test_read 
translate:
	gcc translate.c -o vtop
clean:
	rm daemon
