daemon: daemon.c
	gcc daemon.c -lsqlite3 -o daemon
write:
	gcc test_write.c -o test_write
translate:
	gcc translate.c -o vtop
clean:
	rm daemon
