all: log logserver b64hash checklog

log: log.o sha256.o
	gcc -o log log.o sha256.o

logserver: logserver.o sha256.o base64.o
	gcc -o logserver logserver.o sha256.o base64.o

b64hash: b64hash.o sha256.o base64.o
	gcc -o b64hash b64hash.o sha256.o base64.o

checklog: checklog.o sha256.o base64.o
	gcc -o checklog checklog.o sha256.o base64.o

log.o: log.c sha256.h
	gcc -c log.c

logserver.o: logserver.c sha256.h base64.h
	gcc -c logserver.c

b64hash.o: b64hash.c sha256.h base64.h
	gcc -c -O3 b64hash.c

sha256.o: sha256.c sha256.h
	gcc -O3 -c sha256.c

base64.o: base64.c base64.h
	gcc -O3 -c base64.c

clean:
	rm -f log.txt loghead.txt *.o logserver b64hash log checklog
