CFLAGS=-c -std=c99 -O0 -g -ggdb -Wall -pedantic -Wall
# Remove after I translate the code from Polish
CFLAGS+=-Wno-invalid-source-encoding

kmnsim:			\
	all.o		\
	strdup.o	\
	strsep.o	\
	strlcat.o	\
	strlcpy.o
	gcc -g -ggdb -o kmnsim	\
	all.o		\
	strdup.o	\
	strsep.o	\
	strlcat.o	\
	strlcpy.o

# 
# Helper routines. Shouldn't touch UNIX, but must get enabled
# on Windows. Thus, every file has _WIN32 #ifdef'ed.
#
all.o: all.c queue.h kmnsim.h Makefile
	gcc ${CFLAGS} -o all.o all.c
strdup.o: subr/strdup.c
	gcc ${CFLAGS} -o strdup.o subr/strdup.c
strsep.o: subr/strsep.c
	gcc ${CFLAGS} -o strsep.o subr/strsep.c
strlcpy.o: subr/strlcpy.c
	gcc ${CFLAGS} -o strlcpy.o subr/strlcpy.c
strlcat.o: subr/strlcat.c
	gcc ${CFLAGS} -o strlcat.o subr/strlcat.c

t:
	./kmnsim -a -dd -v ../conf/spec.1
#	./kmnsim -a -dd -v ../conf/spec.5
	./kmnsim -a -dd -v ../conf/spec.6
	./kmnsim -a -dd -v ../conf/spec.7
	./kmnsim -a -dd -v ../conf/spec.8
	./kmnsim -a -dd -v ../conf/spec.9
	./kmnsim -a -dd -v ../conf/spec.10
	./kmnsim -a -dd -v ../conf/spec.11

clean:
	rm -rf kmnsim *.o
