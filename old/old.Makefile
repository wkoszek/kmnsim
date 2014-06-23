all: kmnsim

CFLAGS=-c -std=c99 -g -ggdb -Wall -pedantic -Wall

cmd.o: cmd.c queue.h kmnsim.h Makefile
	gcc ${CFLAGS} -o cmd.o cmd.c
cmds.o: cmds.c queue.h kmnsim.h Makefile
	gcc ${CFLAGS} -o cmds.o cmds.c
host.o: host.c queue.h kmnsim.h Makefile
	gcc ${CFLAGS} -o host.o host.c
hub.o: hub.c queue.h kmnsim.h Makefile
	gcc ${CFLAGS} -o hub.o hub.c
iface.o: iface.c queue.h kmnsim.h Makefile
	gcc ${CFLAGS} -o iface.o iface.c
nid.o: nid.c queue.h kmnsim.h Makefile
	gcc ${CFLAGS} -o nid.o nid.c
kmnsim.o: kmnsim.c queue.h kmnsim.h Makefile
	gcc ${CFLAGS} -o kmnsim.o kmnsim.c
router.o: router.c queue.h kmnsim.h Makefile
	gcc ${CFLAGS} -o router.o router.c
global.o: global.c queue.h kmnsim.h Makefile
	gcc ${CFLAGS} -o global.o global.c
subr.o: subr.c queue.h kmnsim.h Makefile
	gcc ${CFLAGS} -o subr.o subr.c

# 
# Helper routines. Shouldn't touch UNIX, but must get enabled
# on Windows. Thus, every file has _WIN32 #ifdef'ed.
#
strdup.o: subr/strdup.c
	gcc ${CFLAGS} -o strdup.o subr/strdup.c
strsep.o: subr/strsep.c
	gcc ${CFLAGS} -o strsep.o subr/strsep.c
strlcpy.o: subr/strlcpy.c
	gcc ${CFLAGS} -o strlcpy.o subr/strlcpy.c
strlcat.o: subr/strlcat.c
	gcc ${CFLAGS} -o strlcat.o subr/strlcat.c

kmnsim:			\
	cmd.o		\
	cmds.o		\
	host.o		\
	hub.o		\
	iface.o		\
	nid.o		\
	subr.o		\
	router.o	\
	global.o	\
	strdup.o	\
	strsep.o	\
	kmnsim.o
	gcc *.o -o kmnsim

clean:
	rm -rf kmnsim *.o
