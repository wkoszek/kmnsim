CFLAGS=-c -std=c99 -O0 -g -ggdb -Wall -pedantic -Wall
# Remove after I translate the code from Polish
CFLAGS+=-Wno-invalid-source-encoding

TEST_ALL:=$(wildcard ../conf/*.i)
TEST_EXCLUDE=../conf/spec.02.i ../conf/spec.05.i
TEST_INS:=$(filter-out $(TEST_EXCLUDE),$(TEST_ALL))
TEST_OUTS:=$(TEST_INS:.i=.o)
TEST_DOTS:=$(TEST_INS:.i=.dot)
TEST_JPGS:=$(TEST_INS:.i=.jpg)

kmnsim:			\
	all.o		\
	strdup.o	\
	strsep.o	\
	strlcat.o	\
	strlcpy.o
	$(CC) -g -ggdb -o kmnsim	\
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
	$(CC) $(CFLAGS) -o all.o all.c
strdup.o: subr/strdup.c
	$(CC) $(CFLAGS) -o strdup.o subr/strdup.c
strsep.o: subr/strsep.c
	$(CC) $(CFLAGS) -o strsep.o subr/strsep.c
strlcpy.o: subr/strlcpy.c
	$(CC) $(CFLAGS) -o strlcpy.o subr/strlcpy.c
strlcat.o: subr/strlcat.c
	$(CC) $(CFLAGS) -o strlcat.o subr/strlcat.c

analyze:
	 scan-build -o /tmp/_.kmnsim make -j4

testdebug:
	@echo all $(TEST_ALL)
	@echo excluded $(TEST_EXCLUDE)
	@echo ins $(TEST_INS)
	@echo outs $(TEST_OUTS)

test: kmnsim $(TEST_OUTS)
dot: kmnsim $(TEST_DOTS)
jpg: kmnsim $(TEST_JPGS)

%.o: %.i
	./kmnsim -dd -v -S $@ $<

%.dot: %.i
	./kmnsim -dd -v -D $@ $<

%.jpg: %.dot
	dot -Tjpg -o $@ $<

clean:
	rm -rf kmnsim *.o ../conf/*.out ../conf/*.dot \
		../conf/*.txt ../conf/*.o ../conf/*.jpg
