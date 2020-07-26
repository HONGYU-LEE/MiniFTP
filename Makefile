CC = gcc
CFLAGS = -g
OBJS = sysutil.o session.o ftpproto.o privparent.o MiniFTP.o
LIBS = 
BIN  = MiniFTP

$(BIN):$(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)
%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY:clean
clean:
	rm -fr *.o $(BIN)