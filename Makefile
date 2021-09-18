prefix=/usr/local
confdir=/etc
systemd_dir=${DESTDIR}${confdir}/systemd/system
nginx_dir=${DESTDIR}${confdir}/nginx
bindir=${DESTDIR}${prefix}/bin

CC			:= gcc
CFLAGS		:= -O2

BIN			:= pacebin

SOURCE	:= main.c mongoose.c
OBJ		:= mongoose.o main.o
DEPS	:= mongoose.h index.h
LIBS	:= -lcrypt

all: $(BIN)

clean:
	rm -f $(OBJ)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

install-nginx:
	@install -Dm644 doc/pacebin.nginx ${nginx_dir}/sites-available/pacebin

install-systemd:
	@install -Dm644 doc/pacebin.service ${systemd_dir}/pacebin.service
	@install -Dm644 doc/pacebin.conf ${DESTDIR}/${confdir}/pacebin.conf

install-bin:
	@install -Dm755 ${BIN} ${bindir}/${BIN}

install: install-bin install-nginx install-systemd
