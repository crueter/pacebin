prefix=/usr/local
confdir=/etc
systemd_dir=${DESTDIR}${confdir}/systemd/system
nginx_dir=${DESTDIR}${confdir}/nginx
bindir=${DESTDIR}${prefix}/bin

DISABLE_CUSTOM_LINKS ?= 0
MAX_SIZE	?= 52428800
CC			?= gcc
CFLAGS		:= -O2 -DDISABLE_CUSTOM_LINKS=${DISABLE_CUSTOM_LINKS} -DMG_MAX_RECV_BUF_SIZE=${MAX_SIZE} ${CFLAGS}

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
