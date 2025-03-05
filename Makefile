prefix=/usr/local
confdir=/etc
systemd_dir=${DESTDIR}${confdir}/systemd/system
nginx_dir=${DESTDIR}${confdir}/nginx
bindir=${DESTDIR}${prefix}/bin

MAX_SIZE	?= 52428800
CC			?= gcc
CFLAGS		:= -O2 -DMG_MAX_RECV_BUF_SIZE=${MAX_SIZE} ${CFLAGS}

BIN			:= pacebin
PACECTL 	:= pacectl

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
	@sed -i 's|BINDIR|${bindir}|' ${DESTDIR}/${confdir}/pacebin.conf
	@sed -i 's|BINNAME|${BIN}|' ${DESTDIR}/${confdir}/pacebin.conf

install-bin:
	@install -Dm755 ${BIN} ${bindir}/${BIN}
	@install -Dm755 ${PACECTL} ${bindir}/${PACECTL}

install: install-bin install-nginx install-systemd
