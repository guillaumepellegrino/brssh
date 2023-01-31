CFLAGS+=-Wall -Wextra

all: brssh

brssh: brssh.o process.o

install:
	install -m 4755 brssh /usr/bin/
	install -d /etc/brssh
	install -m 0644 client.cfg  /etc/brssh
	install -m 0644 server.cfg  /etc/brssh
	install -m 0644 -T bash_completion /usr/share/bash-completion/completions/brssh

clean:
	rm -f brssh *.o *.d
