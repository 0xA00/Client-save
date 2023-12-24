CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -lcurl -ljansson -lssl -lcrypto

saverClient: client.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f saverClient
