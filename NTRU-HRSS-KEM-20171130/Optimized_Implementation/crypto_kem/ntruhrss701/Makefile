CC=/usr/bin/gcc
LDFLAGS=-lcrypto
CFLAGS=-std=gnu99

SOURCES = cbd.c fips202.c ntrukem.c owcpa.c poly.c verify.c rng.c
HEADERS = api.h cbd.h owcpa.h params.h poly.h rng.h verify.h rng.h

all: pqc_cli PQCgenKAT_kem

PQCgenKAT_kem: $(HEADERS) $(SOURCES) PQCgenKAT_kem.c
	$(CC) -o $@ $(CFLAGS) $(SOURCES) PQCgenKAT_kem.c $(LDFLAGS)

pqc_cli: $(HEADERS) $(SOURCES) pqc_cli_api.c
	$(CC) -o $@ $(CFLAGS) -DBUILD_KEM $(SOURCES) pqc_cli_api.c $(LDFLAGS)

.PHONY: clean

clean:
	-rm -f PQCgenKAT_kem pqc_cli

