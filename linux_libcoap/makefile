##LIBRARIES = -lcoap-1
##INCLUDE = -I /usr/local/include/coap/
##CXXFLAGS = -O2 -D_GNU_SOURCE -DWITH_POSIX

LIBCOAP?=libcoap-2-mbedtls
pkgconfig=$(shell pkg-config $(1) $(2))
CPPFLAGS=-Wall -Wextra $(call pkgconfig,--cflags,$(LIBCOAP))
LDLIBS=$(call pkgconfig,--libs,$(LIBCOAP))
LINK.o=$(LINK.cc)

CXXFLAGS=-std=c++14

all: test_client

client:: test_client.o

clean:
	rm -f *.o test_client

