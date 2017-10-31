CFLAGS=-O3 -Wall -fPIC -std=c++0x -Iexternal/

all: cqlsniff

debug: CFLAGS=-g -Wall -fPIC -std=c++0x
debug: all


cqlsniff: src/utils.o src/cqlframe.o src/stream.o src/main.o external/cityhash/city.o
	g++ $(CFLAGS) -o $@ -Wl,--no-as-needed -lpcap src/*.o external/cityhash/*.o

external/cityhash/city.o: external/cityhash/city.cc
	c++ -c external/cityhash/city.cc -Iexternal/cityhash -O3 -o external/cityhash/city.o

src/utils.o: src/utils.cc
	g++ $(CFLAGS) -c $? -o $@

src/cqlframe.o: src/cqlframe.cc
	g++ $(CFLAGS) -c $? -o $@

src/stream.o: src/stream.cc
	g++ $(CFLAGS) -c $? -o $@

src/main.o: src/main.cc
	g++ $(CFLAGS) -c $? -o $@

clean:
	rm -f src/*.o cqlsniff

