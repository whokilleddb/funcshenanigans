CC=x86_64-w64-mingw32-gcc
CCFLAGS=-Wall -Wextra -O0 -lntdll
INCLUDES=includes
SRC=src

all: build

build:
	$(CC) $(CCFLAGS) -I $(INCLUDES) $(SRC)/replace.c $(SRC)/bound.c  -o replace.exe 

clean:
	@rm -rf *.exe

