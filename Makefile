CC=x86_64-w64-mingw32-gcc
CCFLAGS=-Wall -Wextra -O0 -lntdll
INCLUDES=includes
SRC=src

all: build

build:
	$(CC) $(CCFLAGS) -I $(INCLUDES) $(SRC)/replace.c $(SRC)/bound.c $(SRC)/common.c  -o replace.exe
	$(CC) $(CCFLAGS) -I $(INCLUDES) $(SRC)/fluctuator.c $(SRC)/bound.c $(SRC)/common.c -o fluctuator.exe 

clean:
	@rm -rf *.exe

