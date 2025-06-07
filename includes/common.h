#pragma once
#include <stdio.h>
#include <stdint.h>
#include <windows.h>

#include "bound.h"

#define FUNC_SIZE 4096
#define XORKEY 0xdb

#ifndef STATUS_SUCCESS
	#define STATUS_SUCCESS 0x0
#endif

#ifndef NT_SUCCESS
	#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef RVA2VA
	#define RVA2VA(type, base, rva) (type)((ULONG_PTR) base + rva)
#endif

#ifndef C_PTR
	#define C_PTR( x ) ( PVOID )    x
#endif

#ifndef U_PTR
	#define U_PTR( x ) ( UINT_PTR ) x
#endif

#define eprint(x)           printf("[-] %s() failed at %s:%d with error: 0x%lx\n", x, __FILE__,__LINE__, GetLastError())
#define nteprint(x, status) printf("[-] %s() failed at %s:%d with error: 0x%lx\n", x, __FILE__, __LINE__, status)
#define emalloc()           printf("[-] malloc() failed at %s::%d\n", __FILE__, __LINE__)
