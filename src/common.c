#include "common.h"

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
