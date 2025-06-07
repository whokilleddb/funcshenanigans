#include "common.h"

// Boundary function to mark the starting bound of the function to fluctuate
__attribute__((aligned(FUNC_SIZE))) 
void __start_boundary() {}

__attribute__((aligned(FUNC_SIZE)))
VOID fluctuate() {
	for (int i = 0; i < 5; i++) {
		SYSTEMTIME st = { 0 };
		GetLocalTime(&st);

		printf("\tCurrent Time: %02d:%02d:%02d\n", st.wHour, st.wMinute, st.wSecond);
		Sleep(1000);
	}
  printf("\n");
}

// Boundary function to mark the end bound of the function to fluctuate
__attribute__((aligned(FUNC_SIZE))) 
void __end_boundary() {}
