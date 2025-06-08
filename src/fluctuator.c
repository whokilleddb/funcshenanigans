#include "common.h"
#define FLUCT_DURATION 1*1000 // Fluctuate for 1s

// Globals
HANDLE g_htimer_queue = NULL;
HANDLE g_htimer = NULL;

void protect(BOOL encrypt) {
    DWORD oldp = 0;
    if (!VirtualProtect((LPVOID)fluctuate, FUNC_SIZE, PAGE_READWRITE, &oldp)) {
        eprint("VirtualProtect");
        ExitProcess(0);
    }

    byte_xor((unsigned char *)fluctuate, FUNC_SIZE, XORKEY);

    if (!VirtualProtect((LPVOID)fluctuate, FUNC_SIZE, encrypt==TRUE? PAGE_NOACCESS:PAGE_EXECUTE_READ, &oldp)) {
        eprint("VirtualProtect");
        ExitProcess(0);
    }
}

VOID CALLBACK encryptor_wrapper(IN PVOID lpParameter, IN BOOLEAN TimerOrWaitFired) {
    UNUSED(lpParameter);
    UNUSED(TimerOrWaitFired);
    protect(TRUE);
}

LONG WINAPI fluctuator_veh(PEXCEPTION_POINTERS pExceptionInfo) {
    // Check if Exception if within our boundarty 
    PVOID p_exec_addr = pExceptionInfo->ExceptionRecord->ExceptionAddress;

    if ((p_exec_addr > (PVOID)__boundary_func) || (p_exec_addr < (PVOID)fluctuate)) {
        printf("[-] Unhandled Exception occured at: 0x%p as 0x%lx\n", p_exec_addr, pExceptionInfo->ExceptionRecord->ExceptionCode);      
        ExitProcess(0);  
        return EXCEPTION_CONTINUE_SEARCH;  
	}


	if (pExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) {
		printf("[-] Invalid Exception code found: 0x%lx\n", pExceptionInfo->ExceptionRecord->ExceptionCode);
		return EXCEPTION_CONTINUE_SEARCH;  
	}

    // printf("[-] Exception Code: 0x%lx\n", pExceptionInfo->ExceptionRecord->ExceptionCode);

    if ((g_htimer == NULL)  || (g_htimer_queue == NULL)) {
        printf("[-] Globals aren't initialized\n");
        ExitProcess(0);
    }

    Sleep(2000);
    // Decrypt the function
    protect(FALSE);

    if (!CreateTimerQueueTimer(&g_htimer, g_htimer_queue, (WAITORTIMERCALLBACK)encryptor_wrapper, NULL, FLUCT_DURATION, 0x00, 0x00)) {
        eprint("CreateTimerQueue");
        ExitProcess(0);
    }

    return EXCEPTION_CONTINUE_EXECUTION;
}

int main() {
	printf("[+] Function Addr: \t\t0x%p\n", fluctuate);
	printf("[+] End Bound:     \t\t0x%p\n\n", __boundary_func);

    get_mem_base_address((LPVOID)fluctuate);

    // Register VEH 
	PVOID p_veh_h = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)fluctuator_veh);
	if (p_veh_h == NULL) {
		printf("[-] AddVectoredExceptionHandler() failed\n");
		return -1;
	}
	printf("\n[+] Registered VEH\n");

    do {        
        printf("[+] Calling function without fluctuation:\n\n");
       
        fluctuate();

        // Create Timer queue
        if (!g_htimer_queue) {
            g_htimer_queue = CreateTimerQueue();
            if (g_htimer_queue == NULL) {
                eprint("CreateTimerQueue");
                break;
            }
        }

        if (!CreateTimerQueueTimer(&g_htimer, g_htimer_queue, (WAITORTIMERCALLBACK)encryptor_wrapper, NULL, 0, 0x00, 0x00)) {
            eprint("CreateTimerQueue");
            break;
        }

        printf("[+] Created Timer to encrypt function\n");
        
        // Make sure function is encrypted
        Sleep(FLUCT_DURATION);

        printf("[+] Calling fluctuating function:\n\n");
       
        fluctuate();
        printf("[============================== END ==============================]\n");

    } while(FALSE);

    if (p_veh_h) RemoveVectoredExceptionHandler(p_veh_h); 

    return 0;
}