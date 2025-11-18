#include <windows.h>
#include "beacon.h"

// Advapi32 imports
DECLSPEC_IMPORT BOOL ADVAPI32$OpenProcessToken(
    HANDLE  ProcessHandle,
    DWORD   DesiredAccess,
    PHANDLE TokenHandle
);

DECLSPEC_IMPORT BOOL ADVAPI32$GetTokenInformation(
    HANDLE                  TokenHandle,
    TOKEN_INFORMATION_CLASS TokenInformationClass,
    LPVOID                  TokenInformation,
    DWORD                   TokenInformationLength,
    PDWORD                  ReturnLength
);

DECLSPEC_IMPORT BOOL ADVAPI32$ConvertSidToStringSidA(
    PSID   Sid,
    LPSTR  *StringSid
);

// Kernel32 imports
DECLSPEC_IMPORT HANDLE KERNEL32$GetCurrentProcess();
DECLSPEC_IMPORT DWORD KERNEL32$GetLastError();
DECLSPEC_IMPORT HANDLE KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT LPVOID KERNEL32$HeapAlloc(
    HANDLE hHeap,
    DWORD  dwFlags,
    SIZE_T dwBytes
);
DECLSPEC_IMPORT BOOL KERNEL32$HeapFree(
    HANDLE hHeap,
    DWORD  dwFlags,
    LPVOID lpMem
);
DECLSPEC_IMPORT BOOL KERNEL32$CloseHandle(
    HANDLE hObject
);
DECLSPEC_IMPORT HLOCAL KERNEL32$LocalFree(
    HLOCAL hMem
);

void go(char* args, int argc) {
    HANDLE hToken = NULL;
    PTOKEN_USER pTokenUser = NULL;
    DWORD dwLength = 0;
    LPSTR pStringSid = NULL;
    HANDLE hHeap = KERNEL32$GetProcessHeap();

    // Open process token
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcessToken Failed with Error: %ld", KERNEL32$GetLastError());
        return;
    }

    // Get required buffer size
    ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLength);
    if (dwLength == 0) {
        BeaconPrintf(CALLBACK_ERROR, "GetTokenInformation (size) Failed with Error: %ld", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hToken);
        return;
    }

    // Allocate memory for token information
    pTokenUser = (PTOKEN_USER)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwLength);
    if (pTokenUser == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "HeapAlloc Failed");
        KERNEL32$CloseHandle(hToken);
        return;
    }

    // Get token information
    if (!ADVAPI32$GetTokenInformation(hToken, TokenUser, pTokenUser, dwLength, &dwLength)) {
        BeaconPrintf(CALLBACK_ERROR, "GetTokenInformation Failed with Error: %ld", KERNEL32$GetLastError());
        KERNEL32$HeapFree(hHeap, 0, pTokenUser);
        KERNEL32$CloseHandle(hToken);
        return;
    }

    // Convert SID to string
    if (!ADVAPI32$ConvertSidToStringSidA(pTokenUser->User.Sid, &pStringSid)) {
        BeaconPrintf(CALLBACK_ERROR, "ConvertSidToStringSidA Failed with Error: %ld", KERNEL32$GetLastError());
        KERNEL32$HeapFree(hHeap, 0, pTokenUser);
        KERNEL32$CloseHandle(hToken);
        return;
    }

    // Output the SID
    BeaconPrintf(CALLBACK_OUTPUT, "User SID: %s", pStringSid);

    // Cleanup
    if (pStringSid) {
        KERNEL32$LocalFree(pStringSid);
    }
    KERNEL32$HeapFree(hHeap, 0, pTokenUser);
    KERNEL32$CloseHandle(hToken);
}
