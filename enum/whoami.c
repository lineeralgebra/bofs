#include <windows.h>
#include <stdio.h>
#include "beacon.h"

// Define function prototypes for dynamic resolution
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupAccountSidA(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
DECLSPEC_IMPORT void* __cdecl MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void __cdecl MSVCRT$free(void*);

void go(char * args, int len) {
    HANDLE hToken;
    DWORD dwLength = 0;
    PTOKEN_USER pTokenUser = NULL;
    char * lpName = NULL;
    char * lpDomain = NULL;
    DWORD dwNameSize = 0;
    DWORD dwDomainSize = 0;
    SID_NAME_USE SidType;

    // 1. Open the process token
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcessToken failed: %d", KERNEL32$GetLastError());
        return;
    }

    // 2. Get the required buffer size for the token information
    if (!ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLength)) {
        if (KERNEL32$GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
             BeaconPrintf(CALLBACK_ERROR, "GetTokenInformation (length) failed: %d", KERNEL32$GetLastError());
             KERNEL32$CloseHandle(hToken);
             return;
        }
    }

    // 3. Allocate memory for the token information
    pTokenUser = (PTOKEN_USER)MSVCRT$malloc(dwLength);
    if (!pTokenUser) {
        BeaconPrintf(CALLBACK_ERROR, "malloc failed");
        KERNEL32$CloseHandle(hToken);
        return;
    }

    // 4. Get the token information
    if (!ADVAPI32$GetTokenInformation(hToken, TokenUser, pTokenUser, dwLength, &dwLength)) {
        BeaconPrintf(CALLBACK_ERROR, "GetTokenInformation failed: %d", KERNEL32$GetLastError());
        MSVCRT$free(pTokenUser);
        KERNEL32$CloseHandle(hToken);
        return;
    }

    // 5. Get the required buffer sizes for name and domain
    ADVAPI32$LookupAccountSidA(NULL, pTokenUser->User.Sid, NULL, &dwNameSize, NULL, &dwDomainSize, &SidType);
   
    // 6. Allocate memory for name and domain
    lpName = (char *)MSVCRT$malloc(dwNameSize);
    lpDomain = (char *)MSVCRT$malloc(dwDomainSize);

    if (!lpName || !lpDomain) {
         BeaconPrintf(CALLBACK_ERROR, "malloc for name/domain failed");
         if(lpName) MSVCRT$free(lpName);
         if(lpDomain) MSVCRT$free(lpDomain);
         MSVCRT$free(pTokenUser);
         KERNEL32$CloseHandle(hToken);
         return;
    }

    // 7. Lookup the account name
    if (!ADVAPI32$LookupAccountSidA(NULL, pTokenUser->User.Sid, lpName, &dwNameSize, lpDomain, &dwDomainSize, &SidType)) {
        BeaconPrintf(CALLBACK_ERROR, "LookupAccountSidA failed: %d", KERNEL32$GetLastError());
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "%s\\%s", lpDomain, lpName);
    }

    // 8. Cleanup
    MSVCRT$free(lpName);
    MSVCRT$free(lpDomain);
    MSVCRT$free(pTokenUser);
    KERNEL32$CloseHandle(hToken);
}
