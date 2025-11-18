#include <windows.h>
#include <winldap.h>
#include <winber.h>
#include "beacon.h"

// LDAP function imports
DECLSPEC_IMPORT LDAP* WLDAP32$ldap_initA(PCHAR HostName, ULONG PortNumber);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_set_optionA(LDAP* ld, int option, void* invalue);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_bind_sA(LDAP* ld, PCHAR dn, PCHAR cred, ULONG method);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_search_ext_sA(LDAP* ld, PCHAR base, ULONG scope, PCHAR filter, PCHAR attrs[], ULONG attrsonly, PLDAPControlA* ServerControls, PLDAPControlA* ClientControls, struct l_timeval* timeout, ULONG SizeLimit, LDAPMessage** res);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_search_sA(LDAP* ld, PCHAR base, ULONG scope, PCHAR filter, PCHAR attrs[], ULONG attrsonly, LDAPMessage** res);
DECLSPEC_IMPORT LDAPMessage* WLDAP32$ldap_first_entry(LDAP* ld, LDAPMessage* res);
DECLSPEC_IMPORT LDAPMessage* WLDAP32$ldap_next_entry(LDAP* ld, LDAPMessage* entry);
DECLSPEC_IMPORT PCHAR WLDAP32$ldap_first_attributeA(LDAP* ld, LDAPMessage* entry, BerElement** ptr);
DECLSPEC_IMPORT PCHAR WLDAP32$ldap_next_attributeA(LDAP* ld, LDAPMessage* entry, BerElement* ptr);
DECLSPEC_IMPORT PCHAR* WLDAP32$ldap_get_valuesA(LDAP* ld, LDAPMessage* entry, PCHAR attr);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_value_freeA(PCHAR* vals);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_memfreeA(PCHAR Block);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_msgfree(LDAPMessage* res);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_unbind(LDAP* ld);

// Kernel32 imports
DECLSPEC_IMPORT DWORD KERNEL32$GetLastError();

void go(char* args, int argc) {
    LDAP* ld = NULL;
    LDAPMessage* searchRes = NULL;
    LDAPMessage* entry = NULL;
    PCHAR attrs[] = { "cn", "distinguishedName", "whenChanged", "isDeleted", NULL };
    ULONG result;
    int version = LDAP_VERSION3;
    int count = 0;

    // Initialize LDAP connection (NULL = connect to domain the machine is joined to)
    ld = WLDAP32$ldap_initA(NULL, LDAP_PORT);
    if (ld == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "ldap_init failed with error: %ld", KERNEL32$GetLastError());
        return;
    }

    // Set LDAP version 3
    result = WLDAP32$ldap_set_optionA(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "ldap_set_option failed with error: %ld", result);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    // Bind with current credentials
    result = WLDAP32$ldap_bind_sA(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "ldap_bind_s failed with error: %ld", result);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Successfully connected to Active Directory");

    // Get the default naming context (root DN)
    LDAPMessage* rootRes = NULL;
    PCHAR rootAttrs[] = { "defaultNamingContext", NULL };
    PCHAR baseDN = NULL;

    result = WLDAP32$ldap_search_sA(ld, "", LDAP_SCOPE_BASE, "(objectClass=*)", rootAttrs, 0, &rootRes);
    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get root DSE with error: %ld", result);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    LDAPMessage* rootEntry = WLDAP32$ldap_first_entry(ld, rootRes);
    if (rootEntry != NULL) {
        PCHAR* values = WLDAP32$ldap_get_valuesA(ld, rootEntry, "defaultNamingContext");
        if (values != NULL) {
            baseDN = values[0];
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Domain: %s", baseDN);
        }
    }

    if (baseDN == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get default naming context");
        WLDAP32$ldap_msgfree(rootRes);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Searching for deleted users...\n");

    // Enable showing deleted objects control
    LDAPControlA showDeletedControl;
    PLDAPControlA serverControls[2];
    showDeletedControl.ldctl_oid = "1.2.840.113556.1.4.417";  // LDAP_SERVER_SHOW_DELETED_OID
    showDeletedControl.ldctl_value.bv_len = 0;
    showDeletedControl.ldctl_value.bv_val = NULL;
    showDeletedControl.ldctl_iscritical = TRUE;
    serverControls[0] = &showDeletedControl;
    serverControls[1] = NULL;

    // Search for deleted users with the show deleted control
    result = WLDAP32$ldap_search_ext_sA(
        ld,
        baseDN,
        LDAP_SCOPE_SUBTREE,
        "(&(objectClass=user)(isDeleted=TRUE))",
        attrs,
        0,
        serverControls,  // Pass the control here
        NULL,            // No client controls
        NULL,            // No timeout
        0,               // No size limit
        &searchRes
    );

    // Free root search results
    WLDAP32$ldap_msgfree(rootRes);

    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "ldap_search_s failed with error: %ld", result);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    // Iterate through results
    for (entry = WLDAP32$ldap_first_entry(ld, searchRes);
         entry != NULL;
         entry = WLDAP32$ldap_next_entry(ld, entry)) {

        PCHAR* values = NULL;
        count++;

        BeaconPrintf(CALLBACK_OUTPUT, "=== Deleted User #%d ===", count);

        // Get CN (Common Name)
        values = WLDAP32$ldap_get_valuesA(ld, entry, "cn");
        if (values != NULL) {
            BeaconPrintf(CALLBACK_OUTPUT, "  CN: %s", values[0]);
            WLDAP32$ldap_value_freeA(values);
        }

        // Get Distinguished Name
        values = WLDAP32$ldap_get_valuesA(ld, entry, "distinguishedName");
        if (values != NULL) {
            BeaconPrintf(CALLBACK_OUTPUT, "  DN: %s", values[0]);
            WLDAP32$ldap_value_freeA(values);
        }

        // Get whenChanged (deletion time)
        values = WLDAP32$ldap_get_valuesA(ld, entry, "whenChanged");
        if (values != NULL) {
            BeaconPrintf(CALLBACK_OUTPUT, "  Deleted: %s", values[0]);
            WLDAP32$ldap_value_freeA(values);
        }

        BeaconPrintf(CALLBACK_OUTPUT, "");
    }

    if (count == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] No deleted users found");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Total deleted users found: %d", count);
    }

    // Cleanup
    if (searchRes) {
        WLDAP32$ldap_msgfree(searchRes);
    }
    WLDAP32$ldap_unbind(ld);
}
