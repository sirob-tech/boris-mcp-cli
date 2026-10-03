//go:build darwin && cgo

package main

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

static CFStringRef bmcp_str(const char *s) {
	return CFStringCreateWithCString(kCFAllocatorDefault, s, kCFStringEncodingUTF8);
}

static CFMutableDictionaryRef bmcp_query(const char *service, const char *account) {
	CFMutableDictionaryRef q = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
	CFStringRef s = bmcp_str(service);
	CFDictionarySetValue(q, kSecAttrService, s);
	CFRelease(s);
	if (account != NULL) {
		CFStringRef a = bmcp_str(account);
		CFDictionarySetValue(q, kSecAttrAccount, a);
		CFRelease(a);
	}
	return q;
}

// Toggling interaction is process-wide; the Go side serialises every call.
static Boolean bmcp_begin(int noUI) {
	Boolean prev = true;
	SecKeychainGetUserInteractionAllowed(&prev);
	if (noUI) SecKeychainSetUserInteractionAllowed(false);
	return prev;
}

static void bmcp_end(Boolean prev) { SecKeychainSetUserInteractionAllowed(prev); }

static OSStatus bmcp_kc_get(const char *service, const char *account, int noUI, void **out, size_t *outLen) {
	CFMutableDictionaryRef q = bmcp_query(service, account);
	CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
	CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
	if (noUI) CFDictionarySetValue(q, kSecUseAuthenticationUI, kSecUseAuthenticationUIFail);
	Boolean prev = bmcp_begin(noUI);
	CFTypeRef result = NULL;
	OSStatus st = SecItemCopyMatching(q, &result);
	bmcp_end(prev);
	CFRelease(q);
	*out = NULL;
	*outLen = 0;
	if (st != errSecSuccess) return st;
	if (result == NULL || CFGetTypeID(result) != CFDataGetTypeID()) {
		if (result) CFRelease(result);
		return errSecDecode;
	}
	CFIndex n = CFDataGetLength((CFDataRef)result);
	*out = malloc(n > 0 ? n : 1);
	memcpy(*out, CFDataGetBytePtr((CFDataRef)result), n);
	*outLen = n;
	CFRelease(result);
	return errSecSuccess;
}

// The login keychain, for adds (decision 2): the default keychain is whatever
// the user last made default. NULL when it cannot be opened, so the add falls
// back to the default rather than failing.
static SecKeychainRef bmcp_login_keychain(void) {
	SecKeychainRef kc = NULL;
	SecKeychainStatus status;
	if (SecKeychainOpen("login.keychain", &kc) != errSecSuccess) return NULL;
	if (SecKeychainGetStatus(kc, &status) != errSecSuccess) {
		CFRelease(kc);
		return NULL;
	}
	return kc;
}

// Update first, add only when absent: an update keeps the item's existing ACL,
// which is what lets a re-signed bmcp keep reading without a prompt.
static OSStatus bmcp_kc_set(const char *service, const char *account, const char *label, const void *data, size_t len, int noUI) {
	CFDataRef d = CFDataCreate(kCFAllocatorDefault, data, len);
	CFMutableDictionaryRef q = bmcp_query(service, account);
	CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(attrs, kSecValueData, d);
	Boolean prev = bmcp_begin(noUI);
	OSStatus st = SecItemUpdate(q, attrs);
	if (st == errSecItemNotFound) {
		CFDictionarySetValue(q, kSecValueData, d);
		CFStringRef l = bmcp_str(label);
		CFDictionarySetValue(q, kSecAttrLabel, l);
		CFRelease(l);
		SecKeychainRef login = bmcp_login_keychain();
		if (login != NULL) CFDictionarySetValue(q, kSecUseKeychain, login);
		st = SecItemAdd(q, NULL);
		if (login != NULL) CFRelease(login);
	}
	bmcp_end(prev);
	CFRelease(attrs);
	CFRelease(q);
	CFRelease(d);
	return st;
}

static OSStatus bmcp_kc_del(const char *service, const char *account, int noUI) {
	CFMutableDictionaryRef q = bmcp_query(service, account);
	Boolean prev = bmcp_begin(noUI);
	OSStatus st = SecItemDelete(q);
	bmcp_end(prev);
	CFRelease(q);
	return st;
}

// Attributes only: listing account names needs no access to the secret, so it
// never prompts. Accounts come back newline-separated.
static OSStatus bmcp_kc_list(const char *service, int noUI, char **out) {
	CFMutableDictionaryRef q = bmcp_query(service, NULL);
	CFDictionarySetValue(q, kSecReturnAttributes, kCFBooleanTrue);
	CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitAll);
	Boolean prev = bmcp_begin(noUI);
	CFTypeRef result = NULL;
	OSStatus st = SecItemCopyMatching(q, &result);
	bmcp_end(prev);
	CFRelease(q);
	*out = NULL;
	if (st != errSecSuccess) return st;
	if (result == NULL || CFGetTypeID(result) != CFArrayGetTypeID()) {
		if (result) CFRelease(result);
		return errSecDecode;
	}
	CFIndex n = CFArrayGetCount((CFArrayRef)result);
	size_t cap = 1, used = 0;
	char *buf = malloc(cap);
	buf[0] = 0;
	for (CFIndex i = 0; i < n; i++) {
		CFDictionaryRef item = CFArrayGetValueAtIndex((CFArrayRef)result, i);
		CFStringRef acct = CFDictionaryGetValue(item, kSecAttrAccount);
		if (acct == NULL || CFGetTypeID(acct) != CFStringGetTypeID()) continue;
		CFIndex max = CFStringGetMaximumSizeForEncoding(CFStringGetLength(acct), kCFStringEncodingUTF8) + 1;
		char *tmp = malloc(max);
		if (CFStringGetCString(acct, tmp, max, kCFStringEncodingUTF8)) {
			size_t l = strlen(tmp);
			buf = realloc(buf, cap + l + 1);
			cap += l + 1;
			memcpy(buf + used, tmp, l);
			used += l;
			buf[used++] = '\n';
			buf[used] = 0;
		}
		free(tmp);
	}
	CFRelease(result);
	*out = buf;
	return errSecSuccess;
}
*/
import "C"

import (
	"fmt"
	"strings"
	"sync"
	"unsafe"
)

// keychainMu serialises Security framework calls, because bmcp_begin toggles
// whether the whole process may show keychain UI.
var keychainMu sync.Mutex

type keychainBackend struct {
	service string
	noUI    bool
}

// newKeychainStore keeps items in the login keychain as generic passwords. No ACL is set explicitly: the default trusts the creating app by
// its designated requirement, which for a Developer ID build survives updates.
func newKeychainStore(service string, opts storeOptions) (credStore, error) {
	return keyedStore{b: &keychainBackend{service: service, noUI: !opts.AllowUI}}, nil
}

func (k *keychainBackend) name() backendName { return backendKeychain }

func (k *keychainBackend) flag() C.int {
	if k.noUI {
		return 1
	}
	return 0
}

func (k *keychainBackend) get(item string) ([]byte, error) {
	svc, acct := C.CString(k.service), C.CString(item)
	defer C.free(unsafe.Pointer(svc))
	defer C.free(unsafe.Pointer(acct))
	var out unsafe.Pointer
	var n C.size_t
	keychainMu.Lock()
	st := C.bmcp_kc_get(svc, acct, k.flag(), &out, &n)
	keychainMu.Unlock()
	if st != C.errSecSuccess {
		return nil, keychainError(st, "read")
	}
	defer C.free(out)
	return C.GoBytes(out, C.int(n)), nil
}

func (k *keychainBackend) set(item, label string, data []byte) error {
	svc, acct, lbl := C.CString(k.service), C.CString(item), C.CString(label)
	defer C.free(unsafe.Pointer(svc))
	defer C.free(unsafe.Pointer(acct))
	defer C.free(unsafe.Pointer(lbl))
	var p unsafe.Pointer
	if len(data) > 0 {
		p = C.CBytes(data)
		defer C.free(p)
	}
	keychainMu.Lock()
	st := C.bmcp_kc_set(svc, acct, lbl, p, C.size_t(len(data)), k.flag())
	keychainMu.Unlock()
	if st != C.errSecSuccess {
		return keychainError(st, "write")
	}
	return nil
}

func (k *keychainBackend) del(item string) error {
	svc, acct := C.CString(k.service), C.CString(item)
	defer C.free(unsafe.Pointer(svc))
	defer C.free(unsafe.Pointer(acct))
	keychainMu.Lock()
	st := C.bmcp_kc_del(svc, acct, k.flag())
	keychainMu.Unlock()
	if st != C.errSecSuccess && st != C.errSecItemNotFound {
		return keychainError(st, "delete")
	}
	return nil
}

func (k *keychainBackend) list() ([]string, error) {
	svc := C.CString(k.service)
	defer C.free(unsafe.Pointer(svc))
	var out *C.char
	keychainMu.Lock()
	st := C.bmcp_kc_list(svc, k.flag(), &out)
	keychainMu.Unlock()
	if st == C.errSecItemNotFound {
		return nil, nil
	}
	if st != C.errSecSuccess {
		return nil, keychainError(st, "list")
	}
	defer C.free(unsafe.Pointer(out))
	return strings.Fields(C.GoString(out)), nil
}

// keychainError keeps "needs approval" apart from every other failure. Only
// the status code is reported: Security's messages can name the item, never
// the secret, but the code is all a remedy needs.
func keychainError(st C.OSStatus, op string) error {
	switch st {
	case C.errSecItemNotFound:
		return errStoreItemNotFound
	case C.errSecInteractionNotAllowed, C.errSecAuthFailed, C.errSecUserCanceled, C.errSecInteractionRequired:
		return &storeLockedError{Backend: backendKeychain, Reason: fmt.Sprintf("keychain %s refused (OSStatus %d)", op, int(st)),
			Hint: "approve bmcp's access to the login keychain"}
	}
	return fmt.Errorf("keychain %s failed (OSStatus %d)", op, int(st))
}
