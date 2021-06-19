// +build ios

package global

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

int verifyTrust(char *hostname, void *cert, long certLen) {
	CFStringRef hostnameStr = CFStringCreateWithCStringNoCopy(NULL, hostname, kCFStringEncodingUTF8, NULL);
    SecPolicyRef policy = SecPolicyCreateSSL(true, hostnameStr);
	CFDataRef certData = CFDataCreateWithBytesNoCopy(NULL, cert, certLen, NULL);
	SecCertificateRef certificate = SecCertificateCreateWithData(NULL, certData);
	int result = 0;
	SecTrustRef trust;
	if (SecTrustCreateWithCertificates(certificate, policy, &trust) == errSecSuccess) {
		SecTrustResultType secResult;
		if (SecTrustEvaluate(trust, &secResult) == errSecSuccess) {
			if (secResult == kSecTrustResultUnspecified || secResult == kSecTrustResultProceed) {
				result = 1;
			}
		}
	}
	if (trust) {
		CFRelease(trust);
	}
	if (certificate)  {
		CFRelease(certificate);
	}
	if (policy)  {
		CFRelease(policy);
	}
	return result;
}
*/
import "C"

import (
	"unsafe"
)

func init() {
	TLSCertVerifier = func(serverName string, certs [][]byte) bool {
		if len(certs) == 0 {
			return false
		}

		serverNameStr := C.CString(serverName)
		defer C.free(unsafe.Pointer(serverNameStr))
		certBytes := C.CBytes(certs[0])
		defer C.free(certBytes)
		return C.verifyTrust(serverNameStr, certBytes, C.long(len(certs[0]))) > 0
	}
}
