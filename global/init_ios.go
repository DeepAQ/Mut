//go:build ios

package global

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation

#include <stdlib.h>
#include <os/log.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

void printLog(_GoString_ str) {
	os_log_with_type(OS_LOG_DEFAULT, OS_LOG_TYPE_INFO, "%{public}.*s", (int) str.n, str.p);
}

void printErrorLog(_GoString_ str) {
	os_log_with_type(OS_LOG_DEFAULT, OS_LOG_TYPE_ERROR, "%{public}.*s", (int) str.n, str.p);
}

int verifyTrust(_GoString_ hostname, _GoString_ cert) {
	CFStringRef hostnameStr = CFStringCreateWithBytesNoCopy(kCFAllocatorDefault, hostname.p, hostname.n, kCFStringEncodingUTF8, false, kCFAllocatorNull);
	SecPolicyRef policy = SecPolicyCreateSSL(true, hostnameStr);
	CFDataRef certData = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, cert.p, cert.n, kCFAllocatorNull);
	SecCertificateRef certificate = SecCertificateCreateWithData(kCFAllocatorDefault, certData);
	int result = 0;
	SecTrustRef trust;
	if (SecTrustCreateWithCertificates(certificate, policy, &trust) == errSecSuccess) {
		if (SecTrustEvaluateWithError(trust, NULL)) {
			result = 1;
		}
	}
	if (trust) CFRelease(trust);
	if (certificate) CFRelease(certificate);
	if (certData) CFRelease(certData);
	if (policy) CFRelease(policy);
	if (hostnameStr) CFRelease(hostnameStr);
	return result;
}
*/
import "C"

import (
	"log"
	"unsafe"
)

type iosLogWriter struct{}

func (iosLogWriter) Write(p []byte) (n int, err error) {
	C.printLog(*(*string)(unsafe.Pointer(&p)))
	return len(p), nil
}

type iosErrorLogWriter struct{}

func (iosErrorLogWriter) Write(p []byte) (n int, err error) {
	C.printErrorLog(*(*string)(unsafe.Pointer(&p)))
	return len(p), nil
}

func init() {
	Stdout = log.New(&iosLogWriter{}, "", log.LstdFlags)
	Stderr = log.New(&iosErrorLogWriter{}, "", log.LstdFlags)
	TLSCertVerifier = func(serverName string, certs [][]byte) bool {
		if len(certs) == 0 {
			return false
		}
		return C.verifyTrust(serverName, *(*string)(unsafe.Pointer(&certs[0]))) > 0
	}
}
