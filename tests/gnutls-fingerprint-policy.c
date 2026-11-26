/* SPDX-License-Identifier: Apache-2.0 */

/* Verify GnuTLS fingerprint pin compatibility against a known certificate. */
#include "config.h"

#if defined(ENABLE_TLS) && defined(HAVE_GNUTLS_CERTIFICATE_SET_VERIFY_FUNCTION)

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "gnutls_fingerprint.h"

#ifndef TEST_CERT_DIR
#define TEST_CERT_DIR "tls-certs"
#endif

typedef struct {
	const char *const *pins;
	size_t count;
} pinList_t;

#if GNUTLS_VERSION_NUMBER < 0x030202
typedef gnutls_mac_algorithm_t testDigestId_t;
#define TEST_DIGEST_UNKNOWN GNUTLS_MAC_UNKNOWN
#define TEST_SHA1_ID GNUTLS_MAC_SHA1
#define testDigestGetId gnutls_mac_get_id
#define testDigestGetName gnutls_mac_get_name
#define testDigestList gnutls_mac_list
#else
typedef gnutls_digest_algorithm_t testDigestId_t;
#define TEST_DIGEST_UNKNOWN GNUTLS_DIG_UNKNOWN
#define TEST_SHA1_ID GNUTLS_DIG_SHA1
#define testDigestGetId gnutls_digest_get_id
#define testDigestGetName gnutls_digest_get_name
#define testDigestList gnutls_digest_list
#endif

#define TEST_DIGEST_BUFFER_SIZE 126

static const char *
pinAt(const void *const context, const size_t index)
{
	const pinList_t *const list = context;
	return index < list->count ? list->pins[index] : NULL;
}

static int
loadCertificate(gnutls_x509_crt_t *const cert)
{
	const char *const path = TEST_CERT_DIR "/cert.pem";
	FILE *file = fopen(path, "rb");
	unsigned char *data = NULL;
	long fileLength;
	gnutls_datum_t datum;
	int result = 0;

	if(file == NULL)
		return 0;
	if(fseek(file, 0, SEEK_END) != 0 || (fileLength = ftell(file)) <= 0 ||
	   (unsigned long) fileLength > UINT_MAX || fseek(file, 0, SEEK_SET) != 0)
		goto done;
	data = malloc((size_t) fileLength);
	if(data == NULL || fread(data, 1, (size_t) fileLength, file) != (size_t) fileLength)
		goto done;

	datum.data = data;
	datum.size = (unsigned int) fileLength;
	if(gnutls_x509_crt_init(cert) != GNUTLS_E_SUCCESS)
		goto done;
	if(gnutls_x509_crt_import(*cert, &datum, GNUTLS_X509_FMT_PEM) != GNUTLS_E_SUCCESS) {
		gnutls_x509_crt_deinit(*cert);
		*cert = NULL;
		goto done;
	}
	result = 1;

done:
	free(data);
	fclose(file);
	return result;
}

static int
expectResult(const char *const name, gnutls_x509_crt_t cert,
	const char *const *pins, const size_t pinCount,
	const relpGnuTLSFingerprintResult_t expected)
{
	const pinList_t list = { pins, pinCount };
	int gnutlsError = GNUTLS_E_SUCCESS;
	char authInfo[RELP_GNUTLS_FINGERPRINT_AUTHINFO_SIZE];
	const relpGnuTLSFingerprintResult_t actual = relpGnuTLSFingerprintCheck(
		cert, list.count, pinAt, &list, authInfo, sizeof(authInfo), &gnutlsError);
	if(actual != expected) {
		fprintf(stderr, "%s: expected result %d, got %d (GnuTLS %d)\n",
			name, expected, actual, gnutlsError);
		return 0;
	}
	return 1;
}

static int
expectAuthInfo(const char *const name, gnutls_x509_crt_t cert,
	const char *const *pins, const size_t pinCount,
	const relpGnuTLSFingerprintResult_t expectedResult, const char *const expectedAuthInfo)
{
	const pinList_t list = { pins, pinCount };
	char authInfo[RELP_GNUTLS_FINGERPRINT_AUTHINFO_SIZE];
	int gnutlsError = GNUTLS_E_SUCCESS;
	const relpGnuTLSFingerprintResult_t actual = relpGnuTLSFingerprintCheck(
		cert, list.count, pinAt, &list, authInfo, sizeof(authInfo), &gnutlsError);
	if(actual != expectedResult || strcmp(authInfo, expectedAuthInfo) != 0) {
		fprintf(stderr, "%s: result %d (expected %d), authinfo '%s' (expected '%s'), GnuTLS %d\n",
			name, actual, expectedResult, authInfo, expectedAuthInfo, gnutlsError);
		return 0;
	}
	return 1;
}

static int
expectBackendError(const char *const name, const char *const pin)
{
	const char *pins[1] = { pin };
	const pinList_t list = { pins, 1 };
	gnutls_x509_crt_t incompleteCert = NULL;
	char authInfo[RELP_GNUTLS_FINGERPRINT_AUTHINFO_SIZE];
	int gnutlsError = GNUTLS_E_SUCCESS;
	relpGnuTLSFingerprintResult_t actual;
	if(gnutls_x509_crt_init(&incompleteCert) != GNUTLS_E_SUCCESS)
		return 0;
	actual = relpGnuTLSFingerprintCheck(incompleteCert, list.count, pinAt,
		&list, authInfo, sizeof(authInfo), &gnutlsError);
	gnutls_x509_crt_deinit(incompleteCert);
	if(actual != RELP_GNUTLS_FINGERPRINT_ERROR ||
	   gnutlsError == GNUTLS_E_SUCCESS || authInfo[0] != '\0') {
		fprintf(stderr, "%s: expected digest error with empty authinfo; got result %d, GnuTLS %d, authinfo '%s'\n",
			name, actual, gnutlsError, authInfo);
		return 0;
	}
	return 1;
}

static int
makeFingerprint(gnutls_x509_crt_t cert, const testDigestId_t id,
	const char *const digestName, char *const output, const size_t outputLength)
{
	static const char hexDigits[] = "0123456789ABCDEF";
	unsigned char digest[TEST_DIGEST_BUFFER_SIZE];
	size_t digestLength = sizeof(digest);
	size_t nameLength = strlen(digestName);
	size_t requiredLength;
	size_t position;
	size_t i;
	if(gnutls_x509_crt_get_fingerprint(cert, (gnutls_digest_algorithm_t) id,
		digest, &digestLength) != GNUTLS_E_SUCCESS)
		return 0;
	requiredLength = nameLength + 3 * digestLength + 1;
	if(requiredLength >= 256 || requiredLength > outputLength)
		return 0;
	memcpy(output, digestName, nameLength);
	position = nameLength;
	for(i = 0; i < digestLength; ++i) {
		output[position++] = ':';
		output[position++] = hexDigits[digest[i] >> 4];
		output[position++] = hexDigits[digest[i] & 0x0f];
	}
	output[position] = '\0';
	return 1;
}

static int
testRuntimeDigestAndAlias(gnutls_x509_crt_t cert, const char *const sha1)
{
	static const char *const aliases[] = { "sha1", "SHA-1", "SHA_1", "SHA" };
	static const char unrecognizedAlias[] =
		"sha1:5C:C6:62:D5:9D:25:9F:BC:F3:CB:61:FA:D2:B3:8B:61:88:D7:06:C3";
	char aliasPin[256];
	const char *const colon = strchr(sha1, ':');
	const char *pins[2];
	size_t i;
	if(colon == NULL)
		return 0;
	pins[0] = unrecognizedAlias;
	if(!expectResult("lowercase digest spelling", cert, pins, 1,
		RELP_GNUTLS_FINGERPRINT_NO_MATCH))
		return 0;
	pins[0] = unrecognizedAlias;
	pins[1] = sha1;
	if(!expectResult("lowercase spelling then canonical SHA1", cert, pins, 2,
		RELP_GNUTLS_FINGERPRINT_MATCH))
		return 0;
	pins[0] = sha1;
	pins[1] = unrecognizedAlias;
	if(!expectResult("canonical SHA1 then lowercase spelling", cert, pins, 2,
		RELP_GNUTLS_FINGERPRINT_MATCH))
		return 0;
	for(i = 0; i < sizeof(aliases) / sizeof(aliases[0]); ++i) {
		if(testDigestGetId(aliases[i]) != TEST_SHA1_ID)
			continue;
		(void) snprintf(aliasPin, sizeof(aliasPin), "%s%s", aliases[i], colon);
		pins[0] = aliasPin;
		if(!expectResult("digest alias retains exact canonical spelling rule", cert,
			pins, 1, RELP_GNUTLS_FINGERPRINT_NO_MATCH))
			return 0;
		/* A recognized alias must not prevent a canonical sibling from matching,
		 * regardless of the alias pin's position in the list. */
		pins[0] = aliasPin;
		pins[1] = sha1;
		if(!expectResult("alias then canonical SHA1", cert, pins, 2,
			RELP_GNUTLS_FINGERPRINT_MATCH))
			return 0;
		pins[0] = sha1;
		pins[1] = aliasPin;
		if(!expectResult("canonical SHA1 then alias", cert, pins, 2,
			RELP_GNUTLS_FINGERPRINT_MATCH))
			return 0;
		return 1;
	}
	fprintf(stderr, "no SHA1 alias recognized by this GnuTLS runtime; alias checks skipped\n");
	return 1;
}

static int
testAdditionalRuntimeDigest(gnutls_x509_crt_t cert)
{
	const testDigestId_t *const digestIds = testDigestList();
	size_t i;
	for(i = 0; digestIds != NULL && digestIds[i] != TEST_DIGEST_UNKNOWN; ++i) {
		const char *const name = testDigestGetName(digestIds[i]);
		char pin[256];
		const char *pins[1];
		if(name == NULL || testDigestGetId(name) != digestIds[i] ||
		   strcmp(name, "SHA1") == 0 || strcmp(name, "SHA256") == 0 ||
		   strcmp(name, "SHA384") == 0 || strcmp(name, "SHA512") == 0)
			continue;
		if(!makeFingerprint(cert, digestIds[i], name, pin, sizeof(pin)))
			continue;
		pins[0] = pin;
		if(!expectResult("additional runtime digest", cert, pins, 1,
			RELP_GNUTLS_FINGERPRINT_MATCH))
			return 0;
		fprintf(stderr, "tested additional runtime digest %s\n", name);
		return 1;
	}
	fprintf(stderr, "no additional runtime digest available for fingerprint test\n");
	return 1;
}

static int
testDigestLimit(gnutls_x509_crt_t cert)
{
	const testDigestId_t *const digestIds = testDigestList();
	char pinsText[11][256];
	const char *pins[11];
	testDigestId_t usedIds[11];
	char expectedAuthInfo[256];
	size_t usableCount = 0;
	size_t i;
	for(i = 0; digestIds != NULL && digestIds[i] != TEST_DIGEST_UNKNOWN &&
		usableCount < 11; ++i) {
		const char *const name = testDigestGetName(digestIds[i]);
		char canonicalPin[256];
		size_t j;
		int duplicate = 0;
		if(name == NULL || strlen(name) > 31 || testDigestGetId(name) != digestIds[i] ||
		   !makeFingerprint(cert, digestIds[i], name, canonicalPin, sizeof(canonicalPin)))
			continue;
		for(j = 0; j < usableCount; ++j) {
			if(usedIds[j] == digestIds[i]) {
				duplicate = 1;
				break;
			}
		}
		if(duplicate)
			continue;
		usedIds[usableCount] = digestIds[i];
		if(snprintf(pinsText[usableCount], sizeof(pinsText[usableCount]),
			"%s:malformed", name) >= (int) sizeof(pinsText[usableCount]))
			return 0;
		pins[usableCount] = pinsText[usableCount];
		if(usableCount == 9)
			(void) strcpy(expectedAuthInfo, canonicalPin);
		if(usableCount == 10)
			(void) strcpy(pinsText[usableCount], canonicalPin);
		++usableCount;
	}
	if(usableCount < 11) {
		fprintf(stderr, "runtime exposes fewer than eleven usable digests; ten-pin cap check skipped\n");
		return 1;
	}
	if(!expectAuthInfo("recognized digest cap and malformed slots", cert, pins, 11,
		RELP_GNUTLS_FINGERPRINT_NO_MATCH, expectedAuthInfo))
		return 0;
	return 1;
}

int
main(void)
{
	static const char sha1[] =
		"SHA1:5C:C6:62:D5:9D:25:9F:BC:F3:CB:61:FA:D2:B3:8B:61:88:D7:06:C3";
	static const char sha256[] =
		"SHA256:1E:8F:A1:97:BF:96:8F:A7:27:C3:8F:07:81:1E:C8:B1:32:BD:BD:ED:07:A1:48:C4:BC:83:CE:BD:62:F8:DD:F6";
	static const char sha384[] =
		"SHA384:54:0D:0D:16:C0:8D:65:F4:FF:E8:52:9F:A9:4A:92:B8:D6:7B:A6:21:B2:EF:E5:C7:D8:59:F3:D9:89:54:E1:D8:8C:A5:9A:19:BD:1E:9B:F8:3C:CD:5F:79:8E:40:06:46";
	static const char sha512[] =
		"SHA512:E6:CB:A0:1E:10:15:D4:B8:AE:3A:04:E1:0A:BA:0A:07:D2:3F:36:BA:66:4C:2D:C8:2A:AE:5E:5A:4C:B3:13:A0:7B:BC:EE:BF:1D:09:0C:BB:6B:79:46:58:36:DF:35:B1:B2:EE:07:C2:6B:6F:68:2B:B4:B2:4C:0D:4C:20:17:31";
	static const char wrongSha1[] =
		"SHA1:00:C6:62:D5:9D:25:9F:BC:F3:CB:61:FA:D2:B3:8B:61:88:D7:06:C3";
	static const char wrongSha256[] =
		"SHA256:00:8F:A1:97:BF:96:8F:A7:27:C3:8F:07:81:1E:C8:B1:32:BD:BD:ED:07:A1:48:C4:BC:83:CE:BD:62:F8:DD:F6";
	static const char malformed[] = "SHA1:GG:C6";
	static const char unsupported[] = "UNKNOWN:5C:C6:62:D5:9D:25:9F:BC:F3:CB:61:FA:D2:B3:8B:61:88:D7:06:C3";
	static const char lowerHex[] =
		"SHA1:5c:c6:62:d5:9d:25:9f:bc:f3:cb:61:fa:d2:b3:8b:61:88:d7:06:c3";
	const char *onePin[1];
	const char *twoPins[2];
	gnutls_x509_crt_t cert = NULL;
	int ok = 1;

	if(gnutls_global_init() != GNUTLS_E_SUCCESS || !loadCertificate(&cert)) {
		fputs("failed to initialize GnuTLS or load test certificate\n", stderr);
		return EXIT_FAILURE;
	}

	onePin[0] = sha1;
	ok &= expectResult("SHA1 compatibility", cert, onePin, 1,
		RELP_GNUTLS_FINGERPRINT_MATCH);
	onePin[0] = sha256;
	ok &= expectResult("SHA256", cert, onePin, 1, RELP_GNUTLS_FINGERPRINT_MATCH);
	onePin[0] = sha384;
	ok &= expectResult("SHA384", cert, onePin, 1, RELP_GNUTLS_FINGERPRINT_MATCH);
	onePin[0] = sha512;
	ok &= expectResult("SHA512", cert, onePin, 1, RELP_GNUTLS_FINGERPRINT_MATCH);

	twoPins[0] = wrongSha1;
	twoPins[1] = sha256;
	ok &= expectResult("mixed order SHA1 then SHA256", cert, twoPins, 2,
		RELP_GNUTLS_FINGERPRINT_MATCH);
	twoPins[0] = sha512;
	twoPins[1] = wrongSha1;
	ok &= expectResult("mixed order SHA512 then SHA1", cert, twoPins, 2,
		RELP_GNUTLS_FINGERPRINT_MATCH);
	twoPins[0] = wrongSha1;
	twoPins[1] = wrongSha256;
	ok &= expectAuthInfo("valid pins with no match", cert, twoPins, 2,
		RELP_GNUTLS_FINGERPRINT_NO_MATCH, sha256);
	twoPins[0] = wrongSha256;
	twoPins[1] = wrongSha1;
	ok &= expectAuthInfo("reversed valid pins with no match", cert, twoPins, 2,
		RELP_GNUTLS_FINGERPRINT_NO_MATCH, sha1);
	onePin[0] = wrongSha1;
	ok &= expectAuthInfo("SHA1 mismatch authinfo", cert, onePin, 1,
		RELP_GNUTLS_FINGERPRINT_NO_MATCH, sha1);
	onePin[0] = wrongSha256;
	ok &= expectAuthInfo("SHA256 mismatch authinfo", cert, onePin, 1,
		RELP_GNUTLS_FINGERPRINT_NO_MATCH, sha256);

	twoPins[0] = sha1;
	twoPins[1] = unsupported;
	ok &= expectResult("unknown pin after matching pin", cert, twoPins, 2,
		RELP_GNUTLS_FINGERPRINT_MATCH);
	twoPins[0] = unsupported;
	twoPins[1] = sha1;
	ok &= expectResult("unknown pin before matching pin", cert, twoPins, 2,
		RELP_GNUTLS_FINGERPRINT_MATCH);
	twoPins[0] = sha1;
	twoPins[1] = malformed;
	ok &= expectResult("malformed pin after matching pin", cert, twoPins, 2,
		RELP_GNUTLS_FINGERPRINT_MATCH);
	twoPins[0] = malformed;
	twoPins[1] = sha1;
	ok &= expectResult("malformed pin before matching pin", cert, twoPins, 2,
		RELP_GNUTLS_FINGERPRINT_MATCH);
	onePin[0] = lowerHex;
	ok &= expectResult("non-canonical lowercase hex", cert, onePin, 1,
		RELP_GNUTLS_FINGERPRINT_NO_MATCH);
	onePin[0] = unsupported;
	ok &= expectAuthInfo("unknown-only list", cert, onePin, 1,
		RELP_GNUTLS_FINGERPRINT_NO_MATCH, "");
	onePin[0] = malformed;
	ok &= expectAuthInfo("malformed recognized list", cert, onePin, 1,
		RELP_GNUTLS_FINGERPRINT_NO_MATCH, sha1);
	ok &= expectResult("empty policy", cert, NULL, 0,
		RELP_GNUTLS_FINGERPRINT_NO_MATCH);
	ok &= testRuntimeDigestAndAlias(cert, sha1);
	ok &= testAdditionalRuntimeDigest(cert);
	ok &= testDigestLimit(cert);
	ok &= expectBackendError("backend error authinfo", sha1);

	gnutls_x509_crt_deinit(cert);
	gnutls_global_deinit();
	return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}

#else

int
main(void)
{
	return EXIT_SUCCESS;
}

#endif
