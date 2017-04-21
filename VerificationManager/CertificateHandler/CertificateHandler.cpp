#include "CertificateHandler.h"

#include <iomanip>
#include <cstdio>
#include <time.h>
#include <string>
#include <sys/time.h>
#include <string.h>
#include "UtilityFunctions.h"
#include "../GeneralSettings.h"

#define RSA_KEY_BITS (4096)

#define REQ_DN_C "SE"
#define REQ_DN_ST ""
#define REQ_DN_L ""
#define REQ_DN_O "Example Company"
#define REQ_DN_OU ""
#define REQ_DN_CN "VNF Application"

using namespace util;
using namespace std;

CertificateHandler* CertificateHandler::instance = NULL;

CertificateHandler::CertificateHandler() {}

CertificateHandler::~CertificateHandler() {}

CertificateHandler* CertificateHandler::getInstance() {
    if (instance == NULL) {
        instance = new CertificateHandler();
    }

    return instance;
}


namespace {

void crt_to_pem(X509 *crt, uint8_t **crt_bytes, size_t *crt_size)
{
	/* Convert signed certificate to PEM format. */
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(bio, crt);
	*crt_size = BIO_pending(bio);
	*crt_bytes = (uint8_t *)malloc(*crt_size + 1);
	BIO_read(bio, *crt_bytes, *crt_size);
	BIO_free_all(bio);
}

int generate_key_csr(EVP_PKEY **key, X509_REQ **req)
{
    RSA *rsa = NULL;
    X509_NAME *name = NULL;

	*key = EVP_PKEY_new();
	if (!*key) goto err;
	*req = X509_REQ_new();
	if (!*req) goto err;

	rsa = RSA_generate_key(RSA_KEY_BITS, RSA_F4, NULL, NULL);
	if (!EVP_PKEY_assign_RSA(*key, rsa)) goto err;

	X509_REQ_set_pubkey(*req, *key);

	/* Set the DN of the request. */
	name = X509_REQ_get_subject_name(*req);
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)REQ_DN_C, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (const unsigned char*)REQ_DN_ST, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (const unsigned char*)REQ_DN_L, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)REQ_DN_O, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (const unsigned char*)REQ_DN_OU, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)REQ_DN_CN, -1, -1, 0);

	/* Self-sign the request to prove that we posses the key. */
	if (!X509_REQ_sign(*req, *key, EVP_sha256())) goto err;
	return 1;
err:
	EVP_PKEY_free(*key);
	X509_REQ_free(*req);
	return 0;
}

int generate_set_random_serial(X509 *crt)
{
	/* Generates a 20 byte random serial number and sets in certificate. */
	unsigned char serial_bytes[20];
	if (RAND_bytes(serial_bytes, sizeof(serial_bytes)) != 1) return 0;
	serial_bytes[0] &= 0x7f; /* Ensure positive serial! */
	BIGNUM *bn = BN_new();
	BN_bin2bn(serial_bytes, sizeof(serial_bytes), bn);
	ASN1_INTEGER *serial = ASN1_INTEGER_new();
	BN_to_ASN1_INTEGER(bn, serial);

	X509_set_serialNumber(crt, serial); // Set serial.

	ASN1_INTEGER_free(serial);
	BN_free(bn);
	return 1;
}

int generate_signed_key_pair(EVP_PKEY *ca_key, X509 *ca_crt, EVP_PKEY **key, X509 **crt)
{
    EVP_PKEY *req_pubkey = NULL;

	/* Generate the private key and corresponding CSR. */
	X509_REQ *req = NULL;
	if (!generate_key_csr(key, &req)) {
		Log("Failed to generate key and/or CSR!");
		return 0;
	}

	/* Sign with the CA. */
	*crt = X509_new();
	if (!*crt) goto err;

	X509_set_version(*crt, 2); /* Set version to X509v3 */

	/* Generate random 20 byte serial. */
	if (!generate_set_random_serial(*crt)) goto err;

	/* Set issuer to CA's subject. */
	X509_set_issuer_name(*crt, X509_get_subject_name(ca_crt));

	/* Set validity of certificate to 2 years. */
	X509_gmtime_adj(X509_get_notBefore(*crt), 0);
	X509_gmtime_adj(X509_get_notAfter(*crt), (long)2*365*3600);

	/* Get the request's subject and just use it (we don't bother checking it since we generated
	 * it ourself). Also take the request's public key. */
	X509_set_subject_name(*crt, X509_REQ_get_subject_name(req));
	req_pubkey = X509_REQ_get_pubkey(req);
	X509_set_pubkey(*crt, req_pubkey);
	EVP_PKEY_free(req_pubkey);

	/* Now perform the actual signing with the CA. */
	if (X509_sign(*crt, ca_key, EVP_sha256()) == 0) goto err;

	X509_REQ_free(req);
	return 1;
err:
	EVP_PKEY_free(*key);
	X509_REQ_free(req);
	X509_free(*crt);
	return 0;
}


void key_to_pem(EVP_PKEY *key, uint8_t **key_bytes, size_t *key_size)
{
	/* Convert private key to PEM format. */
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL);
	*key_size = BIO_pending(bio);
	*key_bytes = (uint8_t *)malloc(*key_size + 1);
	BIO_read(bio, *key_bytes, *key_size);
	BIO_free_all(bio);
}

int load_ca(const char *ca_key_path, EVP_PKEY **ca_key, const char *ca_crt_path, X509 **ca_crt)
{
	BIO *bio = NULL;
	*ca_crt = NULL;
	*ca_key = NULL;

	/* Load CA public key. */
	bio = BIO_new(BIO_s_file());
	if (!BIO_read_filename(bio, ca_crt_path)) goto err;
	*ca_crt = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (!*ca_crt) goto err;
	BIO_free_all(bio);

	/* Load CA private key. */
	bio = BIO_new(BIO_s_file());
	if (!BIO_read_filename(bio, ca_key_path)) goto err;
	*ca_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	if (!ca_key) goto err;
	BIO_free_all(bio);
	return 1;
err:
	BIO_free_all(bio);
	X509_free(*ca_crt);
	EVP_PKEY_free(*ca_key);
	return 0;
}

}


int CertificateHandler::generateKeyPair(uint8_t **evp_pkey, int *pkey_size, uint8_t **x509_crt, int *x509_size) {
	/* Load CA key and cert. */
	EVP_PKEY *ca_key = NULL;
	X509 *ca_crt = NULL;
	if (!load_ca(Settings::ca_key_path.c_str(), &ca_key, Settings::ca_crt_path.c_str(), &ca_crt)) {
		Log("Failed to load CA certificate and/or key!");
		return 1;
	}

	/* Generate CA-signed keypair. */
	EVP_PKEY *key = NULL;
	X509 *crt = NULL;

	int ret = generate_signed_key_pair(ca_key, ca_crt, &key, &crt);
	if (!ret) {
		Log("Failed to generate key pair!");
		return 1;
	}

	/* Convert key and certificate to PEM format. */
	uint8_t *key_bytes = NULL;
	uint8_t *crt_bytes = NULL;
	size_t key_size = 0;
	size_t crt_size = 0;

	key_to_pem(key, &key_bytes, &key_size);
	crt_to_pem(crt, &crt_bytes, &crt_size);

    /* Replace \n with \r\n to make it work with mbedtls. */
    std::string tmp;
    std::stringstream ss2;

    std::stringstream ss_pkey((char*)key_bytes);
    while (std::getline(ss_pkey, tmp, '\n')) {
        ss2 << tmp << "\r\n";
    }

    std::string pkey_str = ss2.str();

    ss2.str(string());
    std::stringstream ss_x509((char*)crt_bytes);

    while (std::getline(ss_x509, tmp, '\n')) {
        ss2 << tmp << "\r\n";
    }

    std::string x509_str = ss2.str();

    *pkey_size = StringToByteArray(pkey_str, evp_pkey);
    *x509_size = StringToByteArray(x509_str, x509_crt);

	/* Free stuff. */
	EVP_PKEY_free(ca_key);
	EVP_PKEY_free(key);
	X509_free(ca_crt);
	X509_free(crt);
	free(key_bytes);
	free(crt_bytes);

    return 0;
}

/* vim: set ai expandtab ts=4 sw=4: */
