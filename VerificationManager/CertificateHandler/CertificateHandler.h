#ifndef CERTIFICATEHANDLER_H
#define CERTIFICATEHANDLER_H

#include <iostream>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>

#include "LogBase.h"

using namespace std;

class CertificateHandler {

public:
    static CertificateHandler* getInstance();
    virtual ~CertificateHandler();
    int generateKeyPair(uint8_t **evp_key, int *evp_key_size, uint8_t **x509_crt, int *x509_size);

private:
    CertificateHandler();

private:
    static CertificateHandler *instance;
};

#endif











