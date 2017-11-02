#include "MessageHandlerApplication.h"
#include "../GeneralSettings.h"

using namespace util;

MessageHandlerApplication::MessageHandlerApplication() : MessageHandler(Settings::container_port) {}

MessageHandlerApplication::~MessageHandlerApplication() {}


string MessageHandlerApplication::verificationSuccessful() {
    Log("Send attestation okay");

    Messages::InitialMessage msg;
    msg.set_type(RA_APP_ATT_OK);
    msg.set_size(0);

    return nm->serialize(msg);
}


string MessageHandlerApplication::getCertificate(string path) {
    char *content;
    int content_size;

    content_size = ReadFileToBuffer(path, &content);

    string str(content);

    stringstream ss(content);
    free(content);
    string tmp;
    stringstream ss2;

    while(std::getline(ss, tmp,'\n')) {
        ss2 << tmp << "\r\n";
    }

    return ss2.str();
}



void MessageHandlerApplication::startSSLSession() {
    Log("Start TLS/SSL connection");

    sgx_status_t ret, status;

    string certificate = this->getCertificate(Settings::nginx_pub_crt);

    ret = mbedtls_connection(this->enclave->getID(),
                             &status,
                             certificate.c_str(),
                             (certificate.length()+1));
}


string MessageHandlerApplication::handleApplicationNonce(Messages::SecretMessage sec_msg) {
    Log("Received hmac nonce");

    uint8_t encrypted[sec_msg.size()];
    uint8_t gcm_mac[16];

    for (int i=0; i<sec_msg.size(); i++)
        encrypted[i] = sec_msg.encrypted_content(i);

    for (int i=0; i<16; i++)
        gcm_mac[i] = sec_msg.mac_smk(i);

    sgx_status_t status, ret;
    uint8_t hmac_filename[FILE_UUID_LENGTH];

    ret = extract_hmac(this->enclave->getID(),
                       &status,
                       this->enclave->getContext(),
                       encrypted,
                       sec_msg.size(),
                       gcm_mac,
                       hmac_filename);

    if (SGX_SUCCESS != ret) {
        Log("Return error, processing hmac nonce: 0x%x", ret, log::error);
        print_error_message(ret);
    } else if (SGX_SUCCESS != status) {
        Log("Return status, processing hmac nonce: 0x%x", status, log::error);
        print_error_message(status);
    }

    Log("HMAC stuff decrypted sucessfully");

    string str_hmac_filename = ByteArrayToNoHexString(hmac_filename, FILE_UUID_LENGTH);

    string fullPath = Settings::applicationHashKeyLocation + str_hmac_filename;
    char *content;
    int content_size = ReadFileToBuffer(fullPath, &content);
    RemoveFile(fullPath);

    string str_content(content);
    uint8_t *hmac_key;
    int hmac_key_len = StringToByteArray(str_content, &hmac_key);

    uint8_t hmac_encrypted[HMAC_LENGTH];
    memset(gcm_mac, '\0', 16);

    ret = calc_hmac(this->enclave->getID(),
                    &status,
                    this->enclave->getContext(),
                    hmac_key,
                    hmac_encrypted,
                    gcm_mac);

    if (SGX_SUCCESS != ret) {
        Log("Return error, processing hmac nonce: 0x%x", ret, log::error);
        print_error_message(ret);
    } else if (SGX_SUCCESS != status) {
        Log("Return status, processing hmac nonce: 0x%x", status, log::error);
        print_error_message(status);
    } else {
        Log("HMAC calculated successfully");

        // Now, generate the private key and create a certificate signing request.
        uint8_t buf[4096]; // 4096 bytes should be enough according to mbedtls.
        uint8_t buf_mac[16];
        uint32_t buf_size = sizeof(buf); // will later be replaced by the actual returned content size.
        ret = generate_pkey_csr(this->enclave->getID(), &status, this->enclave->getContext(), buf, &buf_size, buf_mac);
        if (SGX_SUCCESS != ret) {
            Log("Return error, key generation 1: 0x%x", ret, log::error);
            print_error_message(ret);
        } else if (SGX_SUCCESS != status) {
            Log("Return status, key generation 2: 0x%x", status, log::error);
            print_error_message(status);
        } else {
            Log("Private key and CSR (size: %u) generated successfully inside enclave", buf_size);
        }

        // The CSR is now a null-terminated string PEM CSR inside buf, but encrypted and MAC:d as usual.

        Messages::SecretMessage msg;
        msg.set_type(APP_HMAC);
        msg.set_size(HMAC_LENGTH);
        

        for (int i=0; i<HMAC_LENGTH; i++)
            msg.add_encrypted_content(hmac_encrypted[i]);

        for (int i=0; i<16; i++)
            msg.add_mac_smk(gcm_mac[i]);

        // Now add encrypted CSR
        for (int i=0; i<buf_size; i++)
            msg.add_encrypted_x509(buf[i]);
        
        for (int i=0; i<16; i++)
            msg.add_encrypted_x509_mac_smk(buf_mac[i]);

        return nm->serialize(msg);
    }

    return "";
}


string MessageHandlerApplication::handleAppHMACResult(Messages::SecretMessage sec_msg) {
    Log("Received HMAC result");

    //=================  VERIFY HMAC MATCHED  ======================
    uint32_t size = sec_msg.size();
    uint8_t *encrypted = (uint8_t*) malloc(sizeof(uint8_t) * size);
    uint8_t gcm_mac[16] = {0};

    for (int i=0; i<size; i++)
        encrypted[i] = sec_msg.encrypted_content(i);

    for (int i=0; i<16; i++)
        gcm_mac[i] = sec_msg.mac_smk(i);


    sgx_status_t status, ret;
    uint8_t result[1] = {0};

    ret = verify_secret_data(this->enclave->getID(),
                             &status,
                             this->enclave->getContext(),
                             encrypted,
                             size,
                             gcm_mac,
                             0,
                             result);

    free(encrypted);

    if (SGX_SUCCESS != ret) {
        Log("Error, decrypting fingerprint result failed", log::error);
        print_error_message(ret);
        return "";
    }

    if (SGX_SUCCESS != status) {
        Log("Error, decrypting fingerprint result failed", log::error);
        print_error_message(status);
        return "";
    }
    //======================================================================

    if (result[0] == 1) {
        Log("Fingerprints match!!!");
        Log("Processing x509");

        //===============  SETUP THE RECEIVED CRT  ====================



        uint32_t x509_size = sec_msg.encrypted_x509_size();
        uint8_t *x509_encrypted = (uint8_t*) malloc(sizeof(uint8_t) * x509_size);
        uint8_t x509_gcm_mac[16] = {0};

        for (int i=0; i<x509_size; i++)
            x509_encrypted[i] = sec_msg.encrypted_x509(i);

        for (int i=0; i<16; i++)
            x509_gcm_mac[i] = sec_msg.encrypted_x509_mac_smk(i);

        ret = process_x509_cert(this->enclave->getID(),
                                &status,
                                this->enclave->getContext(),
                                x509_encrypted,
                                x509_size,
                                x509_gcm_mac);

        if (SGX_SUCCESS != ret) {
            Log("Return error, processing x509: 0x%x", ret, log::error);
            print_error_message(ret);
            return "";
        }

        if (SGX_SUCCESS != status) {
            Log("Status error, processing x509: 0x%x", status, log::error);
            print_error_message(status);
            return "";
        }
        //=====================================================================

        this->startSSLSession();

    } else {
        Log("HMAC did not match :(");
    }

    return "";
}





