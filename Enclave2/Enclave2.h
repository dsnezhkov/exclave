#ifndef _ENCLAVE2_H_
#define _ENCLAVE2_H_

#include <stdlib.h>
#include <assert.h>
#include <sgx_tcrypto.h>

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

const int sym_shared_key_size = SGX_AESGCM_KEY_SIZE;

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(__cplusplus)
}
#endif

sgx_status_t createRsaKeyPair(sgx_rsa3072_public_key_t* public_key, sgx_rsa3072_key_t* private_key, void** public_key_raw, void** private_key_raw);
unsigned char* storeSymKey(unsigned char* encryptedData, size_t encryptedDataSize);
unsigned char* decryptPayload(unsigned char* encryptedData, size_t encryptedDataSize, unsigned char* mac);

void DumpHex(const void* data, size_t size);

#endif /* !_ENCLAVE2_H_ */
