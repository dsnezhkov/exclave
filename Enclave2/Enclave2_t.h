#ifndef ENCLAVE2_T_H__
#define ENCLAVE2_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int ecall_do_trusted(int check);
void createRsaKeyPairEcall(char* public_key_raw_out, char* public_key_out);
void storeSymKeyEcall(unsigned char* encrypted_payload, size_t encrypted_payload_len);
void decryptPayloadEcall(unsigned char* encrypted_payload, size_t encrypted_payload_len, unsigned char* mac);
int ecall_do_trusted_inside_ocall(void);

sgx_status_t SGX_CDECL ocall_print(const char* str);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
