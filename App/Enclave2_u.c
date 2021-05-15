#include "Enclave2_u.h"
#include <errno.h>

typedef struct ms_ecall_do_trusted_t {
	int ms_retval;
	int ms_check;
} ms_ecall_do_trusted_t;

typedef struct ms_createRsaKeyPairEcall_t {
	char* ms_public_key_raw_out;
	char* ms_public_key_out;
	unsigned int ms_KEY_SIZE;
} ms_createRsaKeyPairEcall_t;

typedef struct ms_decryptPayloadEcall_t {
	unsigned char* ms_encrypted_payload;
	size_t ms_encrypted_payload_len;
} ms_decryptPayloadEcall_t;

typedef struct ms_decryptPayloadGetSizeEcall_t {
	unsigned char* ms_encrypted_payload;
	size_t ms_encrypted_payload_len;
	size_t* ms_decrypted_payload_len;
} ms_decryptPayloadGetSizeEcall_t;

typedef struct ms_ecall_do_trusted_inside_ocall_t {
	int ms_retval;
} ms_ecall_do_trusted_inside_ocall_t;

typedef struct ms_ocall_print_t {
	const char* ms_str;
} ms_ocall_print_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL Enclave2_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave2_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave2_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave2_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave2_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave2_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[6];
} ocall_table_Enclave2 = {
	6,
	{
		(void*)(uintptr_t)Enclave2_ocall_print,
		(void*)(uintptr_t)Enclave2_sgx_oc_cpuidex,
		(void*)(uintptr_t)Enclave2_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)Enclave2_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)Enclave2_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)Enclave2_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};

sgx_status_t ecall_do_trusted(sgx_enclave_id_t eid, int* retval, int check)
{
	sgx_status_t status;
	ms_ecall_do_trusted_t ms;
	ms.ms_check = check;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave2, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t createRsaKeyPairEcall(sgx_enclave_id_t eid, char* public_key_raw_out, char* public_key_out, unsigned int KEY_SIZE)
{
	sgx_status_t status;
	ms_createRsaKeyPairEcall_t ms;
	ms.ms_public_key_raw_out = public_key_raw_out;
	ms.ms_public_key_out = public_key_out;
	ms.ms_KEY_SIZE = KEY_SIZE;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave2, &ms);
	return status;
}

sgx_status_t decryptPayloadEcall(sgx_enclave_id_t eid, unsigned char* encrypted_payload, size_t encrypted_payload_len)
{
	sgx_status_t status;
	ms_decryptPayloadEcall_t ms;
	ms.ms_encrypted_payload = encrypted_payload;
	ms.ms_encrypted_payload_len = encrypted_payload_len;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave2, &ms);
	return status;
}

sgx_status_t decryptPayloadGetSizeEcall(sgx_enclave_id_t eid, unsigned char* encrypted_payload, size_t encrypted_payload_len, size_t* decrypted_payload_len)
{
	sgx_status_t status;
	ms_decryptPayloadGetSizeEcall_t ms;
	ms.ms_encrypted_payload = encrypted_payload;
	ms.ms_encrypted_payload_len = encrypted_payload_len;
	ms.ms_decrypted_payload_len = decrypted_payload_len;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave2, &ms);
	return status;
}

sgx_status_t ecall_do_trusted_inside_ocall(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_do_trusted_inside_ocall_t ms;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave2, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

