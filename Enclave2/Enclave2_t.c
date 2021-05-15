#include "Enclave2_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_ecall_do_trusted_t {
	int ms_retval;
	int ms_check;
} ms_ecall_do_trusted_t;

typedef struct ms_createRsaKeyPairEcall_t {
	char* ms_public_key_raw_out;
	char* ms_public_key_out;
} ms_createRsaKeyPairEcall_t;

typedef struct ms_storeSymKeyEcall_t {
	unsigned char* ms_encrypted_payload;
	size_t ms_encrypted_payload_len;
} ms_storeSymKeyEcall_t;

typedef struct ms_decryptPayloadEcall_t {
	unsigned char* ms_encrypted_payload;
	size_t ms_encrypted_payload_len;
	unsigned char* ms_mac;
} ms_decryptPayloadEcall_t;

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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_ecall_do_trusted(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_do_trusted_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_do_trusted_t* ms = SGX_CAST(ms_ecall_do_trusted_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = ecall_do_trusted(ms->ms_check);


	return status;
}

static sgx_status_t SGX_CDECL sgx_createRsaKeyPairEcall(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_createRsaKeyPairEcall_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_createRsaKeyPairEcall_t* ms = SGX_CAST(ms_createRsaKeyPairEcall_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_public_key_raw_out = ms->ms_public_key_raw_out;
	size_t _len_public_key_raw_out = 384;
	char* _in_public_key_raw_out = NULL;
	char* _tmp_public_key_out = ms->ms_public_key_out;
	size_t _len_public_key_out = 388;
	char* _in_public_key_out = NULL;

	CHECK_UNIQUE_POINTER(_tmp_public_key_raw_out, _len_public_key_raw_out);
	CHECK_UNIQUE_POINTER(_tmp_public_key_out, _len_public_key_out);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_public_key_raw_out != NULL && _len_public_key_raw_out != 0) {
		if ( _len_public_key_raw_out % sizeof(*_tmp_public_key_raw_out) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_public_key_raw_out = (char*)malloc(_len_public_key_raw_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_public_key_raw_out, 0, _len_public_key_raw_out);
	}
	if (_tmp_public_key_out != NULL && _len_public_key_out != 0) {
		if ( _len_public_key_out % sizeof(*_tmp_public_key_out) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_public_key_out = (char*)malloc(_len_public_key_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_public_key_out, 0, _len_public_key_out);
	}

	createRsaKeyPairEcall(_in_public_key_raw_out, _in_public_key_out);
	if (_in_public_key_raw_out) {
		if (memcpy_s(_tmp_public_key_raw_out, _len_public_key_raw_out, _in_public_key_raw_out, _len_public_key_raw_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_public_key_out) {
		if (memcpy_s(_tmp_public_key_out, _len_public_key_out, _in_public_key_out, _len_public_key_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_public_key_raw_out) free(_in_public_key_raw_out);
	if (_in_public_key_out) free(_in_public_key_out);
	return status;
}

static sgx_status_t SGX_CDECL sgx_storeSymKeyEcall(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_storeSymKeyEcall_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_storeSymKeyEcall_t* ms = SGX_CAST(ms_storeSymKeyEcall_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_encrypted_payload = ms->ms_encrypted_payload;
	size_t _tmp_encrypted_payload_len = ms->ms_encrypted_payload_len;
	size_t _len_encrypted_payload = _tmp_encrypted_payload_len;
	unsigned char* _in_encrypted_payload = NULL;

	CHECK_UNIQUE_POINTER(_tmp_encrypted_payload, _len_encrypted_payload);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_encrypted_payload != NULL && _len_encrypted_payload != 0) {
		if ( _len_encrypted_payload % sizeof(*_tmp_encrypted_payload) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_encrypted_payload = (unsigned char*)malloc(_len_encrypted_payload);
		if (_in_encrypted_payload == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_encrypted_payload, _len_encrypted_payload, _tmp_encrypted_payload, _len_encrypted_payload)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	storeSymKeyEcall(_in_encrypted_payload, _tmp_encrypted_payload_len);

err:
	if (_in_encrypted_payload) free(_in_encrypted_payload);
	return status;
}

static sgx_status_t SGX_CDECL sgx_decryptPayloadEcall(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_decryptPayloadEcall_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_decryptPayloadEcall_t* ms = SGX_CAST(ms_decryptPayloadEcall_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_encrypted_payload = ms->ms_encrypted_payload;
	size_t _tmp_encrypted_payload_len = ms->ms_encrypted_payload_len;
	size_t _len_encrypted_payload = _tmp_encrypted_payload_len;
	unsigned char* _in_encrypted_payload = NULL;
	unsigned char* _tmp_mac = ms->ms_mac;
	size_t _len_mac = 16;
	unsigned char* _in_mac = NULL;

	CHECK_UNIQUE_POINTER(_tmp_encrypted_payload, _len_encrypted_payload);
	CHECK_UNIQUE_POINTER(_tmp_mac, _len_mac);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_encrypted_payload != NULL && _len_encrypted_payload != 0) {
		if ( _len_encrypted_payload % sizeof(*_tmp_encrypted_payload) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_encrypted_payload = (unsigned char*)malloc(_len_encrypted_payload);
		if (_in_encrypted_payload == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_encrypted_payload, _len_encrypted_payload, _tmp_encrypted_payload, _len_encrypted_payload)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_mac != NULL && _len_mac != 0) {
		if ( _len_mac % sizeof(*_tmp_mac) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_mac = (unsigned char*)malloc(_len_mac);
		if (_in_mac == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_mac, _len_mac, _tmp_mac, _len_mac)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	decryptPayloadEcall(_in_encrypted_payload, _tmp_encrypted_payload_len, _in_mac);

err:
	if (_in_encrypted_payload) free(_in_encrypted_payload);
	if (_in_mac) free(_in_mac);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_do_trusted_inside_ocall(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_do_trusted_inside_ocall_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_do_trusted_inside_ocall_t* ms = SGX_CAST(ms_ecall_do_trusted_inside_ocall_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = ecall_do_trusted_inside_ocall();


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[5];
} g_ecall_table = {
	5,
	{
		{(void*)(uintptr_t)sgx_ecall_do_trusted, 0, 0},
		{(void*)(uintptr_t)sgx_createRsaKeyPairEcall, 0, 0},
		{(void*)(uintptr_t)sgx_storeSymKeyEcall, 0, 0},
		{(void*)(uintptr_t)sgx_decryptPayloadEcall, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_do_trusted_inside_ocall, 1, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[6][5];
} g_dyn_entry_table = {
	6,
	{
		{0, 0, 0, 0, 1, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_t));
	ocalloc_size -= sizeof(ms_ocall_print_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
