#pragma once
#ifndef _BRIDGE_H_
#define _BRIDGE_H_


#define WIN32_LEAN_AND_MEAN 
#include <tchar.h>
#include <windows.h>

#include <assert.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <stdarg.h>

#include "sgx_error.h"       
#include "sgx_eid.h"		

#include "sgx_capable.h"
#include "sgx_urts.h"
#include "sgx_tcrypto.h"

#include "Enclave2_u.h"

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

#define CANNOT_CONTINUE FALSE
#define CAN_CONTINUE TRUE

#pragma comment( lib, "sgx_capable" )


typedef struct _sgx_errlist_t {
	sgx_status_t err;
	const char* msg;
	const char* sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
    {
        SGX_ERROR_MAC_MISMATCH,
        "Enc/Dec MAC mismatch",
        NULL
    },

};

sgx_enclave_id_t enclaveId;		
sgx_status_t     ret;

#if defined(__cplusplus)
extern "C" {
#endif
    // internal
	// utility
	void DumpHex(const void* data, size_t size);
	void buf2hex(uint8_t* buf, unsigned int sz);
	void WriteBufFile(const char* fileName, char* buf, size_t sz);
	int readBin(const char* bin_file_name, unsigned char** buffer);
    void print_error_message(sgx_status_t ret);

    sgx_enclave_id_t createEnclave(char* encalaveSignedFile);

    // ocalls
    void ocall_print(const char* str);

    // exported
    int __declspec(dllexport) enableSGXEFI();
    int __declspec(dllexport) checkECapability();
	uint64_t __declspec(dllexport) initEnclave(char* enclaveSignedFile);
	int __declspec(dllexport) genPair(uint64_t eid, char** public_key_struct);
    int __declspec(dllexport) storeSymKey(uint64_t eid, unsigned char* encData);
    int __declspec(dllexport) decryptPayload(uint64_t eid, unsigned char* encData, size_t encDataSz, unsigned char* mac);
	int __declspec(dllexport) destageEnclave(uint64_t eid);
#if defined(__cplusplus)
}
#endif

#endif /* !_BRIDGE_H_ */
