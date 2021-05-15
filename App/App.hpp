#pragma once
#ifndef _APP_H_
#define _APP_H_


#include "httplib.h"
#include <tchar.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>

#include "json.hpp"
#include "base64.h"
#include "obfuscate.h"


#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

#define PUB_KEY_MOD_SIZE 384
#define PUB_KEY_EXP_SIZE 4
#define PUB_KEY_STRUCT_SIZE (PUB_KEY_MOD_SIZE + PUB_KEY_EXP_SIZE)

template <typename T>
T checkInvoke(HINSTANCE& dllHandle, char* funcName);

typedef UINT64(__cdecl* initEnclave)(char* enclaveSignedFile);
typedef int(__cdecl* genPair)(UINT64 eid, char** public_key_struct);
typedef int(__cdecl* storeSymKey)(UINT64 eid, unsigned char* encData);
typedef int(__cdecl* decryptPayload)(UINT64 eid, unsigned char* encData, size_t encDataSz, unsigned char* mac);
typedef int(__cdecl* destageEnclave)(UINT64 eid);


#endif /* !_ENCLAVE2_H_ */
