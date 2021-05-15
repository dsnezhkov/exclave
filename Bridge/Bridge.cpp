#include "Bridge.h"
#include "Util.cpp"

// Warning	C26812 The enum type is unscoped.
#pragma warning( disable : 26812 )

using namespace std;

void ocall_print(const char* str)
{
    std::cout << str;
}

void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if (ret == sgx_errlist[idx].err) {
            if (NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

sgx_enclave_id_t createEnclave(char* encalaveSignedFile){

    sgx_launch_token_t token = { 0 };
    sgx_launch_token_t* launchToken = NULL;
    sgx_enclave_id_t eid;
    int updated = 0; // new ephemeral token

    ret = sgx_create_enclavea(encalaveSignedFile, SGX_DEBUG_FLAG, &token, &updated,
        &eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        return CANNOT_CONTINUE;
    }

    return eid;
}
/// <summary>
/// checkECapabilioty checks if this is an SGX capable platform
/// </summary>
/// <returns>
///   1 - Platform is SGX enabled or the Software Control Interface is available to configure SGX
///   0 - SGX not available
///   XX - SGX Error code
/// </returns>
extern "C" int checkECapability() {
    int sgx_capable = 0;
    ret = sgx_is_capable(&sgx_capable);
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        return CANNOT_CONTINUE;
    }
    return TRUE;
}

extern "C" int enableSGXEFI() {
    sgx_device_status_t devstatus;
    ret = sgx_cap_enable_device(&devstatus);
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        return CANNOT_CONTINUE;
    }

    switch (devstatus)
    {
    case SGX_ENABLED:
        cout << "Platform ready to use" << endl;
        return CAN_CONTINUE;

    case SGX_DISABLED_REBOOT_REQUIRED: 
        cout << "A reboot is required to finish enabling SGX" << endl;
        return CANNOT_CONTINUE;

    case SGX_DISABLED_LEGACY_OS: 
        cout << "SGX is disabled and a Software Control Interface is not available to enable it" << endl;
        return CANNOT_CONTINUE;

    case SGX_DISABLED:
        cout << "SGX is not enabled on this platform. More details are unavailable." << endl;
        return CANNOT_CONTINUE;

    case SGX_DISABLED_SCI_AVAILABLE: 
        cout << "SGX is disabled, but a Software Control Interface is available to enable it." << endl;
        return CANNOT_CONTINUE;

    case SGX_DISABLED_MANUAL_ENABLE: 
        cout << "SGX is disabled, but can be enabled manually in the BIOS setup" << endl;
        return CANNOT_CONTINUE;

    case SGX_DISABLED_HYPERV_ENABLED: 
        cout << "Detected an unsupported version of Windows* 10 with Hyper-V enabled" << endl;
        return CANNOT_CONTINUE;

    case SGX_DISABLED_UNSUPPORTED_CPU: 
        cout << "SGX is not supported by this CPU" << endl;
        return CANNOT_CONTINUE;

    default:
        cout << "SGX capabilities unknown. This should not happen" << endl;
        return CANNOT_CONTINUE;
    }
}

extern "C" uint64_t initEnclave(char* enclaveSignedFile) {
    ret = SGX_ERROR_UNEXPECTED;

    sgx_enclave_id_t eid;

    int callRet = 0;
    int check = 0;

    cout << "Checking platform capability... " << endl;
    if (checkECapability() == CANNOT_CONTINUE) {
        return CANNOT_CONTINUE;
    }

    cout << "Enabling SGX via EFI ... " << endl;
    if (enableSGXEFI() == CANNOT_CONTINUE) {
        return CANNOT_CONTINUE;
    }

    cout << "Creating SGX enclave " << endl;
    eid = createEnclave(enclaveSignedFile);
    if (eid == CANNOT_CONTINUE) {
        return CANNOT_CONTINUE;
    }
    return eid;
}
extern "C" int genPair(uint64_t eid, char** public_key_full) {

    char* public_key_struct = NULL;
    char* public_key_raw = NULL;

    public_key_struct = (char*)malloc(
        (static_cast<size_t>(SGX_RSA3072_KEY_SIZE) + SGX_RSA3072_PUB_EXP_SIZE));
    if (public_key_struct == NULL) {
        cout << "B: Error: public key malloc() failed" << endl;
        return CANNOT_CONTINUE;
    }

    public_key_raw = (char*)malloc(SGX_RSA3072_KEY_SIZE);
    if (public_key_raw == NULL) {
        cout << "B: Error: public key  (raw) malloc() failed" << endl;
        return CANNOT_CONTINUE;
    }

    cout << "B: Generating keys ... " << std::endl;
    ret = createRsaKeyPairEcall(eid, public_key_raw, public_key_struct);
    if (ret != SGX_SUCCESS)
    {
        cout << "B: Key Generation failed." << endl;
        print_error_message(ret);
        return CANNOT_CONTINUE;
    }

    cout << "B: Public key (Raw):" << std::endl;
    DumpHex(public_key_raw, SGX_RSA3072_KEY_SIZE);
    // std::cout << "B: Writing pub key" << std::endl;
    // WriteBufFile("e.pub", public_key_struct, (static_cast<size_t>(SGX_RSA3072_KEY_SIZE) + SGX_RSA3072_PUB_EXP_SIZE));

    // Allocate key(pub) return buffer
    *public_key_full = (char*)malloc(
        (static_cast<size_t>(SGX_RSA3072_KEY_SIZE) + SGX_RSA3072_PUB_EXP_SIZE));
    if (public_key_full == NULL) {
        cout << "B: Error: public key response malloc() failed" << endl;
        return CANNOT_CONTINUE;
    }

    memcpy(*public_key_full, public_key_struct, sizeof(sgx_rsa3072_public_key_t));
	cout << "B: public_key_full" << endl;
    DumpHex(*public_key_full, (static_cast<size_t>(SGX_RSA3072_KEY_SIZE) + SGX_RSA3072_PUB_EXP_SIZE));

    // TODO: check more
    /*if (sizeof(public_key_full) != sizeof(sgx_rsa3072_key_t)) {
        cout << "B: Error: public key response copy failed" << endl;
        return CANNOT_CONTINUE;
    }*/

    /* sgx_rsa3072_public_key_t* public_key_struct = (sgx_rsa3072_public_key_t*)malloc(sizeof(sgx_rsa3072_public_key_t));
    if (public_key_struct != NULL) {
        memcpy(public_key_struct, public_key, sizeof(sgx_rsa3072_public_key_t));
        buf2hex(public_key_struct->exp, SGX_RSA3072_PUB_EXP_SIZE);
        buf2hex(public_key_struct->mod, SGX_RSA3072_KEY_SIZE);
    }
    */

    return CAN_CONTINUE;
}
    
extern "C" int storeSymKey(uint64_t eid, unsigned char* encData) {

    if (NULL == encData) {
        cout << "Enc data is null" << endl;
        return CANNOT_CONTINUE;
    }
    // DumpHex(encData, SGX_RSA3072_KEY_SIZE);

    size_t len = (size_t)SGX_RSA3072_KEY_SIZE;
    ret = storeSymKeyEcall(eid, encData, len);
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        return CANNOT_CONTINUE;
    }
	return CAN_CONTINUE;
}

extern "C" int decryptPayload(uint64_t eid, unsigned char* encData, size_t encDataLen, unsigned char* mac) {

    if (NULL == encData || NULL == mac) {
        cout << "Enc data or MAC are null" << endl;
        return CANNOT_CONTINUE;
    }
    cout << "B: Data:" << endl;
    DumpHex(encData, encDataLen);

    cout << "B: MAC:" << endl;
    DumpHex(mac, 16);

    ret = decryptPayloadEcall(eid, encData, encDataLen, mac);
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        return CANNOT_CONTINUE;
    }

    return CAN_CONTINUE;
}


extern "C" int destageEnclave(uint64_t eid) {
    ret = SGX_ERROR_UNEXPECTED;

    ret = sgx_destroy_enclave(eid);
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        return CANNOT_CONTINUE;
    }
    return CAN_CONTINUE;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

