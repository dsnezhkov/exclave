#include "Util.hpp"
#include "App.hpp"

#include "httplib.h"

using namespace nlohmann;

using namespace std;


int main()
{
    HINSTANCE bridgeLib;
    initEnclave initEnclaveStub;
    genPair genPairStub;
    storeSymKey storeSymKeyStub;
    decryptPayload decryptPayloadStub;
    destageEnclave destageEnclaveStub;
    UINT64 enclaveId;

    LPCWSTR bridgeDllName = _T("Bridge.dll");
    char* enclaveSignedDllName = (char*) "Enclave2.signed.dll";
    int ret;

    bridgeLib = importEBridge(bridgeDllName);
    if (NULL == bridgeLib) {
        cout << "Unable to import bridge dll. check you path?" << endl;
        return 1;
    }

    initEnclaveStub = checkInvoke<initEnclave>(bridgeLib, (char*)"initEnclave");
    genPairStub = checkInvoke<genPair>(bridgeLib, (char*)"genPair");
    storeSymKeyStub = checkInvoke<storeSymKey>(bridgeLib, (char*)"storeSymKey");
    decryptPayloadStub = checkInvoke<decryptPayload>(bridgeLib, (char*)"decryptPayload");
    destageEnclaveStub = checkInvoke<destageEnclave>(bridgeLib, (char*)"destageEnclave");
    if (NULL == initEnclaveStub ||
        NULL == genPairStub || 
        NULL == storeSymKeyStub || 
        NULL == decryptPayloadStub || 
        NULL == destageEnclaveStub){
        cout << "Unable to find one of the critical functions. Are they exported?" << endl;
        return 2;
    }

    // Init Enclave
    enclaveId = (initEnclaveStub)(enclaveSignedDllName);
    if (enclaveId == 0) {
        cout << "Unable to create enclave" << endl;
        return 3;
    }

	cout << "New Enclave id " << enclaveId <<  endl;

    // Generate Key(pub)/Key(pri)
    char* public_key = NULL; // send a pointer, bridge will fill it out
    ret = (genPairStub)(enclaveId, &public_key);
    if (ret == 0) {
        cout << "Unable to generate key pair" << endl;
        return 3;
    }

	cout << "A: public_key: " << endl;
    DumpHex(public_key, 388);
    // The library for now stores Key(pub) in files for the server to consume.
    // Once the server encrypted Key(sym) with Key(pub), come back here to proceed
	cout << "A: b64(public_key):" << endl;

    json public_key_j;
    public_key_j["mod"] = base64_encode((unsigned char*)public_key, PUB_KEY_MOD_SIZE).c_str();
    public_key_j["exp"] = base64_encode((unsigned char*)(public_key + PUB_KEY_MOD_SIZE), PUB_KEY_EXP_SIZE).c_str();

    std::string pkj = public_key_j.dump();

    //WriteBufFile("b64.pub", public_key_j.dump().c_str(), pkj.length());

    httplib::Client cli("http://127.0.0.1:8443");
    auto res = cli.Post("/symkey", public_key_j.dump().c_str(), "application/json");
    
	if (res->status == 200) {
		cout << res->body << endl;
    }
    else {
        auto err = res.error();
		cout << err << endl;
    }

    string sym_key_response = res->body;

    cout << "http response" << endl;
    cout << sym_key_response << endl;

    cout << "J-Parsing http response" << endl;
    json symkeyPayJ = json::parse(sym_key_response);


    /*for (json::iterator it = symkeyPayJ.begin(); it != symkeyPayJ.end(); ++it) {
        std::cout << it.key() << " : " << it.value() << "\n";
    }*/


    vector<BYTE> symkeyDecoded = base64_decode(symkeyPayJ["key"]);
    unsigned char* symkeyRawEncrypted = reinterpret_cast<unsigned char*>(&symkeyDecoded[0]);

    size_t symkeyRawEncryptedSz  = symkeyPayJ["len"];
    cout << "Length of Raw Enc paylaod: " << symkeyRawEncryptedSz << endl;

    DumpHex(symkeyRawEncrypted, symkeyRawEncryptedSz);


    // Send Key(sym) to Enclave
    // It does enc/dec test
    ret = (storeSymKeyStub)(enclaveId, symkeyRawEncrypted);
    if (ret == 0) {
        cout << "Unable to store SymKey" << endl;
        return 3;
    }


    //-----------------get paylaod -----------------------------



    res = cli.Get("/payload");

    if (res->status != 200) {
        auto err = res.error();
        cout << "Unable to fetch paylaod" << err << endl;
        return 3;
    }

    string payload_response = res->body;

    cout << "http response" << endl;
    cout << payload_response << endl;

    cout << "J-Parsing http response" << endl;
    json payloadPayJ = json::parse(payload_response);


    /*for (json::iterator it = symkeyPayJ.begin(); it != symkeyPayJ.end(); ++it) {
        std::cout << it.key() << " : " << it.value() << "\n";
    }*/


    vector<BYTE> payloadDecoded = base64_decode(payloadPayJ["payload"]);
    unsigned char* payloadRawEncrypted = reinterpret_cast<unsigned char*>(&payloadDecoded[0]);

    size_t payloadRawEncryptedSz = payloadPayJ["len"];
    cout << "Length of Raw Enc payload: " << payloadRawEncryptedSz << endl;

    DumpHex(payloadRawEncrypted, payloadRawEncryptedSz);

    vector<BYTE> macDecoded = base64_decode(payloadPayJ["mac"]);
    unsigned char* macRaw = reinterpret_cast<unsigned char*>(&macDecoded[0]);
    cout << "Length of Raw MAC is 16"  << endl;
    DumpHex(macRaw, 16);


    ret = (decryptPayloadStub)(enclaveId, payloadRawEncrypted, payloadRawEncryptedSz, macRaw);
    if (ret == 0) {
        cout << "Unable to decrypt payload" << endl;
        return 3;
    }

    //cout << "Hit Enter : ";
    //cin.ignore();

    // Destroy memory resident enclave
    ret = (destageEnclaveStub)(enclaveId);
    if (ret == 0) {
        cout << "Unable to destage enclave" << endl;
        return 3;
    }

	cout << "Done!" << endl;
	FreeLibrary(bridgeLib);

    return 0;
}


template <typename T>
T checkInvoke(HINSTANCE& dllHandle, char* funcName) {

    T fn = (T)GetProcAddress(dllHandle, funcName);

    if (NULL != fn)
        return fn;
    else
        return NULL;
}

