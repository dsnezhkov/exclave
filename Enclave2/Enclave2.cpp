#include "sgx_trts.h"

#include <stdarg.h>
#include <stdio.h>    
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "Enclave2.h"
#include "Enclave2_t.h" 


// Warning	C26812 The enum type is unscoped.
#pragma warning( disable : 26812 )

void* private_key_raw = NULL; // Asymmetric Key(pri)
void* public_key_raw = NULL;  // Asymmetric Key(pub)
char* sym_shared_key = NULL;  // Symmetric Key

void eprintf(const char* fmt, ...)
{
    const short BSZ = 256;
    char buf[BSZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BSZ, fmt, ap);
    va_end(ap);
    ocall_print(buf);
}
int ecall_do_trusted_inside_ocall(void) {
    return TRUE;
}
int ecall_do_trusted(int check)
{
    if (check)
        return TRUE;
    else
        return FALSE;
}
void DumpHex(const void* data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        eprintf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        }
        else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            eprintf(" ");
            if ((i + 1) % 16 == 0) {
                eprintf("|  %s \n", ascii);
            }
            else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    eprintf(" ");
                }
                for (j = (i + 1) % 16; j < 16; ++j) {
                    eprintf("   ");
                }
                eprintf("|  %s \n", ascii);
            }
        }
    }
}
void createRsaKeyPairEcall(char* public_key_raw_out, char* public_key_out) {

    /* Public key is allocated  with 
     *  uint8_t mod[SGX_RSA3072_KEY_SIZE];
	 *  uint8_t exp[SGX_RSA3072_PUB_EXP_SIZE];
     */
    sgx_rsa3072_key_t* private_key = (sgx_rsa3072_key_t*)malloc(sizeof(sgx_rsa3072_key_t));
    sgx_rsa3072_public_key_t* public_key = (sgx_rsa3072_public_key_t*)malloc(sizeof(sgx_rsa3072_public_key_t));


    sgx_status_t status =  createRsaKeyPair(public_key, private_key, &public_key_raw, &private_key_raw);

    memcpy(public_key_raw_out, public_key_raw, SGX_RSA3072_KEY_SIZE);
    memcpy(public_key_out, public_key, sizeof(sgx_rsa3072_public_key_t));

    eprintf("E: Private key raw (gen):\n");
    DumpHex(private_key_raw, SGX_RSA3072_KEY_SIZE);

    eprintf("E: Public key raw (gen):\n");
    DumpHex(public_key_raw, SGX_RSA3072_KEY_SIZE);

}


sgx_status_t createRsaKeyPair(
        sgx_rsa3072_public_key_t* public_key, sgx_rsa3072_key_t* private_key, void** public_key_raw, void** private_key_raw) {

    int e_byte_size = SGX_RSA3072_PUB_EXP_SIZE;
    int n_byte_size = SGX_RSA3072_KEY_SIZE;
    unsigned char* p_n = (unsigned char*)malloc(SGX_RSA3072_KEY_SIZE);
    unsigned char* p_d = (unsigned char*)malloc(SGX_RSA3072_PRI_EXP_SIZE);
    unsigned char  p_e[] = { 0x01, 0x00, 0x01, 0x00 }; //65537 - a common exp
    unsigned char* p_p = (unsigned char*)malloc(SGX_RSA3072_KEY_SIZE);
    unsigned char* p_q = (unsigned char*)malloc(SGX_RSA3072_KEY_SIZE);
    unsigned char* p_dmp1 = (unsigned char*)malloc(SGX_RSA3072_KEY_SIZE);
    unsigned char* p_dmq1 = (unsigned char*)malloc(SGX_RSA3072_KEY_SIZE);
    unsigned char* p_iqmp = (unsigned char*)malloc(SGX_RSA3072_KEY_SIZE);


    sgx_status_t status = SGX_ERROR_UNEXPECTED;
    status = sgx_create_rsa_key_pair(
        n_byte_size,
        e_byte_size,
        p_n,
        p_d,
        p_e,
        p_p,
        p_q,
        p_dmp1,
        p_dmq1,
        p_iqmp
    );
    if (status != SGX_SUCCESS) {
        ocall_print("Rsa Key Pair creation error!\n");
        return status;
    }
    else {
        ocall_print("RSA Generated Succesfully!\n");
    }

    // Populate Key(priv) struct
    memcpy(private_key->mod, p_n, n_byte_size);
    memcpy(private_key->d, p_d, n_byte_size);
    memcpy(private_key->e, p_e, e_byte_size);

    // Populate Key(pub) struct
    memcpy(public_key->mod, p_n, n_byte_size);
    memcpy(public_key->exp, p_e, e_byte_size);

    // Create Key(pub)
    status = sgx_create_rsa_pub1_key(
        SGX_RSA3072_KEY_SIZE,
        SGX_RSA3072_PUB_EXP_SIZE,
        (const unsigned char*)public_key->mod,
        (const unsigned char*)public_key->exp,
        public_key_raw);
    if (status != SGX_SUCCESS) {
        ocall_print("Error in creating void** rsapubkey!\n");
        if (status == SGX_ERROR_INVALID_PARAMETER) {
            ocall_print("Invalid parameters\n");
            return status;
        }
        if (status == SGX_ERROR_UNEXPECTED) {
            ocall_print("Unexpected error\n");
			return status;
        }
    }
    else {
        ocall_print("Key(pub) created.\n");
    }

    // Create Key(pri)
    status = sgx_create_rsa_priv2_key(
        SGX_RSA3072_KEY_SIZE,
        SGX_RSA3072_PUB_EXP_SIZE,
        p_e,
        p_p,
        p_q,
        p_dmp1,
        p_dmq1,
        p_iqmp,
        private_key_raw);
    if (status != SGX_SUCCESS) {
        ocall_print("Error in creating void** rsaprivkey!\n");
        if (status == SGX_ERROR_INVALID_PARAMETER) {
            ocall_print("Invalid parameters\n");
            return status;
        }
        if (status == SGX_ERROR_UNEXPECTED) {
            ocall_print("Unexpected error\n");
            return status;
        }
    }
    else {
        ocall_print("Key(pri) created.\n");
    }


    if (NULL != p_dmp1 ||
        NULL != p_dmq1 ||
        NULL != p_iqmp ||
        NULL != p_n ||
        NULL != p_d ||
        NULL != p_p ||
        NULL != p_q 
        ) {
	free(p_dmp1);
	free(p_dmq1);
	free(p_iqmp);
    free(p_n);
    free(p_d);
    free(p_p);
    free(p_q);
    }

    return SGX_SUCCESS;
}

void decryptPayloadGetSizeEcall(unsigned char* encryptedData, size_t encryptedDataSize, size_t* decrypted_data_size) {

    // eprintf("Enc dat size:");
    // DumpHex((char *) encryptedDataSize, 1);
    size_t* dec_d_s = 0;

    sgx_status_t status = sgx_rsa_priv_decrypt_sha256(
        private_key_raw, 
        NULL, 
        dec_d_s,
        //decrypted_data_size, 
        encryptedData, 
        encryptedDataSize);
    if (status != SGX_SUCCESS) {
        eprintf("%s %d", "Determination of output length failed\n", status);
        return;
    }
}

void storeSymKeyEcall(unsigned char* encryptedData, size_t encryptedDataSize) {

    unsigned char* decryptedMessage = storeSymKey(encryptedData, encryptedDataSize);
    if (decryptedMessage != NULL) {
        sym_shared_key = (char*) malloc(sym_shared_key_size);
		memcpy(sym_shared_key, decryptedMessage, sym_shared_key_size);
		eprintf("%s\n", sym_shared_key);
        DumpHex(decryptedMessage, sym_shared_key_size);
    }
}

unsigned char* storeSymKey(unsigned char* encryptedData, size_t encryptedDataSize) {

    sgx_status_t status;
    size_t decrypted_data_length = 384;
    size_t decrypted_data_real_sz;

    eprintf("e: Encrypted data:\n");
    DumpHex(encryptedData, encryptedDataSize);
    //eprintf("e: Private key:");
    // DumpHex(private_key_raw, SGX_RSA3072_KEY_SIZE);

    unsigned char* decrypted_data = (unsigned char*)malloc(decrypted_data_length);

    status = sgx_rsa_priv_decrypt_sha256(
        private_key_raw,
        (unsigned char*)decrypted_data,
        &decrypted_data_length,
        (unsigned char*)encryptedData,
        encryptedDataSize);

    if (status != SGX_SUCCESS) {
        eprintf("Error in decrypting using private key! ");
        eprintf("status: %d\n", status);
        return NULL;
    }
    else {
        eprintf("Decrypted!\n");
        // check size
        decrypted_data_real_sz = strlen((char*)decrypted_data);
        DumpHex(decrypted_data, decrypted_data_real_sz);

        if (decrypted_data_real_sz != sym_shared_key_size) {
            eprintf("Size of decrypted symkey is != 16 : %d\n", decrypted_data_real_sz);
            return NULL;
        }
    }
    return decrypted_data;
}

void decryptPayloadEcall(unsigned char* encryptedData, size_t encryptedDataSize, unsigned char* mac) {

    eprintf("%s\n", "E: Data");
	DumpHex(encryptedData, encryptedDataSize);
    eprintf("%s\n", "E: MAC");
	DumpHex(mac, 16);
    unsigned char* decryptedPayload = decryptPayload(encryptedData, encryptedDataSize, mac);
    if (decryptedPayload != NULL) {
        DumpHex(decryptedPayload, encryptedDataSize);
    }
}

unsigned char* decryptPayload(unsigned char* encryptedData, size_t encryptedDataSize, unsigned char* mac){
      sgx_status_t		ret = SGX_SUCCESS;
      sgx_aes_gcm_128bit_tag_t* mac2 = (sgx_aes_gcm_128bit_tag_t*) mac;
      uint8_t iv[12] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C
      };

	 // eprintf("IV: %02x\n", iv);
	 // eprintf("--- %s --- \n", "Encrypting");
  //    // Gen IV
  //    /*
  //    sgx_read_rand(reinterpret_cast<unsigned char*>(&iv),
  //        sizeof(iv));
  //    eprintf("E: iv: %02x \n", iv);
  //    */


  //    // KEY
  //    const sgx_aes_gcm_128bit_key_t* p_key = (const sgx_aes_gcm_128bit_key_t*) sym_shared_key;

  //    // Payload
  //    const char* message = "This ia a long string to encrypt. Some of it will be very very very long!!!!";
  //    const uint8_t* p_src = (const uint8_t*)message;
  //    size_t src_message_sz = strlen(message);

  //    size_t dst_message_sz = src_message_sz + SGX_AESGCM_KEY_SIZE + SGX_AESGCM_IV_SIZE;

  //    // Destination
	 // eprintf("enc IV: %02x\n", iv);
  //    eprintf("src_message_sz: %d\n", src_message_sz);
  //    //eprintf("Allocating dst_message_sz %d\n", (dst_message_sz * sizeof(uint8_t)) );
  //    //uint8_t* p_dst = (uint8_t*)malloc(dst_message_sz * sizeof(uint8_t));
  //    eprintf("Allocating dst_message_sz %d\n", dst_message_sz );
  //    uint8_t* p_dst = (uint8_t*)malloc(dst_message_sz);

  //    //ENCRYPTION
  //    ret = sgx_rijndael128GCM_encrypt(
  //        p_key, 
  //        p_src, 
  //        (uint32_t) src_message_sz, 
  //        p_dst,
  //        iv, 
  //        SGX_AESGCM_IV_SIZE,
  //        NULL, 
  //        0, 
  //        &mac
  //    );


	 // if (ret != SGX_SUCCESS) {
		//eprintf("ret: %d\n", ret); 
  //      if (ret == SGX_ERROR_INVALID_PARAMETER) {
  //          eprintf("%s\n", "SGX_ERROR_INVALID_PARAMETER");
  //      }
  //      if (ret == SGX_ERROR_UNEXPECTED) {
  //          eprintf("%s\n", "SGX_ERROR_UNEXPECTED");
  //      }
	 // }
	 // else {
  //        // Teminate with \0 so we can strlen
  //        // *(p_dst + dst_message_sz) = '\0';
		//  eprintf("enc: %s\n", p_dst);
  //        DumpHex(p_dst, dst_message_sz);

		//  eprintf("%s\n", "computed mac");
  //        DumpHex((void*) mac, SGX_AESGCM_MAC_SIZE);
	 // }


	  eprintf("--- %s --- \n", "Decrypting");
      const sgx_aes_gcm_128bit_key_t* p_key = (const sgx_aes_gcm_128bit_key_t*)sym_shared_key;
      uint8_t* dec_message = (uint8_t*)malloc(encryptedDataSize);

      size_t cypertext_len = encryptedDataSize - (SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE);

      //DECRYPTION
	  eprintf("Encrypted buffer (p_dst) : %d\n", encryptedDataSize);
      DumpHex(encryptedData, encryptedDataSize);

      ret = sgx_rijndael128GCM_decrypt(
          p_key,
          encryptedData, 
          (uint32_t)encryptedDataSize,
          dec_message,
          iv,
          SGX_AESGCM_IV_SIZE,
          NULL,
          0,
          mac2
      );

      if (ret != SGX_SUCCESS) {
          eprintf("ret: %d\n", ret);
          if (ret == SGX_ERROR_INVALID_PARAMETER) {
            eprintf("%s\n", "SGX_ERROR_INVALID_PARAMETER");
          }
          if (ret == SGX_ERROR_UNEXPECTED) {
            eprintf("%s\n", "SGX_ERROR_UNEXPECTED");
          }
          if (ret == SGX_ERROR_MAC_MISMATCH) {
            eprintf("%s\n", "SGX_ERROR_MAC_MISMATCH ");
          }
      }
      else {
          // Teminate with \0 so we can strlen
          eprintf("dec: %s\n", dec_message);
          DumpHex(dec_message, encryptedDataSize);
      }

      return dec_message;
  }
