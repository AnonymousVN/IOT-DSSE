//
// Created by Shangqi on 12/6/22.
//

#include "CommonUtils.h"
#include "bitset"

size_t aes_cmac(const unsigned char *message, size_t message_size,
                const unsigned char *key,
                unsigned char *output) {
    size_t length;

    CMAC_CTX *ctx = CMAC_CTX_new();
    CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), nullptr);
    CMAC_Update(ctx, message, message_size);
    CMAC_Final(ctx, output, &length);
    CMAC_CTX_free(ctx);

    return length;
}


int enc_aes_cbc(const unsigned char *plaintext, size_t plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;

    int len = 0;

    int ciphertext_len;

    /* Create and initialise the context */
    ctx = EVP_CIPHER_CTX_new();

    /* Initialise the encryption operation. */
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, nullptr, nullptr);

    /* Initialise key and IV */
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;

    /* Finalise the encryption */
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int dec_aes_cbc(const unsigned char *ciphertext, size_t ciphertext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int plaintext_len;

    /* Create and initialise the context */
    ctx = EVP_CIPHER_CTX_new();

    /* Initialise the decryption operation. */
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, nullptr, nullptr);

    /* Initialise key and IV */
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv);

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);

    plaintext_len = len;

    /* Finalise the decryption. */
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    plaintext_len += len;

    return plaintext_len;
}

//int enc_ashe(const unsigned char *plaintext, size_t plaintext_len,
//             const unsigned char *key, const uint8_t* label, const int state, unsigned char *ciphertext){
//    uint8_t * label1 = new uint8_t [plaintext_len];
//    uint8_t * label2 = new uint8_t [plaintext_len];
//    for(int i = 0; i < plaintext_len; i++){
//        label1[i] = label[i] + state;
//        label2[i] = label1[i] + 1;
//    }
//
////    cout << "Label 1, 2 in enc: " << endl;
////    print_chararray(label1, plaintext_len);
////    print_chararray(label2, plaintext_len);
//
//    uint8_t *prf1, *prf2;
//    prf1 = new uint8_t[(plaintext_len / BLOCK_SIZE + 2) * BLOCK_SIZE];
//    prf2 = new uint8_t[(plaintext_len / BLOCK_SIZE + 2) * BLOCK_SIZE];
//    aes_cmac(label1, plaintext_len, key, prf1);
//    aes_cmac(label2, plaintext_len, key, prf2);
//    //RAND_bytes(prf1, BLOCK_SIZE); //create random iv
//    //RAND_bytes(prf2, BLOCK_SIZE);
//    enc_aes_cbc(label1, plaintext_len,
//                key, prf1, prf1 + BLOCK_SIZE);
//    enc_aes_cbc(label2, plaintext_len,
//                key, prf2, prf2 + BLOCK_SIZE);
//
////    cout << "prf 1, 2 in enc: " << endl;
////    print_chararray(prf1, plaintext_len);
////    print_chararray(prf2, plaintext_len);
//
//    for (int i = 0; i < plaintext_len; i++)
//        ciphertext[i] = plaintext[i] ^ prf1[i] ^ prf2[i];
//}
//
//int dec_ashe(const unsigned char *ciphertext, const size_t ciphertext_len,
//             const unsigned char *key, const unsigned char* label1, const int state, unsigned char *plaintext){
//    unsigned char* label2 = new uint8_t [ciphertext_len];
//    for(int i = 0; i < ciphertext_len; i++)
//        label2[i] = label1[i] + state;
//
////    cout << "Label 1, 2 in dec: " << endl;
////    print_chararray(label1, ciphertext_len);
////    print_chararray(label2, ciphertext_len);
//
//    uint8_t *prf1, *prf2;
//    prf1 = new uint8_t[(ciphertext_len / BLOCK_SIZE + 2) * BLOCK_SIZE];
//    prf2 = new uint8_t[(ciphertext_len / BLOCK_SIZE + 2) * BLOCK_SIZE];
//    aes_cmac(label1, ciphertext_len, key, prf1);
//    aes_cmac(label2, ciphertext_len, key, prf2);
//    //RAND_bytes(prf1, BLOCK_SIZE);
//    //RAND_bytes(prf2, BLOCK_SIZE);
//    enc_aes_cbc(label1, ciphertext_len,
//                key, prf1, prf1 + BLOCK_SIZE);
//    enc_aes_cbc(label2, ciphertext_len,
//                key, prf2, prf2 + BLOCK_SIZE);
//
////    cout << "prf 1, 2 in dec: " << endl;
////    print_chararray(prf1, ciphertext_len);
////    print_chararray(prf2, ciphertext_len);
//
//    for (int i = 0; i < ciphertext_len; i++)
//        plaintext[i] = ciphertext[i] ^ prf1[i] ^ prf2[i];
//}


size_t aes_cmac_nwise(const unsigned char *message, size_t message_size,
                      const unsigned char *key, size_t times,
                      unsigned char *output){
    uint8_t cmac[BLOCK_SIZE];
    uint8_t tmp[message_size];
    for (int i = 0; i < message_size; i++)
        tmp[i] = message[i];
    for (int i = 0; i < times; i++) {
        if (i != 0)
            for (int j = 0; j < message_size; j++){
                tmp[j] = tmp[j] + 1;
            }
        aes_cmac(tmp, message_size, key, cmac);
        memcpy(output + BLOCK_SIZE * i, cmac, BLOCK_SIZE);
    }
}

void enc_ashe(const vector<bool> plaintext, const int plaintext_len_bits,
              const uint8_t *key, const uint8_t* label, const int label_size, const int state, vector<bool>& ciphertext){

    int num_cmac = plaintext_len_bits/(BLOCK_SIZE * 8) + 1;
    uint8_t *label1 = new uint8_t [label_size];
    uint8_t *label2 = new uint8_t [label_size];
    for(int i = 0; i < label_size; i++){
        label1[i] = label[i] + state;
        label2[i] = label1[i] + 1;
    }

//    cout << "label1: ";
//    print_chararray(label1, label_size);
//    cout << "label2: ";
//    print_chararray(label2, label_size);

    uint8_t *prf1 = new uint8_t[num_cmac * BLOCK_SIZE];
    uint8_t *prf2 = new uint8_t[num_cmac * BLOCK_SIZE];
    aes_cmac_nwise(label1, label_size, key, num_cmac, prf1);
    aes_cmac_nwise(label2, label_size, key, num_cmac, prf2);

//    cout << "prf1: ";
//    print_chararray(prf1, num_cmac*BLOCK_SIZE);
//    cout << "prf2: ";
//    print_chararray(prf2, num_cmac*BLOCK_SIZE);

    int j = 0;
    for (int i = 0; i < num_cmac * BLOCK_SIZE; i++){
        bitset<8> bin1(prf1[i]);
        bitset<8> bin2(prf2[i]);
        for (int k = 0; k < 8; k++) {
            ciphertext[j] = XOR(plaintext[j], XOR(bin1.test(k), bin2.test(k)));
            j++;
            if (j == plaintext_len_bits){
                delete label1;
                delete label2;
                delete prf1;
                delete prf2;
                return;
            }
        }
    }

}

void dec_ashe(const vector<bool> ciphertext, const int ciphertext_len_bits,
              const uint8_t *key, const uint8_t* label1, const int label1_size, const int state, vector<bool>& plaintext){
    int num_cmac = ciphertext_len_bits/(BLOCK_SIZE * 8) + 1;
    uint8_t *label2 = new uint8_t[label1_size];
    for(int i = 0; i < label1_size; i++)
        label2[i] = label1[i] + state;

//    cout << "label1: ";
//    print_chararray(label1, label1_size);
//    cout << "label2: ";
//    print_chararray(label2, label1_size);


    uint8_t *prf1 = new uint8_t[num_cmac * BLOCK_SIZE];
    uint8_t *prf2 = new uint8_t[num_cmac * BLOCK_SIZE];
    aes_cmac_nwise(label1, label1_size, key, num_cmac, prf1);
    aes_cmac_nwise(label2, label1_size, key, num_cmac, prf2);

//    cout << "prf1: ";
//    print_chararray(prf1, num_cmac*BLOCK_SIZE);
//    cout << "prf2: ";
//    print_chararray(prf2, num_cmac*BLOCK_SIZE);

    int j = 0;
//    cout << num_cmac << endl;
//    cout << num_cmac * BLOCK_SIZE << endl;
//    cout << ciphertext_len_bits << endl;
    for (int i = 0; i < num_cmac * BLOCK_SIZE; i++){
        bitset<8> bin1(prf1[i]);
        bitset<8> bin2(prf2[i]);
        for (int k = 0; k < 8; k++) {
            plaintext[j] = XOR(ciphertext[j], XOR(bin1.test(k), bin2.test(k)));
            j++;
            if (j == ciphertext_len_bits){
//                delete label2;
//                delete prf1;
//                delete prf2;
                return;
            }
        }
    }
}

void print_chararray(const uint8_t *a, int size){
    for(int i = 0; i < size; i++)
        cout << (int)a[i] << " ";
    cout << endl;
}


void print_vector(const vector<uint32_t>& v){
    for (uint32_t i: v)
        cout << i << " ";
    cout << endl;
}

void print_vector(const vector<bool>& v){
    for (bool i: v)
        if (i)
            cout << 1 << " ";
        else
            cout << 0 << " ";
    cout << endl;
}

void print_vector(const vector<double>& v){
    for (double i: v)
        cout << i << " ";
    cout << endl;
}

bool XOR(bool a, bool b)
{
    return (a + b) % 2;
}