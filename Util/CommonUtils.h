//
// Created by Shangqi on 12/6/22.
//

#ifndef IOTSSE_COMMONUTILS_H
#define IOTSSE_COMMONUTILS_H

#include "iostream"
#include <cstring>
#include <string>
#include <vector>
#include <openssl/cmac.h>
#include <openssl/rand.h>

#define BLOCK_SIZE 16
using namespace std;
size_t aes_cmac(const unsigned char *message, size_t message_size,
              const unsigned char *key,
              unsigned char *output);

size_t aes_cmac_nwise(const unsigned char *message, size_t message_size,
                const unsigned char *key, size_t times,
                unsigned char *output);

int enc_aes_cbc(const unsigned char *plaintext, size_t plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *ciphertext);

int dec_aes_cbc(const unsigned char *ciphertext, size_t ciphertext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *plaintext);

void enc_ashe(const vector<bool> plaintext, const int plaintext_len_bits,
              const uint8_t *key, const uint8_t* label, const int label_size, const int state, vector<bool>& ciphertext);

void dec_ashe(const vector<bool> ciphertext, const int ciphertext_len_bits,
              const uint8_t *key, const uint8_t* label1, const int label_size, const int state, vector<bool>& plaintext);

void print_chararray(const uint8_t *a, int size);

void print_vector(const vector<uint32_t>& v);

void print_vector(const vector<bool>& v);

void print_vector(const vector<double>& v);

bool XOR(bool a, bool b);

#endif //IOTSSE_COMMONUTILS_H
