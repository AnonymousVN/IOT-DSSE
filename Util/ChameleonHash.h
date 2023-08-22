//
// Created by Shangqi on 4/7/22.
//

#ifndef IOTSSE_CHAMELEONHASH_H
#define IOTSSE_CHAMELEONHASH_H

#include <gmpxx.h>
#include <PBC.h>

using namespace std;

struct chameleon_hash_pk {
    mpz_t p;
    mpz_t q;
    mpz_t g;
    mpz_t y;
};

struct chameleon_hash_sk {
    mpz_t xi;
};

pair<chameleon_hash_pk, chameleon_hash_sk> keygen();

void chameleon_hash(chameleon_hash_pk pk, mpz_t x, mpz_t r, mpz_t &digest);

void forge(chameleon_hash_pk pk, chameleon_hash_sk sk, mpz_t origin_msg, mpz_t r, mpz_t new_msg,  mpz_t &new_r);

void destroy_keys(chameleon_hash_pk pk, chameleon_hash_sk sk);

#endif //IOTSSE_CHAMELEONHASH_H
