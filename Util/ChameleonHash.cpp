//
// Created by Shangqi on 11/7/22.
//

#include "ChameleonHash.h"

pair<chameleon_hash_pk, chameleon_hash_sk> keygen() {
    mpz_t p, q;
    // set p as a prime number 730750862221594424981965739670091261094297337857 = r in pairing.param
    mpz_init_set_str(q, "730750862221594424981965739670091261094297337857", 10); //parse the input string as a base 10 number
    mpz_init(p);
    int k = 0;
    // find prime p = kq + 1
    while(!mpz_probab_prime_p(p, 20)) {
        k++;
        mpz_mul_ui(p, q, k);
        mpz_add_ui(p, p, 1);
    }
    // compute g ((random_num in p)^k mod p)
    gmp_randstate_t state;
    gmp_randinit_mt (state);
    mpz_t a, g;
    mpz_inits(a, g, nullptr);
    mpz_urandomm(a, state, p); // a <--R Zp
    mpz_powm_ui(g, a, k, p); // g = a^k mod p ? how to prove g is of order q
    // randomly select secret key from Zq
    mpz_t xi, y;
    mpz_inits(xi, y, nullptr);
    mpz_urandomm(xi, state, q); // xi <--R Zq
    mpz_powm(y, g, xi, p);  // y = g^xi mod p
    // initialise two keys and assign values
    chameleon_hash_pk pk{};
    mpz_set(pk.p, p);
    mpz_set(pk.q, q);
    mpz_set(pk.g, g);
    mpz_set(pk.y, y);
    chameleon_hash_sk sk{};
    mpz_set(sk.xi, xi);
    // clear up
    mpz_clears(p, q, a, g, xi, y, nullptr);
    return make_pair(pk, sk);
}

void chameleon_hash(chameleon_hash_pk pk, mpz_t x, mpz_t r, mpz_t &digest) {
    mpz_t a, b, c;
    mpz_inits(a, b, c, nullptr);
    // compute g^x*y^r mod p
    mpz_powm(a, pk.g, x, pk.p);
    mpz_powm(b, pk.y, r, pk.p);
    mpz_mul(c, a, b);
    mpz_fdiv_r(digest, c, pk.p);
    // clear up
    mpz_clears(a, b, c, nullptr);
}

void forge(chameleon_hash_pk pk, chameleon_hash_sk sk, mpz_t origin_msg, mpz_t r, mpz_t new_msg,  mpz_t &new_r) {
    mpz_t diff, inverse, tmp;
    mpz_inits(diff, inverse, tmp, nullptr);
    // compute x - x'
    mpz_sub(diff, origin_msg, new_msg);
    // find the inverse of xi
    mpz_invert(inverse, sk.xi, pk.q);
    // compute ((x - x') * xi^-1) + r mod q
    mpz_mul(tmp, diff, inverse);
    mpz_add(tmp, tmp, r);
    mpz_fdiv_r(new_r, tmp, pk.q);
    // clear up
    mpz_clears(diff, inverse, tmp, nullptr);
}

void destroy_keys(chameleon_hash_pk pk, chameleon_hash_sk sk) {
    mpz_clears(pk.p, pk.q, pk.g, pk.y, sk.xi, nullptr);
}