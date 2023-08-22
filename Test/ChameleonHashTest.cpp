//
// Created by Shangqi on 4/7/22.
//

#include "ChameleonHash.h"

int main() {
    auto [pk, sk] = keygen();
    mpz_t x;
    mpz_init_set_str(x, "5465465465", 10);
    gmp_printf ("%s is %Zd\n", "x'", x);
    // choose a r
    gmp_randstate_t state;
    gmp_randinit_mt (state);
    mpz_t r;
    mpz_init(r);
    mpz_urandomm(r, state, pk.q);
    // compute the hash of x
    mpz_t digest;
    mpz_init(digest);
    chameleon_hash(pk, x, r, digest);
    gmp_printf ("%s is %Zd\n", "r", r);
    gmp_printf ("%s is %Zd\n", "hash digest", digest);
    // forge a new r for x'
    mpz_t x_prime;
    mpz_init_set_str(x_prime, "178234578000", 10);
    gmp_printf ("%s is %Zd\n", "x'", x_prime);
    mpz_t new_r;
    mpz_init(new_r);
    forge(pk, sk, x, r, x_prime, new_r);
    // compute new digest with new r
    mpz_t digest_prime;
    mpz_init(digest_prime);
    chameleon_hash(pk, x_prime, new_r, digest_prime);
    gmp_printf ("%s is %Zd\n", "new r", new_r);
    gmp_printf ("%s is %Zd\n", "hash digest", digest_prime);
}