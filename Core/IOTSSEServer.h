//
// Created by Shangqi on 15/8/22.
//

#ifndef IOTSSE_IOTSSESERVER_H
#define IOTSSE_IOTSSESERVER_H

#include <unordered_map>

#include <cstdint>
#include "ChameleonHash.h"
#include "GroupKeyTree.h"
class IOTSSEServer {
//private:
public:
    unordered_map<string, pair<string, vector<bool>>> EDB;
    chameleon_hash_pk pk;

//public:
    IOTSSEServer(chameleon_hash_pk pk);
    void get_db(const unordered_map<string, pair<string, vector<bool>>>& D_W);
    void get_updated_db(const mpz_t& add_keyword, const vector<bool> e_w_up, const int size);
    void get_updated_revokedusers(const mpz_t& add_keyword, const mpz_t& r_up);
    vector<bool> search(mpz_t trapdoor_1, mpz_t trapdoor_2);
};


#endif //IOTSSE_IOTSSESERVER_H
