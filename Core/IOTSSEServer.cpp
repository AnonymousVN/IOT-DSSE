//
// Created by Shangqi on 15/8/22.
//

#include "IOTSSEServer.h"


#include <bitset>
#include <utility>
#include "IOTSSEDBOwner.h"

IOTSSEServer::IOTSSEServer(chameleon_hash_pk pk) {
    this->EDB.clear();
    this->pk = pk;
}

void IOTSSEServer::get_db(const unordered_map<string, pair<string, vector<bool>>>& D_W) {
    this->EDB = D_W;
}

vector<bool> IOTSSEServer::search(mpz_t trapdoor_1, mpz_t trapdoor_2) {
    // get r from server
    string index = mpz_get_str(nullptr, 10, trapdoor_1);
    mpz_t r, digest;
    mpz_init(r);
    mpz_set_str(r, this->EDB[index].first.c_str(), 10);
    mpz_init(digest);
    chameleon_hash(this->pk, trapdoor_2, r, digest);
    vector<bool> res;
    if(mpz_cmp(digest, trapdoor_1) == 0) {
        res = this->EDB[index].second;
    }
    return res;
}

void IOTSSEServer::get_updated_db(const mpz_t& add_keyword, const vector<bool> e_w_up, const int size){
    pair<string, vector<bool>> p = this->EDB[mpz_get_str(nullptr, 10, add_keyword)];
    //HE
    vector<bool> e_w(size);
    if (p.second.size() == size) {
        for (int i = 0; i < size; i++) {
            e_w[i] = p.second[i] ^ e_w_up[i];
        }
    }
    else {
        //cout << "p.second.size() = 0" << endl;
        for (int i = 0; i < size; i++) {
            e_w[i] = e_w_up[i];
        }
    }

    //cout << "size: " << size << endl;
    this->EDB[mpz_get_str(nullptr, 10, add_keyword)] = make_pair(p.first, e_w);
}

void IOTSSEServer::get_updated_revokedusers(const mpz_t& add_keyword, const mpz_t& r_up){
    pair<string, vector<bool>> p = this->EDB[mpz_get_str(nullptr, 10, add_keyword)];
    this->EDB[mpz_get_str(nullptr, 10, add_keyword)] = make_pair(mpz_get_str(nullptr, 10, r_up), p.second);
}