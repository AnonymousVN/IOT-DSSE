//
// Created by Shangqi on 11/7/22.
//

#ifndef IOTSSE_IOTSSEDBOWNER_H
#define IOTSSE_IOTSSEDBOWNER_H

#include <vector>

#include "IOTSSEServer.h"


class IOTSSEDBOwner {
//private:
public:
    // crypto keys
    uint8_t *MSK =  (unsigned char*) "0123456789123456"; //choose random in Z*_q, q = 730750862221594424981965739670091261094297337857?
    chameleon_hash_sk sk{};
    uint8_t **user_label_PRF; //F(K_uid, l_uid)

    // user parameters
    uint32_t num_users;

    // attr parameters
    uint32_t num_attr;
    string *attr_universe;
    unordered_map<string, uint8_t*> attr_key;
    unordered_map<string, uint8_t*> attr_dhtkey;
    unordered_map<string, vector<uint32_t>> attr_users;


    // inverted_index: mapping keyword to associated file identifiers
    unordered_map<string, vector<uint32_t>> inverted_index;

    // group key tree
    GroupKeyTree *tree;

    // state map
    unordered_map<string, int> ATT_ST;   //attribute_state?
    unordered_map<string, int> keyword_ST; //store the latest state of the keyword. Change the state whenever doing the client revocation on the keyword
    unordered_map<string, int> LW_ST;   //labelword_state, side information of ASHE, change when update

//public:
    // public information
    Pairing *e;
    chameleon_hash_pk pk{};

    uint32_t num_files;
    unordered_map<string, vector<string>> attr_keywords; //mapping an attribute to a list of keywords
    unordered_map<string, vector<string>> keyword_attrs; //mapping a keyword to the corresponding attributes
    vector<uint8_t*> DHT; //list of servers' addresses
    //unordered_map<string, uint8_t[4][BLOCK_SIZE]> bulletin; //store 4 keys (K_dht, K_w1, K_w2, K_w3) for keyword w
    unordered_map<string, uint8_t**> bulletin;
    unordered_map<string, mpz_t> bulletin_r;    //store the random number r_w for keyword w
    unordered_map<string, uint8_t*> bulletin_lw;
    unordered_map<uint32_t, uint8_t**> bulletin_pathkey;

    // SSE Server
    IOTSSEServer *server;



    IOTSSEDBOwner(uint32_t num_users, uint32_t num_files, const string *attr_universe, uint32_t num_attr,
                  const unordered_map<string, vector<uint32_t>> &attr_users,
                  const unordered_map<string, vector<string>> &attr_keywords,
                  const unordered_map<string, vector<string>> &keyword_attrs,
                  const unordered_map<string, vector<uint32_t>> &inverted_index);
    ~IOTSSEDBOwner();

    uint8_t * get_user_label_PRF(uint32_t uid);

    void get_user_path(uint32_t uid, vector<uint32_t>& nodes);

    void generate_encrypted_db();

    void update_db(const vector<uint32_t>& f_up, const string& keyword);

    void revoke_users(const string& keyword, const vector<uint32_t>& non_revoked_users);
};


#endif //IOTSSE_IOTSSEDBOWNER_H
