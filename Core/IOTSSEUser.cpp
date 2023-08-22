//
// Created by Hong Yen Tran on 19/11/22.
//

#include <bitset>
#include <utility>
#include "IOTSSEUser.h"
#include <chrono>

using namespace std;

IOTSSEUser::IOTSSEUser(uint32_t uid, IOTSSEDBOwner* dbowner){
    this->uid = uid;
    this->dbowner = dbowner;
    this->get_nodes_keys();
}

IOTSSEUser::~IOTSSEUser() {
}

void IOTSSEUser::get_nodes_keys(){
    uint8_t * label_PRF = this->dbowner->get_user_label_PRF(this->uid);
    vector<uint32_t> idx_nodes;
    this->dbowner->get_user_path(this->uid, idx_nodes); // get user's nodes in order ...
    // xor the path's keys with the label_PRF of the user
    for (uint32_t i=0; i < idx_nodes.size(); i++) {
        this->u_node_key[idx_nodes[i]] = new uint8_t[BLOCK_SIZE];
        memcpy(this->u_node_key[idx_nodes[i]], this->dbowner->bulletin_pathkey[uid][i], BLOCK_SIZE);
        for (int j = 0; j < BLOCK_SIZE; j++) {
            this->u_node_key[idx_nodes[i]][j] ^= label_PRF[j];
        }

    }

}

void IOTSSEUser::query(const string& keyword, vector<uint32_t>& res_list) {
//    vector<uint32_t> res_list;
    //find the corresponding attribute of the searched keyword (keyword-attribute: n-1 relation?)
//    unordered_map<string, vector<string>>::iterator ptm;
//    vector<string>::iterator ptv;
    vector<string> attrs;
    attrs = this->dbowner->keyword_attrs[keyword];
//    for (ptm = this->dbowner->attr_keywords.begin(); ptm != this->dbowner->attr_keywords.end(); ++ptm)
//        for (ptv = ptm->second.begin(); ptv != ptm->second.end(); ++ptv)
//            if (*ptv == keyword)
//                attrs.push_back(ptm->first);


    //For each attribute category, find if there is a common node d
    unordered_map<uint32_t, uint8_t*> :: iterator it;
    string attr = attrs[0];
 //   for (string attr : attrs) {
//        cout << u_node_key.size();
    for (it = this->u_node_key.begin(); it != this->u_node_key.end(); it++) {
        string common_node = to_string(it->first);
        if (this->dbowner->bulletin.find(attr + keyword + common_node) != this->dbowner->bulletin.end()) {
//            auto t_start = std::chrono::high_resolution_clock::now();
            uint8_t common_node_key[BLOCK_SIZE];
            //memcpy(common_node_key, this->dbowner->tree->keys[it->first], BLOCK_SIZE);
            memcpy(common_node_key, it->second, BLOCK_SIZE);
            // convert common_node_key to mpz
            Zr h_common_node_key(*this->dbowner->e, common_node_key, BLOCK_SIZE);
            mpz_t element_common_node_key;
            mpz_init(element_common_node_key);
            element_to_mpz(element_common_node_key, (element_s *) h_common_node_key.getElement());
            //for (int j = 0; j <= this->keyword_ST[keyword]; j++) { //no need, just get the latest j?
            // use the common node key to recover key_dht, k_123 from PubToken

            uint8_t key_dht[BLOCK_SIZE];
            uint8_t key_1[BLOCK_SIZE];
            uint8_t key_2[BLOCK_SIZE];
            uint8_t key_3[BLOCK_SIZE];
            for (int k = 0; k < BLOCK_SIZE; k++) {
                key_dht[k] = this->dbowner->bulletin[attr + keyword + common_node][0][k] ^ common_node_key[k];
                key_1[k] = this->dbowner->bulletin[attr + keyword + common_node][1][k] ^ common_node_key[k];
                key_2[k] = this->dbowner->bulletin[attr + keyword + common_node][2][k] ^ common_node_key[k];
                key_3[k] = this->dbowner->bulletin[attr + keyword + common_node][3][k] ^ common_node_key[k];
            }
            // recover r_key_1
            mpz_t r_key_1;
            mpz_init(r_key_1);
            mpz_xor(r_key_1, this->dbowner->bulletin_r[attr + keyword + common_node], element_common_node_key);

//            auto t_end = std::chrono::high_resolution_clock::now();
//            double elapsed_time_ms = std::chrono::duration<double, std::milli>(t_end-t_start).count();
//            cout << "Time pre-search, part bulletin: " << elapsed_time_ms << endl;

            //auto t_start = std::chrono::high_resolution_clock::now();
            // generate the trapdoor
            // convert key_1 and key_2 to mpz
            Zr h_key_1(*this->dbowner->e, key_1, BLOCK_SIZE);
            Zr h_key_2(*this->dbowner->e, key_2, BLOCK_SIZE);
//            print_chararray(key_1, BLOCK_SIZE);
//            print_chararray(key_2, BLOCK_SIZE);

            mpz_t element_key_1;
            mpz_init(element_key_1);
            element_to_mpz(element_key_1, (element_s *) h_key_1.getElement());
            mpz_t trapdoor_1;
            mpz_init(trapdoor_1);
//            cout << "r_key_1: " <<  mpz_get_ui(r_key_1) << endl;
//            cout << "element_key_1: " <<  mpz_get_ui(element_key_1) << endl;

            chameleon_hash(this->dbowner->pk, element_key_1, r_key_1, trapdoor_1); // trapdoor1 is g^x*pk^r
            mpz_t trapdoor_2;
            mpz_init(trapdoor_2);
            element_to_mpz(trapdoor_2, (element_s *) h_key_2.getElement()); // trapdoor2 is x'

//            auto t_end = std::chrono::high_resolution_clock::now();
//            double elapsed_time_ms = std::chrono::duration<double, std::milli>(t_end-t_start).count();
//            cout << "Time pre-search, part CH: " << elapsed_time_ms << endl;


//            t_start = std::chrono::high_resolution_clock::now();
            vector<bool> e_w;
            e_w = this->dbowner->server->search(trapdoor_1, trapdoor_2);
//            t_end = std::chrono::high_resolution_clock::now();
//            elapsed_time_ms = std::chrono::duration<double, std::milli>(t_end-t_start).count();
//            cout << "Time search: " << elapsed_time_ms << endl;
            // decrypt e_w if it is available
            // print_chararray(e_w, this->dbowner->num_files);
            if (e_w.size() != 0) {
                //cout << "size e_w: " << e_w.size() << endl;
                vector<bool> plaintext(this->dbowner->num_files);
//                    cout << this->dbowner->num_files << endl;
//                   t_start = std::chrono::high_resolution_clock::now();
                dec_ashe(e_w, this->dbowner->num_files, key_3,
                         (uint8_t *)keyword.c_str(), keyword.size(), this->dbowner->LW_ST[keyword] + 1, plaintext);
//                  t_end = std::chrono::high_resolution_clock::now();
//                elapsed_time_ms = std::chrono::duration<double, std::milli>(t_end-t_start).count();
  //              cout << "Time decryption: " << elapsed_time_ms << endl;
                // scan the plaintext for result
                for (int k = 0; k < this->dbowner->num_files; k++) {
                    if (plaintext[k] == true) {
                        res_list.emplace_back(k);
                    }
                }
                //return res_list;
                return;
            }
        }

    }
    //cout << "Unauthorized!" << endl;
   // }
    return;
}
