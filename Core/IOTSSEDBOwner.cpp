//
// Created by Shangqi on 11/7/22.
//

#include <bitset>
#include <utility>
#include "IOTSSEDBOwner.h"
#include "chrono"


IOTSSEDBOwner::IOTSSEDBOwner(uint32_t num_users, uint32_t num_files, const string *attr_universe, uint32_t num_attr,
                             const unordered_map<string, vector<uint32_t>> &attr_users,
                             const unordered_map<string, vector<string>> &attr_keywords,
                             const unordered_map<string, vector<string>> &keyword_attrs,
                             const unordered_map<string, vector<uint32_t>> &inverted_index) {
    // load a pair with
    // FILE *sysParamFile = fopen("pairing.param", "r"); //pairing.param
    FILE *sysParamFile = fopen("Data/pairing.param", "r");
    this->e = new Pairing(sysParamFile);
    fclose(sysParamFile);
    // generate a chameleon hash key pair
    tie(this->pk, this->sk) = keygen();

    // save parameter
    this->num_users = num_users;
    this->num_attr = num_attr;
    this->num_files = num_files;
    // Generate a group tree
    this->tree = new GroupKeyTree(this->MSK, num_users); //user_size = num_users?
    this->user_label_PRF = new uint8_t*[this->num_users];
    // create user_label_PRF and public bulletin PathKeyToken
    for (int uid = 0; uid < this->num_users; uid++) {
        // generate the client key
        uint8_t client_key[BLOCK_SIZE];
        aes_cmac((uint8_t*) &uid, sizeof (int), MSK, client_key); //=k_i=F(MK, uid)
        // choose a random label for the user
        uint8_t label[BLOCK_SIZE];
        RAND_bytes(label, BLOCK_SIZE);
        // fetch a path of keys from the tree
        bulletin_pathkey[uid] = new uint8_t*[this->tree->get_depth() + 1];
        this->tree->fetch_path_keys(uid, bulletin_pathkey[uid]); // get users' path-keys in order ....
        // generate the PRF of client label
        user_label_PRF[uid] = new uint8_t[BLOCK_SIZE];
        aes_cmac(label, BLOCK_SIZE, client_key, user_label_PRF[uid]); //F(K_uid, l_uid) shared to user
        // xor the path of keys with the label

        for (int i = 0; i <= this->tree->get_depth(); i++) {
            for (int j = 0; j < BLOCK_SIZE; j++) {
                bulletin_pathkey[uid][i][j] ^= user_label_PRF[uid][j];
            }
        }

    }

    // copy the user attribute/keyword attribute list
    this->attr_users = move(attr_users);
    this->attr_keywords = move(attr_keywords);
    this->keyword_attrs = move(keyword_attrs);
    this->inverted_index = move(inverted_index);


    // Initialise attribute state map.
    this->attr_universe = new string[this->num_attr];
    for(int i = 0; i < this->num_attr; i++) {
        this->attr_universe[i] = string(attr_universe[i]);
        if (ATT_ST.find(this->attr_universe[i]) == ATT_ST.end()) {
            // add attribute to the map if it does not exist
            ATT_ST[this->attr_universe[i]] = 0;
        } else {
            ATT_ST[this->attr_universe[i]]++;
        }
        for(string keyword: this->attr_keywords[this->attr_universe[i]]){
            LW_ST[keyword] = 0;
        }
    }

    // Generate DHT: line 11-14 phase 2 Algorithm 1: DHT[i] = S_atti
    this->DHT.reserve(this->num_attr);
    for (int i = 0; i < this->num_attr; i++) {
        // compute attribute key k_att
        uint8_t key_attr[BLOCK_SIZE]; //key 128 bit from PRF AES-128bit
        aes_cmac((unsigned char *) this->attr_universe[i].c_str(),
                 this->attr_universe[i].size(), MSK, key_attr); //Alg1 - line 17
        this->attr_key.emplace(this->attr_universe[i],key_attr);
        // compute dht key
        uint8_t key_dht[BLOCK_SIZE];
        aes_cmac((unsigned char *) (this->attr_universe[i] + to_string(this->ATT_ST[this->attr_universe[i]])).c_str(),
                 this->attr_universe[i].size() + to_string(this->ATT_ST[this->attr_universe[i]]).size(), MSK, key_dht);
        this->attr_dhtkey.emplace(this->attr_universe[i], key_dht);
        // compute address in DHT
        this->DHT[i] = new uint8_t[BLOCK_SIZE];
        aes_cmac((unsigned char *) this->attr_universe[i].c_str(), this->attr_universe[i].size(), key_dht, DHT[i]);
    }

    // initialise server
    server = new IOTSSEServer(this->pk);
}

IOTSSEDBOwner::~IOTSSEDBOwner() {
    // clear DHT
    for (int i = 0; i < this->num_attr; i++) {
        delete this->DHT[i];
        this->DHT[i] = nullptr;
    }

    // delete bulletin_pathkey, user_label_PRF
    for (int uid = 0; uid < this->num_users; uid++) {
        delete this->user_label_PRF[uid];
        this->user_label_PRF = nullptr;
        for (int i = 0; i < this->tree->get_depth(); i++) {
            delete this->bulletin_pathkey[uid][i];
            this->bulletin_pathkey[uid][i] = nullptr;
        }
        delete this->bulletin_pathkey[uid];
        this->bulletin_pathkey[uid] = nullptr;
    }
    delete this->user_label_PRF;
    this->user_label_PRF = nullptr;

    // delete bulletin
    unordered_map<string, uint8_t**>::iterator it;
    for (it = this->bulletin.begin(); it != this->bulletin.end(); it++){
        for (int i = 0; i < 4; i++){
            delete it->second[i];
            it->second[i] = nullptr;
        }
        delete it->second;
        it->second = nullptr;
    }

    // delete bulletin_lw
    for (uint32_t i = 0; i < num_attr; i++)
        for (string keyword: this->attr_keywords[this->attr_universe[i]]){
            delete this->bulletin_lw[keyword];
            this->bulletin_lw[keyword] = nullptr;
        }

    // trigger the destructor of GroupKeyTree
    delete this->tree;
    this->tree = nullptr;

    // delete the chameleon hash key
    destroy_keys(this->pk, this->sk);

    // delete the pairing
    delete e;

    // trigger the destructor of IOTSSEServer
    delete server;
}

uint8_t * IOTSSEDBOwner::get_user_label_PRF(const uint32_t uid){
    return this->user_label_PRF[uid];
}

void IOTSSEDBOwner::get_user_path(uint32_t uid, vector<uint32_t>& idx_nodes){ //
    this->tree->fetch_path(uid, idx_nodes);
}

void IOTSSEDBOwner::generate_encrypted_db() {
    unordered_map<string, pair<string, vector<bool>>> D_W;
    for(uint32_t i = 0; i < this->num_attr; i++) {
        // retrieve the RootsSubtrees keys from the tree
        unordered_map<uint32_t, uint8_t[BLOCK_SIZE]> node_key;
        unordered_map<uint32_t, uint8_t[BLOCK_SIZE]>::iterator i_node_key;
        this->tree->min_coverage_key(node_key, this->attr_users[this->attr_universe[i]]);
        for(string keyword: this->attr_keywords[this->attr_universe[i]]){
            // choose a random label for the keyword and public it to bulletin
            uint8_t label[BLOCK_SIZE];
            RAND_bytes(label, BLOCK_SIZE); // Alg1 - line 20
            this->bulletin_lw[keyword] = new uint8_t[BLOCK_SIZE];
            memcpy(this->bulletin_lw[keyword], label, BLOCK_SIZE);
            // hash w to Zr
            //Zr h_w(*this->e, keyword.c_str(), keyword.length()); // Alg1 - line 21 - H1(w)
            // update keyword state
            if (this->keyword_ST.find(keyword) == this->keyword_ST.end()) {
                this->keyword_ST[keyword] = 0;
            } else {
                this->keyword_ST[keyword]++;
            }
            // generate the key
            uint8_t key_1[BLOCK_SIZE];
            uint8_t key_2[BLOCK_SIZE];
            uint8_t key_3[BLOCK_SIZE];
            // use AES as prf to generate 128-bit keys
            aes_cmac((unsigned char *) (keyword + "0" +  to_string(this->keyword_ST[keyword])).c_str(),
                     keyword.size() + to_string(this->keyword_ST[keyword]).size() + 1, this->attr_key[this->attr_universe[i]], key_1);
            aes_cmac((unsigned char *) (keyword + "1" +  to_string(this->keyword_ST[keyword])).c_str(),
                     keyword.size() + to_string(this->keyword_ST[keyword]).size() + 1, this->attr_key[this->attr_universe[i]], key_2);
            aes_cmac((unsigned char *) (keyword + "2" +  to_string(this->keyword_ST[keyword])).c_str(),
                     keyword.size() + to_string(this->keyword_ST[keyword]).size() + 1, this->attr_key[this->attr_universe[i]], key_3);
            Zr h_key_1(*this->e, key_1, BLOCK_SIZE); //hash key_1 key_2 128bit to Zr
            Zr h_key_2(*this->e, key_2, BLOCK_SIZE);

            mpz_t element_key_1;
            mpz_t element_key_2;
            mpz_init(element_key_1);
            mpz_init(element_key_2);
            element_to_mpz(element_key_1, (element_s*) h_key_1.getElement()); //convert
            element_to_mpz(element_key_2, (element_s*) h_key_2.getElement());
            // generate two random numbers with Chameleon Hash
            // choose the r for key_1
            gmp_randstate_t state;
            gmp_randinit_mt (state);
            mpz_t r_key_1;
            mpz_init(r_key_1);
            mpz_urandomm(r_key_1, state, this->pk.q);
            mpz_t add_keyword;
            mpz_init(add_keyword);
            chameleon_hash(this->pk, element_key_1, r_key_1, add_keyword); //Alg1 - line 25 - address-keyword: H(K_1w, r1_w)
            // forge r for key_2
            mpz_t r_key_2;
            mpz_init(r_key_2);
            forge(this->pk, this->sk, element_key_1, r_key_1, element_key_2, r_key_2); //out r_key_2

            // generate a bit string for files
            vector<bool> S(this->num_files);
            for (uint32_t id : inverted_index[keyword])
                S[id] = true;
            vector<bool> e_w(this->num_files);
            enc_ashe(S, this->num_files,
                     key_3, (unsigned char*) keyword.c_str(), keyword.size(), this->LW_ST[keyword], e_w);

            // append (r_key_2, e_w) to EDB[add_keyword] : Alg1 - line 29
            D_W[mpz_get_str(nullptr, 10, add_keyword)] = make_pair(mpz_get_str(nullptr, 10, r_key_2), e_w);

            // generate a PubToken for the current keyword
            for(i_node_key=node_key.begin(); i_node_key!=node_key.end();i_node_key++){
                uint8_t common_node_key[BLOCK_SIZE];
                memcpy(common_node_key, i_node_key->second, BLOCK_SIZE); //k_d
                // convert common_node_key to mpz
                Zr h_common_node_key(*this->e, common_node_key, BLOCK_SIZE);
                mpz_t element_common_node_key;
                mpz_init(element_common_node_key);
                element_to_mpz(element_common_node_key, (element_s*) h_common_node_key.getElement());
                string common_node = to_string(i_node_key->first);
                this->bulletin[this->attr_universe[i] + keyword + common_node] = new uint8_t *[4];
                for (int k = 0; k < 4; k++)
                    this->bulletin[this->attr_universe[i] + keyword + common_node][k] = new uint8_t[BLOCK_SIZE];
                // copy keys into bulletin
                memcpy(this->bulletin[this->attr_universe[i] + keyword + common_node][0], this->attr_dhtkey[this->attr_universe[i]], BLOCK_SIZE);
                memcpy(this->bulletin[this->attr_universe[i] + keyword + common_node][1], key_1, BLOCK_SIZE);
                memcpy(this->bulletin[this->attr_universe[i] + keyword + common_node][2], key_2, BLOCK_SIZE);
                memcpy(this->bulletin[this->attr_universe[i] + keyword + common_node][3], key_3, BLOCK_SIZE);

                for (int j = 0; j < BLOCK_SIZE; j++) { //(Kdht||K1w||K2w||K3w xor common_node_key)
                    this->bulletin[this->attr_universe[i] + keyword + common_node][0][j] ^= common_node_key[j]; //^: xor byte
                    this->bulletin[this->attr_universe[i] + keyword + common_node][1][j] ^= common_node_key[j];
                    this->bulletin[this->attr_universe[i] + keyword + common_node][2][j] ^= common_node_key[j];
                    this->bulletin[this->attr_universe[i] + keyword + common_node][3][j] ^= common_node_key[j];
                }
                // copy r_key_1 into bulletin_r
                mpz_init(this->bulletin_r[this->attr_universe[i] + keyword + common_node]);
                mpz_xor(this->bulletin_r[this->attr_universe[i] + keyword + common_node], r_key_1, element_common_node_key);
            }

        }
    }

    // send EDB to server
    server->get_db(D_W);

}

void IOTSSEDBOwner::update_db(const vector<uint32_t>& f_up, const string& keyword){ // Algo 3
    //find the corresponding attribute of the searched keyword (attribute-keywords: 1-n relation?)
//    unordered_map<string, vector<string>>::iterator ptm;
//    vector<string>::iterator ptv;
    vector<string> attrs;
    attrs = this->keyword_attrs[keyword];
//    for (ptm = attr_keywords.begin(); ptm != attr_keywords.end(); ++ptm)
//        for (ptv = ptm->second.begin(); ptv != ptm->second.end(); ++ptv)
//            if (*ptv == keyword)
//                attrs.push_back(ptm->first);

//    cout << "Size attrs: " << attrs.size() << endl;

    //For each attribute category, retrieve the existing trapdoors corresponding to the keyword
    unordered_map<uint32_t, uint8_t[BLOCK_SIZE]> srt_node_key;
    unordered_map<uint32_t, uint8_t[BLOCK_SIZE]>::iterator i_srt_node_key;
    for (string attr : attrs) {
        // recover add_keyword from PubToken and key_node
//        auto t_start = std::chrono::high_resolution_clock::now();
        srt_node_key.clear();

        this->tree->min_coverage_key(srt_node_key, this->attr_users[attr]);
        i_srt_node_key = srt_node_key.begin();
        uint8_t root_subtree_key[BLOCK_SIZE];


        memcpy(root_subtree_key, i_srt_node_key->second, BLOCK_SIZE); //k_d


        Zr h_root_subtree_key(*this->e, root_subtree_key, BLOCK_SIZE);
        mpz_t element_root_subtree_key;
        mpz_init(element_root_subtree_key);
        element_to_mpz(element_root_subtree_key, (element_s *) h_root_subtree_key.getElement());
        mpz_t add_keyword;
        uint8_t key_1[BLOCK_SIZE];
        uint8_t key_3[BLOCK_SIZE];
        string root_substree = to_string(i_srt_node_key->first);
//        auto t_end = std::chrono::high_resolution_clock::now();
//        double elapsed_time_ms = std::chrono::duration<double, std::milli>(t_end-t_start).count();
//        cout << "Time b4 if update: " << elapsed_time_ms << endl;


        if (this->bulletin.find(attr + keyword + root_substree) != this->bulletin.end()) {
            for (int k = 0; k < BLOCK_SIZE; k++) {
                key_1[k] = this->bulletin[attr + keyword + root_substree][1][k] ^ root_subtree_key[k];
                key_3[k] = this->bulletin[attr + keyword + root_substree][3][k] ^ root_subtree_key[k];
            }
            // recover r_key_1
            mpz_t r_key_1;
            mpz_init(r_key_1);
            mpz_xor(r_key_1, this->bulletin_r[attr + keyword + root_substree], element_root_subtree_key);

//            auto t_start = std::chrono::high_resolution_clock::now();
            //generate add_keyword: Alg3 - line 2
            Zr h_key_1(*this->e, key_1, BLOCK_SIZE);
            mpz_t element_key_1;
            mpz_init(element_key_1);
            element_to_mpz(element_key_1, (element_s *) h_key_1.getElement());
            mpz_init(add_keyword);
            chameleon_hash(this->pk, element_key_1, r_key_1, add_keyword);
            //check trapdoor
            //cout << "Trapdoor recovered: " << mpz_get_ui(add_keyword) << endl;
//            auto t_end = std::chrono::high_resolution_clock::now();
//            double elapsed_time_ms = std::chrono::duration<double, std::milli>(t_end-t_start).count();
//            cout << "Time if update: " << elapsed_time_ms << endl;
        }


        // change the state of keyword results
        this->LW_ST[keyword]++;
        // line 1: generate a bit string for files updated (delete/add)

        vector<bool> S_up(this->num_files);
        for (uint32_t id: f_up) {
            S_up[id] = true;
        }

        // line 3: encrypt bit_S_up
        vector<bool> e_w_up(this->num_files);
//        auto t_start = std::chrono::high_resolution_clock::now();
        enc_ashe(S_up, this->num_files,
                 key_3, (uint8_t*)keyword.c_str(), keyword.size(), this->LW_ST[keyword], e_w_up);
//        auto t_end = std::chrono::high_resolution_clock::now();
//        double elapsed_time_ms = std::chrono::duration<double, std::milli>(t_end-t_start).count();
//        cout << "Time encryption update: " << elapsed_time_ms << endl;
        //send to server the updated information

//        t_start = std::chrono::high_resolution_clock::now();
        this->server->get_updated_db(add_keyword, e_w_up, this->num_files);
//        t_end = std::chrono::high_resolution_clock::now();
//        elapsed_time_ms = std::chrono::duration<double, std::milli>(t_end-t_start).count();
//        cout << "Time server update: " << elapsed_time_ms << endl;
    }
}

void IOTSSEDBOwner::revoke_users(const string& keyword, const vector<uint32_t>& non_revoked_users) { //Algo 4
    //find the corresponding attribute of the searched keyword (keyword-attribute: n-1 relation?)
//    unordered_map<string, vector<string>>::iterator ptm;
//    vector<string>::iterator ptv;
    vector<string> attrs;
    attrs = this->keyword_attrs[keyword];
//    for (ptm = attr_keywords.begin(); ptm != attr_keywords.end(); ++ptm)
//        for (ptv = ptm->second.begin(); ptv != ptm->second.end(); ++ptv)
//            if (*ptv == keyword)
//                attrs.push_back(ptm->first);
    //For each attribute category, retrieve the existing trapdoors corresponding to the keyword
    unordered_map<uint32_t, uint8_t[BLOCK_SIZE]> srt_node_key;
    unordered_map<uint32_t, uint8_t[BLOCK_SIZE]>::iterator i_srt_node_key;
    for (string attr: attrs) {
        // recover add_keyword from PubToken and key_node
        this->tree->min_coverage_key(srt_node_key, this->attr_users[attr]);
        i_srt_node_key = srt_node_key.begin(); // just need to get one node in SRT set
        uint8_t root_subtree_key[BLOCK_SIZE];
        memcpy(root_subtree_key, i_srt_node_key->second, BLOCK_SIZE); //k_d
        Zr h_root_subtree_key(*this->e, root_subtree_key, BLOCK_SIZE);
        mpz_t element_root_subtree_key;
        mpz_init(element_root_subtree_key);
        element_to_mpz(element_root_subtree_key, (element_s *) h_root_subtree_key.getElement());
        mpz_t add_keyword;
        uint8_t key_1[BLOCK_SIZE];
        uint8_t key_2[BLOCK_SIZE];
        uint8_t key_3[BLOCK_SIZE];
        string root_substree = to_string(i_srt_node_key->first);
        if (this->bulletin.find(attr + keyword + root_substree) != this->bulletin.end()) {
            for (int k = 0; k < BLOCK_SIZE; k++) {
                key_1[k] = this->bulletin[attr + keyword + root_substree][1][k] ^ root_subtree_key[k];
                key_3[k] = this->bulletin[attr + keyword + root_substree][3][k] ^ root_subtree_key[k];
            }
            // recover r1_j
            mpz_t r1_j;
            mpz_init(r1_j);
            mpz_xor(r1_j, this->bulletin_r[attr + keyword + root_substree], element_root_subtree_key);
            //generate add_keyword: Alg3 - line 2
            Zr h_key_1(*this->e, key_1, BLOCK_SIZE);
            mpz_t element_key_1;
            mpz_init(element_key_1);
            element_to_mpz(element_key_1, (element_s *) h_key_1.getElement());
            mpz_init(add_keyword);
            chameleon_hash(this->pk, element_key_1, r1_j, add_keyword);
            // done recover add_keyword
//            //check if correct recovery: Done
//            if (attr == "attribute3") {
//                cout << "##################################################" << endl;
//                cout << "Keys and trapdoors dbowner recovers" << endl;
//                cout << "key1_j+1: ";
//                this->tree->print_key(key_1);
//                cout << "trapdoor1: " << mpz_get_ui(add_keyword) << endl;
//                cout << "##################################################" << endl;
//
//            }

            //line 1: update the state of the keyword
            this->keyword_ST[keyword] = this->keyword_ST[keyword] + 1;

            //line 2: compute fresh keys K_1w, K_2w with the new state. (w||0||j, w||1||j
            aes_cmac((unsigned char *) (keyword + "0" + to_string(this->keyword_ST[keyword])).c_str(),
                     keyword.size() + to_string(this->keyword_ST[keyword]).size() + 1, this->attr_key[attr], key_1);
            aes_cmac((unsigned char *) (keyword + "1" + to_string(this->keyword_ST[keyword])).c_str(),
                     keyword.size() + to_string(this->keyword_ST[keyword]).size() + 1, this->attr_key[attr], key_2);

            // NOTE THAT WE DO NOT UPDATE KEY_3
            // forge r1_jup
            Zr h_key_1up(*this->e, key_1, BLOCK_SIZE);
            mpz_t element_key_1up;
            mpz_init(element_key_1up);
            element_to_mpz(element_key_1up, (element_s *) h_key_1up.getElement());
            mpz_t r1_jup;
            mpz_init(r1_jup);
            forge(this->pk, this->sk, element_key_1, r1_j, element_key_1up, r1_jup);

            // forge r2_jup
            Zr h_key_2up(*this->e, key_2, BLOCK_SIZE);
            mpz_t element_key_2up;
            mpz_init(element_key_2up);
            element_to_mpz(element_key_2up, (element_s *) h_key_2up.getElement());
            mpz_t r2_jup;
            mpz_init(r2_jup);
            forge(this->pk, this->sk, element_key_1up, r1_jup, element_key_2up, r2_jup);

//            //check new keys and trapdoors: trapdor1_j+1 = trapdoor1_j; trapdoor2_j+1 != trapdoor2_j, key1/2_j+1 != key1/2_j
//            if (attr == "attribute3") {
//                cout << "##################################################" << endl;
//                cout << "Keys and trapdoors dbowner creates after revocation" << endl;
//                cout << "key1_j+1: ";
//                this->tree->print_key(key_1);
//                cout << "key2_j+1: ";
//                this->tree->print_key(key_2);
//                mpz_t trapdoor_1;
//                mpz_init(trapdoor_1);
//                chameleon_hash(this->pk, element_key_1up, r1_jup, trapdoor_1); // trapdoor1 is g^x*pk^r
//                cout << "trapdoor1: " << mpz_get_ui(trapdoor_1) << endl;
//                cout << "trapdoor2: " << mpz_get_ui(element_key_2up) << endl;
//                cout << "##################################################" << endl;
//
//            }

            //line 4, 5, 6: generate the updated PubToken to the keyword
            //update the list of authorized users
            //if (this->attr_users.find(attr) != this->attr_users.end())
            this->attr_users[attr] = non_revoked_users;

            // Update PubToken corresponding to the updated authorized users
            srt_node_key.clear();
            this->tree->min_coverage_key(srt_node_key, this->attr_users[attr]);
            for (i_srt_node_key=srt_node_key.begin(); i_srt_node_key!=srt_node_key.end(); i_srt_node_key++) {
                uint8_t root_subtree_key[BLOCK_SIZE];
                memcpy(root_subtree_key, i_srt_node_key->second, BLOCK_SIZE); //k_d
                Zr h_root_subtree_key(*this->e, root_subtree_key, BLOCK_SIZE);
                mpz_t element_root_subtree_key;
                mpz_init(element_root_subtree_key);
                element_to_mpz(element_root_subtree_key, (element_s *) h_root_subtree_key.getElement());
                // generate a PubToken for the current keyword
                string root_subtree = to_string(i_srt_node_key->first);
                this->bulletin[attr + keyword + root_subtree] = new uint8_t *[4];
                for (int k = 0; k < 4; k++)
                    this->bulletin[attr + keyword + root_subtree][k] = new uint8_t[BLOCK_SIZE];
                // copy the updated keys k1_j+1, k2_j+1 into bulletin
                //memcpy(this->bulletin[attr + keyword + common_node][0], attr_dhtkey[attr], BLOCK_SIZE);
                memcpy(this->bulletin[attr + keyword + root_subtree][1], key_1, BLOCK_SIZE);
                memcpy(this->bulletin[attr + keyword + root_subtree][2], key_2, BLOCK_SIZE);
                memcpy(this->bulletin[attr + keyword + root_subtree][3], key_3, BLOCK_SIZE);

                for (int j = 0; j < BLOCK_SIZE; j++) { //(Kdht||K1w||K2w||K3w xor common_node_key)
                    //this->bulletin[attr + keyword + common_node][0][j] ^= common_node_key[j]; //^: xor byte
                    this->bulletin[attr + keyword + root_subtree][1][j] ^= root_subtree_key[j];
                    this->bulletin[attr + keyword + root_subtree][2][j] ^= root_subtree_key[j];
                    this->bulletin[attr + keyword + root_subtree][3][j] ^= root_subtree_key[j];
                }

                // copy r1_jup into bullein_r
                mpz_init(this->bulletin_r[attr + keyword + root_subtree]);
                mpz_xor(this->bulletin_r[attr + keyword + root_subtree], r1_jup, element_root_subtree_key);
                // send (r2_jup) corresponding to add_keyword (trap1) to the server
                this->server->get_updated_revokedusers(add_keyword, r2_jup);
            }
        }
    }
}

