#include <iostream>
#include <chrono>

#include "IOTSSEDBOwner.h"
#include "IOTSSEUser.h"
#include "IOTSSEServer.h"


//#define NUM_ATTRS 100//10^2
//#define NUM_KEYWORDS 100000//10^6
//#define NUM_DOCS 1000 //10^3 (# of docs)
//#define NUM_USERS 100



using namespace std;
//#define NUM_ATTRS 10//10^2
//#define NUM_KEYWORDS 10//10^6
//#define NUM_DOCS 10 //10^3 (# of docs)
//#define NUM_USERS 10
void test_accuracy(int NUM_ATTRS, int NUM_KEYWORDS, int NUM_DOCS, int NUM_USERS){
    cout << "################################################################################################" << endl;
    cout << "Parameter setting: ";
    cout << "NUM_DOCS " << NUM_DOCS;
    cout << ", NUM_KEYWORDS " << NUM_KEYWORDS;
    cout << ", NUM_USERS " << NUM_USERS;
    int DB_SIZE = 0;

    auto t_start = std::chrono::high_resolution_clock::now();
    string attr_universe[NUM_ATTRS];
    unordered_map<string, vector<uint32_t>> inverted_index; //store list of id files corresponding to keywords
    unordered_map<string, vector<uint32_t>> attr_users;
    unordered_map<string, vector<string>> attr_keywords;
    unordered_map<string, vector<string>> keyword_attrs;

    //create list of attributes
    for (int i = 0; i < NUM_ATTRS; i++)
        attr_universe[i] = "attribute" + to_string(i);

    //create unordered_map inverted_index: keyword_i for list of docs {0 --> DB_SIZE/(i+1) - 1}
    int num_kwtypes = log2(NUM_DOCS);
    int num_kw_per_type = NUM_KEYWORDS / num_kwtypes;
    int kw_idx;

    for (int i = 0; i < num_kwtypes; i++)
        for (int k = 0; k < num_kw_per_type; k++)
            for (int j = 0; j < NUM_DOCS / (exp2(i)); j++){
                kw_idx = i*num_kw_per_type+k;
                inverted_index[to_string(i*num_kw_per_type+k)].emplace_back(j);
                DB_SIZE++;
            }
    for (int i = kw_idx + 1; i < NUM_KEYWORDS; i++) {
        inverted_index[to_string(i)].emplace_back(0);
        DB_SIZE++;
    }

    cout << ", DB_SIZE (# of (keyword-doc) pairs): " << DB_SIZE;
    cout << endl;

    //create unordered_map attr_users: attr i has authorized users {0 --> NUM_USERS/(i+1) - 1}
    for (int i = 0; i < NUM_ATTRS; i++)
        for (int j = 0; j < NUM_USERS/(i+1); j++)
            attr_users[attr_universe[i]].emplace_back(j);

    //create unordered_map attr_keywords: attr i has keywords {step*i --> step*(i+1) - 1}
    int step = NUM_KEYWORDS / NUM_ATTRS;
    for (int i = 0; i < NUM_ATTRS; i++)
        for (int j = 0; j < step; j++) {
            attr_keywords[attr_universe[i]].emplace_back(to_string(step * i + j));
            keyword_attrs[to_string(step * i + j)].emplace_back(attr_universe[i]);
        }
    IOTSSEDBOwner *dbowner = new IOTSSEDBOwner(NUM_USERS, NUM_DOCS, attr_universe, NUM_ATTRS, attr_users, attr_keywords, keyword_attrs, inverted_index);
    //create users
    IOTSSEUser **u = new IOTSSEUser*[NUM_USERS];
    for (int i = 0; i < NUM_USERS; i++)
        u[i] = new IOTSSEUser(i, dbowner);
    auto t_end = std::chrono::high_resolution_clock::now();
    double elapsed_time_ms = std::chrono::duration<double, std::milli>(t_end-t_start).count();
    cout << "Setup time: " << elapsed_time_ms << " milliseconds" << endl;


    cout << "################################################################################################" << endl;
    t_start = std::chrono::high_resolution_clock::now();
    dbowner->generate_encrypted_db();
    t_end = std::chrono::high_resolution_clock::now();
    elapsed_time_ms = std::chrono::duration<double, std::milli>(t_end-t_start).count();
    cout << "EDB generation time: " << elapsed_time_ms << " milliseconds" << endl;


    //Test query: Each user queries 100 random each keyword. Time is averaged
    cout << "################################################################################################" << endl;
    vector<uint32_t> query_res;
    t_start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < NUM_USERS; i++) {
        for (int j = 0; j < 10; j++) {
            string keyword = to_string(rand() % NUM_KEYWORDS);
            //string keyword = to_string(j);
            query_res.clear();
            u[i]->query(keyword, query_res);
            if (i == 0) {
                cout << "User " << i << ", query " << keyword << ", result: ";
                for (uint32_t id: query_res) {
                    cout << id << " ";
                }
                cout << endl;
            }
        }
    }
    int num_queries = 10 * NUM_USERS;
    t_end = std::chrono::high_resolution_clock::now();
    elapsed_time_ms = std::chrono::duration<double, std::milli>(t_end-t_start).count();
    cout << "Average query time: " << elapsed_time_ms / num_queries << " milliseconds" << endl;

    //Test DB update: (DEL then INS for keyword "0"
    cout << "################################################################################################" << endl;
    t_start = std::chrono::high_resolution_clock::now();
    vector<uint32_t> f_up;
    for (int i = 0; i < NUM_DOCS; i++) {
        f_up.push_back(i);
        string keyword = to_string(rand() % NUM_KEYWORDS);
        query_res.clear();
        u[0]->query(keyword, query_res);
        cout << "i = " << i << endl;
        cout << "Before update:";
        if (query_res.size() != 0) {
            for (uint32_t id: query_res) {
                cout << id << " ";
            }
            cout << endl;
        }
        else
            cout << "No result" << endl;
        dbowner->update_db(f_up, keyword); // remove file i from keyword 0's result
        query_res.clear();
        u[0]->query(keyword, query_res);
        cout << "After update 1:";
        if (query_res.size() != 0) {
            for (uint32_t id: query_res) {
                cout << id << " ";
            }
            cout << endl;
        }
        else
            cout << "No result" << endl;
        dbowner->update_db(f_up, keyword); // insert file i from keyword 0's result
        query_res.clear();
        u[0]->query(keyword, query_res);
        cout << "After update 2:";
        if (query_res.size() != 0) {
            for (uint32_t id: query_res) {
                cout << id << " ";
            }
            cout << endl;
        }
        else
            cout << "No result" << endl;
    }
    t_end = std::chrono::high_resolution_clock::now();
    elapsed_time_ms = std::chrono::duration<double, std::milli>(t_end-t_start).count();
    cout << "Average update time: " << elapsed_time_ms / (2*NUM_DOCS) << " milliseconds" << endl;

    //Test user revocation: Randomize keyword for revocation 100 times. After revocation, only first half are authorized
    cout << "################################################################################################" << endl;
    vector<uint32_t> non_revoked_users;
    for (int i = 0; i < NUM_USERS / 2; i++)
        non_revoked_users.push_back(i);

    t_start = std::chrono::high_resolution_clock::now();
    for (int k = 0; k < 10; k++) {
        string keyword = to_string(rand() % NUM_KEYWORDS);
        dbowner->revoke_users(keyword, non_revoked_users);
        query_res.clear();
        u[8]->query("0", query_res);
        if (query_res.size() != 0) {
            for (uint32_t id: query_res) {
                cout << id << " ";
            }
            cout << endl;
        }
        else
           cout << "User is not authorized" << endl;
    }
    t_end = std::chrono::high_resolution_clock::now();
    elapsed_time_ms = std::chrono::duration<double, std::milli>(t_end-t_start).count();
    cout << "Average revocation time: " << elapsed_time_ms / 10 << " milliseconds" << endl;

}

void test_performance(int NUM_ATTRS, int NUM_KEYWORDS, int NUM_DOCS, int NUM_USERS,
                      vector<double>& t_setup, vector<double>& t_dbgen,
                      vector<double>& t_search, vector<double>& t_update, vector<double>& t_revoke){

    cout << "################################################################################################" << endl;
    cout << "Parameter setting: ";
    cout << "NUM_DOCS " << NUM_DOCS;
    cout << ", NUM_KEYWORDS " << NUM_KEYWORDS;
    cout << ", NUM_USERS " << NUM_USERS;
    cout << ", NUM_ATTRS " << NUM_ATTRS;
    int DB_SIZE = 0;

    auto t_start = std::chrono::high_resolution_clock::now();
    string attr_universe[NUM_ATTRS];
    unordered_map<string, vector<uint32_t>> inverted_index; //store list of id files corresponding to keywords
    unordered_map<string, vector<uint32_t>> attr_users;
    unordered_map<string, vector<string>> attr_keywords;
    unordered_map<string, vector<string>> keyword_attrs;

    //create list of attributes
    for (int i = 0; i < NUM_ATTRS; i++)
        attr_universe[i] = "attribute" + to_string(i);


    //create unordered_map inverted_index: keyword_i for list of docs
    int num_kwtypes = log2(NUM_DOCS);
    int num_kw_per_type = NUM_KEYWORDS / num_kwtypes;
    int kw_idx;

    for (int i = 0; i < num_kwtypes; i++)
        for (int k = 0; k < num_kw_per_type; k++)
            for (int j = 0; j < NUM_DOCS / (exp2(i)); j++){
                kw_idx = i*num_kw_per_type+k;
                inverted_index[to_string(i*num_kw_per_type+k)].emplace_back(j);
                DB_SIZE++;
            }
    for (int i = kw_idx + 1; i < NUM_KEYWORDS; i++) {
        inverted_index[to_string(i)].emplace_back(0);
        DB_SIZE++;
    }

    cout << ", DB_SIZE (# of (keyword-doc) pairs): " << DB_SIZE;
    cout << endl;

    //create unordered_map attr_users: attr i has authorized users {0 --> NUM_USERS/(i+1) - 1}
    for (int i = 0; i < NUM_ATTRS; i++)
        for (int j = 0; j < NUM_USERS/(i+1); j++)
            attr_users[attr_universe[i]].emplace_back(j);

    //create unordered_map attr_keywords: attr i has keywords {step*i --> step*(i+1) - 1}
    int step = NUM_KEYWORDS / NUM_ATTRS;
    for (int i = 0; i < NUM_ATTRS; i++)
        for (int j = 0; j < step; j++) {
            attr_keywords[attr_universe[i]].emplace_back(to_string(step * i + j));
            keyword_attrs[to_string(step * i + j)].emplace_back(attr_universe[i]);
        }
    IOTSSEDBOwner *dbowner = new IOTSSEDBOwner(NUM_USERS, NUM_DOCS, attr_universe, NUM_ATTRS, attr_users, attr_keywords, keyword_attrs, inverted_index);
    //create users
    IOTSSEUser **u = new IOTSSEUser*[NUM_USERS];
    for (int i = 0; i < NUM_USERS; i++)
        u[i] = new IOTSSEUser(i, dbowner);
    auto t_end = std::chrono::high_resolution_clock::now();
    double elapsed_time_ms = std::chrono::duration<double, std::milli>(t_end-t_start).count();
    cout << "Setup time: " << elapsed_time_ms << " milliseconds" << endl;
    t_setup.push_back(elapsed_time_ms);


    cout << "################################################################################################" << endl;
    t_start = std::chrono::high_resolution_clock::now();
    dbowner->generate_encrypted_db();
    t_end = std::chrono::high_resolution_clock::now();
    elapsed_time_ms = std::chrono::duration<double, std::milli>(t_end-t_start).count();
    cout << "EDB generation time: " << elapsed_time_ms << " milliseconds" << endl;
    t_dbgen.push_back(elapsed_time_ms);

    //Test query: User 0 (who is authorized for all queries) queries 1000 random each keyword. Time is averaged
    cout << "################################################################################################" << endl;
    vector<uint32_t> query_res;
    t_start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        string keyword = to_string(rand() % NUM_KEYWORDS);
        //int user = rand() % NUM_USERS;
//        cout << "Keyword: " << keyword << ", Att: " << keyword_attrs[keyword][0] << endl;
//        cout << "attr-users: ";
//        print_vector(attr_users[keyword_attrs[keyword][0]]);
        query_res.clear();
        u[0]->query(keyword, query_res);
//        cout << "Query_res's size: " << query_res.size() << endl;
//        cout << inverted_index[keyword].size() << endl;
    }

    t_end = std::chrono::high_resolution_clock::now();
    elapsed_time_ms = std::chrono::duration<double, std::milli>(t_end-t_start).count();
    cout << "Average query time: " << elapsed_time_ms / 1000 << " milliseconds" << endl;
    t_search.push_back(elapsed_time_ms / 1000);

    //Test DB update: (DEL then INS for keyword "0"
    cout << "################################################################################################" << endl;
    t_start = std::chrono::high_resolution_clock::now();
    vector<uint32_t> f_up;
    f_up.push_back(0);
    for (int i = 0; i < 1000; i++) {
        string keyword = to_string(rand() % NUM_KEYWORDS);
        dbowner->update_db(f_up, keyword); // remove file i from keyword 0's result
    }
    t_end = std::chrono::high_resolution_clock::now();
    elapsed_time_ms = std::chrono::duration<double, std::milli>(t_end-t_start).count();
    cout << "Average update time: " << elapsed_time_ms / 1000 << " milliseconds" << endl;
    t_update.push_back(elapsed_time_ms / 1000);

    //Test user revocation: Randomize keyword for revocation 100 times. After revocation, only first half are authorized
    cout << "################################################################################################" << endl;
    vector<uint32_t> non_revoked_users;
    for (int i = 0; i < NUM_USERS / 2; i++)
        non_revoked_users.push_back(i);

    t_start = std::chrono::high_resolution_clock::now();
    for (int k = 0; k < 1000; k++) {
        string keyword = to_string(rand() % NUM_KEYWORDS);
        //keyword = "0";
        dbowner->revoke_users(keyword, non_revoked_users);
    }
    t_end = std::chrono::high_resolution_clock::now();
    elapsed_time_ms = std::chrono::duration<double, std::milli>(t_end-t_start).count();
    cout << "Average revocation time: " << elapsed_time_ms / 1000 << " milliseconds" << endl;
    t_revoke.push_back(elapsed_time_ms / 1000);

}

void evaluate(){
//    double num_kws[8] = {1e2, 5e2, 1e3, 5e3,1e4, 5e4,1e5, 5e5};;
    double num_kws[10] = {1e2, 2e2, 3e2,4e2,5e2, 6e2, 7e2, 8e2, 9e2, 1e3};
    double num_docs[9] = {1e2, 5e2, 1e3, 5e3,1e4, 5e4,1e5, 5e5, 1e6};
    double num_users[9] = {1e2, 5e2, 1e3, 5e3,1e4, 5e4, 1e5, 5e5, 1e6};

    vector<double> t_setup, t_dbgen, t_search, t_update, t_revoke;

//    // Varying No of users
//    cout << "Varying No of users |U|, |D| = 10^5, |W| = 10^3" << endl;
//
//    int NUM_ATTRS = 100;
//    int NUM_DOCS = 100000;
//    int NUM_KEYWORDS = 1000;
//    int NUM_USERS;
//
//    for (int i = 0; i < 7; i++){
//        NUM_USERS = num_users[i];
//        test_performance(NUM_ATTRS, NUM_KEYWORDS, NUM_DOCS, NUM_USERS, t_setup, t_dbgen, t_search, t_update, t_revoke);
//    }
//    print_vector(t_setup);
//    print_vector(t_dbgen);
//    print_vector(t_search);
//    print_vector(t_update);
//    print_vector(t_revoke);


//    // Varying No of documents
//    cout << "Varing No of supported documents L" << endl;
//
//    int NUM_ATTRS = 100;
//    int NUM_USERS = 100;
//    int NUM_KEYWORDS = 1000;
//    int NUM_DOCS;
//
//    for (int i = 0; i < 7; i++){
//        NUM_DOCS = num_docs[i];
//        test_performance(NUM_ATTRS, NUM_KEYWORDS, NUM_DOCS, NUM_USERS, t_setup, t_dbgen, t_search, t_update, t_revoke);
//    }
//    print_vector(t_setup);
//    print_vector(t_dbgen);
//    print_vector(t_search);
//    print_vector(t_update);
//    print_vector(t_revoke);


    // Varying No of keywords
    cout << "Varing No of keywords |W|" << endl;

    int NUM_ATTRS = 100;
    int NUM_USERS = 100;
    int NUM_DOCS = 100000;
    int NUM_KEYWORDS;

    for (int i = 0; i < 10; i++){
        NUM_KEYWORDS = num_kws[i];
        test_performance(NUM_ATTRS, NUM_KEYWORDS, NUM_DOCS, NUM_USERS, t_setup, t_dbgen, t_search, t_update, t_revoke);
    }
    print_vector(t_setup);
    print_vector(t_dbgen);
    print_vector(t_search);
    print_vector(t_update);
    print_vector(t_revoke);



}


void test_compare(int NUM_ATTRS, int NUM_KEYWORDS, int NUM_DOCS, int NUM_USERS,
                      vector<double>& t_setup, vector<double>& t_dbgen,
                      vector<double>& t_search, vector<double>& t_update, vector<double>& t_revoke){

    cout << "################################################################################################" << endl;
    cout << "Parameter setting: ";
    cout << "NUM_DOCS " << NUM_DOCS;
    cout << ", NUM_KEYWORDS " << NUM_KEYWORDS;
    cout << ", NUM_USERS " << NUM_USERS;
    cout << ", NUM_ATTRS " << NUM_ATTRS;
    int DB_SIZE = 0;

    auto t_start = std::chrono::high_resolution_clock::now();
    string attr_universe[NUM_ATTRS];
    unordered_map<string, vector<uint32_t>> inverted_index; //store list of id files corresponding to keywords
    unordered_map<string, vector<uint32_t>> attr_users;
    unordered_map<string, vector<string>> attr_keywords;
    unordered_map<string, vector<string>> keyword_attrs;

    //create list of attributes
    for (int i = 0; i < NUM_ATTRS; i++)
        attr_universe[i] = "attribute" + to_string(i);

    //create unordered_map inverted_index: keyword_i for list of docs {0 --> DB_SIZE/(i+1) - 1}
//    for (int i = 0; i < NUM_KEYWORDS; i++)
//        for (int j = 0; j < 1 + NUM_DOCS/(i+1); j++) {
//            inverted_index[to_string(i)].emplace_back(j);
//            DB_SIZE++;
//        }
//

    //create unordered_map inverted_index: keyword_i for list of docs
    int num_kwtypes = log2(NUM_DOCS);
    int num_kw_per_type = NUM_KEYWORDS / num_kwtypes;
    int kw_idx;
    if (NUM_KEYWORDS < num_kwtypes)
        num_kw_per_type = 1;
    else
        num_kw_per_type = NUM_KEYWORDS / num_kwtypes;
    for (int i = 0; i < num_kwtypes; i++)
        for (int k = 0; k < num_kw_per_type; k++)
            for (int j = 0; j < NUM_DOCS / (exp2(i)); j++){
                kw_idx = i*num_kw_per_type+k;
                inverted_index[to_string(i*num_kw_per_type+k)].emplace_back(j);
                if (DB_SIZE == NUM_KEYWORDS)
                    break;
                else
                    DB_SIZE++;
            }
    for (int i = kw_idx + 1; i < NUM_KEYWORDS; i++) {
        inverted_index[to_string(i)].emplace_back(0);
        if (DB_SIZE == NUM_KEYWORDS)
            break;
        else
            DB_SIZE++;
    }

    cout << ", DB_SIZE (# of (keyword-doc) pairs): " << DB_SIZE;
    cout << endl;

    //create unordered_map attr_users: attr i has authorized users {0 --> NUM_USERS/(i+1) - 1}
    for (int i = 0; i < NUM_ATTRS; i++)
        for (int j = 0; j < NUM_USERS/(i+1); j++)
            attr_users[attr_universe[i]].emplace_back(j);

    //create unordered_map attr_keywords: attr i has keywords {step*i --> step*(i+1) - 1}
    int step = NUM_KEYWORDS / NUM_ATTRS;
    for (int i = 0; i < NUM_ATTRS; i++)
        for (int j = 0; j < step; j++) {
            attr_keywords[attr_universe[i]].emplace_back(to_string(step * i + j));
            keyword_attrs[to_string(step * i + j)].emplace_back(attr_universe[i]);
        }
    IOTSSEDBOwner *dbowner = new IOTSSEDBOwner(NUM_USERS, NUM_DOCS, attr_universe, NUM_ATTRS, attr_users, attr_keywords, keyword_attrs, inverted_index);
    //create users
    IOTSSEUser **u = new IOTSSEUser*[NUM_USERS];
    for (int i = 0; i < NUM_USERS; i++)
        u[i] = new IOTSSEUser(i, dbowner);
    auto t_end = std::chrono::high_resolution_clock::now();
    double elapsed_time_ms = std::chrono::duration<double, std::milli>(t_end-t_start).count();
    cout << "Setup time: " << elapsed_time_ms << " milliseconds" << endl;
    t_setup.push_back(elapsed_time_ms);


    cout << "################################################################################################" << endl;
    t_start = std::chrono::high_resolution_clock::now();
    dbowner->generate_encrypted_db();
    t_end = std::chrono::high_resolution_clock::now();
    elapsed_time_ms = std::chrono::duration<double, std::milli>(t_end-t_start).count();
    cout << "EDB generation time: " << elapsed_time_ms << " milliseconds" << endl;
    t_dbgen.push_back(elapsed_time_ms);

    //Test query: User 0 (who is authorized for all queries) queries 1000 random each keyword. Time is averaged
    cout << "################################################################################################" << endl;
    vector<uint32_t> query_res;
    t_start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        string keyword = to_string(rand() % NUM_KEYWORDS);
        //int user = rand() % NUM_USERS;
//        cout << "Keyword: " << keyword << ", Att: " << keyword_attrs[keyword][0] << endl;
//        cout << "attr-users: ";
//        print_vector(attr_users[keyword_attrs[keyword][0]]);
        query_res.clear();
        u[0]->query(keyword, query_res);
//        cout << "Query_res's size: " << query_res.size() << endl;
//        cout << inverted_index[keyword].size() << endl;
    }

    t_end = std::chrono::high_resolution_clock::now();
    elapsed_time_ms = std::chrono::duration<double, std::milli>(t_end-t_start).count();
    cout << "Average query time: " << elapsed_time_ms / 1000 << " milliseconds" << endl;
    t_search.push_back(elapsed_time_ms / 1000);

    //Test DB update: (DEL then INS for keyword "0"
    cout << "################################################################################################" << endl;
    t_start = std::chrono::high_resolution_clock::now();
    vector<uint32_t> f_up;
    f_up.push_back(0);
    for (int i = 0; i < 1000; i++) {
        string keyword = to_string(rand() % NUM_KEYWORDS);
        //       keyword = "30";
        //cout << "i = " << i << ", keyword = " << keyword << endl;
//        if (keyword == "30")
//            print_vector(f_up);
        //keyword = "0";
        dbowner->update_db(f_up, keyword); // remove file i from keyword 0's result
    }
    t_end = std::chrono::high_resolution_clock::now();
    elapsed_time_ms = std::chrono::duration<double, std::milli>(t_end-t_start).count();
    cout << "Average update time: " << elapsed_time_ms / 1000 << " milliseconds" << endl;
    t_update.push_back(elapsed_time_ms / 1000);

    //Test user revocation: Randomize keyword for revocation 100 times. After revocation, only first half are authorized
    cout << "################################################################################################" << endl;
    vector<uint32_t> non_revoked_users;
    for (int i = 0; i < NUM_USERS / 2; i++)
        non_revoked_users.push_back(i);

    t_start = std::chrono::high_resolution_clock::now();
    for (int k = 0; k < 1000; k++) {
        string keyword = to_string(rand() % NUM_KEYWORDS);
        //keyword = "0";
        dbowner->revoke_users(keyword, non_revoked_users);
    }
    t_end = std::chrono::high_resolution_clock::now();
    elapsed_time_ms = std::chrono::duration<double, std::milli>(t_end-t_start).count();
    cout << "Average revocation time: " << elapsed_time_ms / 1000 << " milliseconds" << endl;
    t_revoke.push_back(elapsed_time_ms / 1000);

}

void compare(){
    cout << "Compare " << endl;
    double num_kws[9] = {1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10};
//    double num_kws[10] = {1e2, 2e2, 3e2,4e2,5e2, 6e2, 7e2, 8e2, 9e2, 1e3};
    double num_docs[9] = {1e2, 5e2, 1e3, 5e3,1e4, 5e4,1e5, 5e5, 1e6};
    double num_users[9] = {1e2, 5e2, 1e3, 5e3,1e4, 5e4, 1e5, 5e5, 1e6};

    vector<double> t_setup, t_dbgen, t_search, t_update, t_revoke;

    // Varying No of keywords
    cout << "Varing No of keywords |W|" << endl;

    int NUM_ATTRS = 100;
    int NUM_USERS = 100;
    int NUM_DOCS = 1000;
    int NUM_KEYWORDS;

    for (int i = 0; i < size(num_kws); i++){
        NUM_KEYWORDS = num_kws[i];
        test_compare(NUM_ATTRS, NUM_KEYWORDS, NUM_DOCS, NUM_USERS, t_setup, t_dbgen, t_search, t_update, t_revoke);
    }
    print_vector(t_setup);
    print_vector(t_dbgen);
    print_vector(t_search);
    print_vector(t_update);
    print_vector(t_revoke);



}

int main(){
    //test_accuracy();
//    evaluate();
    compare();
}

