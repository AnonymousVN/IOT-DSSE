//
// Created by Hong Yen Tran on 19/11/22.
//

#ifndef IOTSSE_IOTSSEUSER_H
#define IOTSSE_IOTSSEUSER_H

#include "IOTSSEServer.h"
#include "IOTSSEDBOwner.h"

class IOTSSEUser {
//private:
public:
    uint32_t uid;
    IOTSSEDBOwner* dbowner;
    unordered_map<uint32_t, uint8_t*> u_node_key;

//public:
    // public information
    IOTSSEUser(uint32_t uid, IOTSSEDBOwner* dbowner);
    ~IOTSSEUser();
    void get_nodes_keys();
    void query(const string& keyword, vector<uint32_t>& res_list);
};


#endif //IOTSSE_IOTSSEUSER_H
