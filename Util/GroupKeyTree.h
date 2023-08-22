//
// Created by Shangqi on 17/5/22.
//

#ifndef IOTSSE_GROUPKEYTREE_H
#define IOTSSE_GROUPKEYTREE_H

#include <cmath>
#include <openssl/rand.h>

#include "CommonUtils.h"
#include "GGMNode.h"

class GroupKeyTree {
//private:
public:
    uint32_t size;
    uint32_t depth;
    uint32_t *labels;
    uint8_t **keys;

    uint32_t get_position_on_path(uint32_t uid, int p_depth) const {
        uint32_t pos = uid + size / 2;
        for (int d = depth; d >= p_depth + 1; d--) {
            pos = (pos + 1) / 2 - 1;
        }
        return pos;
    }

    vector<GGMNode> min_coverage(const vector<GGMNode>& pos_list) {
        vector<GGMNode> next_level_node;
        for (int i = 0; i < pos_list.size(); i++) {
            auto node1 = pos_list[i];

            if(i + 1 == pos_list.size()) {
                next_level_node.emplace_back(node1);
            } else {
                auto node2 = pos_list[i + 1];
                // same parent in the binary path (node index 2k+1 and 2k+2 has the same parent k)
                if((((node1.index - 1) >> 1) == ((node2.index - 1) >> 1)) && (node1.level == node2.level)) {
                    next_level_node.emplace_back(GGMNode(node1.id,
                                                         get_position_on_path(node1.id, node1.level - 1),
                                                         node1.level - 1));
                    i++;
                } else {
                    next_level_node.emplace_back(node1);
                }
            }
        }

        // no merge return
        if (next_level_node.size() == pos_list.size() || next_level_node.empty()) {
            return pos_list;
        }

        return min_coverage(next_level_node);
    }




//public:

    GroupKeyTree(uint8_t *MSK, uint32_t user_size) {
        this->depth = ceil(log2(user_size));
        this->size = pow(2, this->depth + 1) - 1;
        this->labels = new uint32_t[this->size];
        this->keys = new uint8_t*[this->size]; //allocate an array of 'size' elements. Each element stores the address to uint8_t
        for (int i = 0; i < size; i++) {
            // assign a random label to the node
            RAND_bytes((uint8_t*) (this->labels + i), sizeof(uint32_t));
            // derive the node key from the label
            this->keys[i] = new uint8_t[BLOCK_SIZE];
            aes_cmac((uint8_t*) (this->labels + i), sizeof(uint32_t),MSK,this->keys[i]);
        }
    }

    ~GroupKeyTree() {
        for (int i = 0; i < size; i++) {
            delete this->keys[i];
            this->keys[i] = nullptr;
        }
        delete this->keys;
        this->keys = nullptr;
    }


    // fetch a path of keys with given uid
    void fetch_path_keys(uint32_t uid, uint8_t **key_list) {
        // fetch #depth keys
        for (int d = 0; d <= depth; d++) {
            //cout << get_position_on_path(uid, d) << endl;
            key_list[d] = new uint8_t[BLOCK_SIZE];
            memcpy(key_list[d], keys[get_position_on_path(uid, d)], BLOCK_SIZE);
//            if (uid == 8){
//                cout << "keys " << get_position_on_path(uid, d) << ": ";
//                print_key(key_list[d]);
//                print_key(keys[get_position_on_path(uid, d)]);
//            }
        }
    }

    void fetch_path(uint32_t uid, vector<uint32_t>& node_list) {
        // fetch #depth nodes
        for (int d = 0; d <= depth; d++) {
            node_list.push_back(get_position_on_path(uid, d));
            //cout << node_list[d];
        }

    }

    void min_coverage_key(unordered_map<uint32_t, uint8_t[BLOCK_SIZE]>& t_node_key, const vector<uint32_t> uid_list) {
        // convert uid_list to position
        vector<GGMNode> pos_list;
        for (unsigned int uid : uid_list) {
            pos_list.emplace_back(GGMNode(uid, get_position_on_path(uid, this->depth), this->depth));
        }
        // find the minimum coverage set
        vector<GGMNode> min_coverage_list = min_coverage(pos_list);
        // keys in SubRootedTrees
        for (GGMNode node: min_coverage_list)
            memcpy(t_node_key[node.index], keys[node.index], BLOCK_SIZE);
    }

    [[nodiscard]]
    uint32_t get_depth() const {
        return depth;
    }
    void print_key(uint8_t * key){
        for (int i = 0; i < BLOCK_SIZE; i++)
            cout << (int) key[i]  << " ";
        cout << endl;
    }
};

#endif //IOTSSE_GROUPKEYTREE_H
