//
// Created by Shangqi on 31/8/22.
//

#ifndef IOTSSE_GGMNODE_H
#define IOTSSE_GGMNODE_H

class GGMNode {
public:
    uint32_t id;
    long index;
    int level;

    GGMNode(uint32_t id, long index, int level) {
        this->id = id;
        this->index = index;
        this->level = level;
    }
};

#endif //IOTSSE_GGMNODE_H
