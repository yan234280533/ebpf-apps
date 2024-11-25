//
// Created by devin on 24-11-25.
//

#ifndef MKDIR_H
#define MKDIR_H

struct trace {
    unsigned int tgid;
    unsigned int action;  // system call number
    unsigned long ts;
    long ret;
    int ready;  // // 0: empty or writing; 1: readable; 2: useless
};

#endif //MKDIR_H
