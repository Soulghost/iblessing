//
//  ProgramStateManager.cpp
//  iblessing
//
//  Created by soulghost on 2020/9/18.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "ProgramStateManager.hpp"

using namespace std;
using namespace iblessing;

bool ProgramStateManager::enqueueState(shared_ptr<ProgramState> &state) {
    if (visitedPc.find(state->pc) != visitedPc.end()) {
        return false;
    }
    
    visitedPc.insert(state->pc);
    stateQueue.push(state);
    return true;
}

shared_ptr<ProgramState> ProgramStateManager::popState() {
    if (stateQueue.empty()) {
        return nullptr;
    }
    
    shared_ptr<ProgramState> state = stateQueue.front();
    stateQueue.pop();
    return state;
}

bool ProgramStateManager::isEmpty() {
    return stateQueue.empty();
}
