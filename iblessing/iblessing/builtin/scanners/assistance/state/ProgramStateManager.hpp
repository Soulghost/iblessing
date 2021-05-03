//
//  ProgramStateManager.hpp
//  iblessing
//
//  Created by soulghost on 2020/9/18.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ProgramStateManager_hpp
#define ProgramStateManager_hpp

#include "ProgramState.hpp"
#include <queue>
#include <set>
#include <memory>

NS_IB_BEGIN

class ProgramStateManager {
public:
    bool enqueueState(std::shared_ptr<ProgramState> &state);
    std::shared_ptr<ProgramState> popState();
    bool isEmpty();
    
private:
    std::queue<std::shared_ptr<ProgramState>> stateQueue;
    std::set<uint64_t> visitedPc;
};

NS_IB_END

#endif /* ProgramStateManager_hpp */
