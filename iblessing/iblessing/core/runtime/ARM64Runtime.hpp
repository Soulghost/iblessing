//
//  ARM64Runtime.hpp
//  iblessing
//
//  Created by soulghost on 2020/2/23.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ARM64Runtime_hpp
#define ARM64Runtime_hpp

#include <iblessing/infra/Object.hpp>
#include <capstone/capstone.h>

NS_IB_BEGIN

class ARM64Runtime {
public:
    static bool handleInstruction(cs_insn *insn, std::string *insnDesc = nullptr, std::string *insnComment = nullptr, bool fatal = true);
    static bool handleSTP(cs_insn *insn, std::string *insnDesc, std::string *insnComment, bool fatal = true);
    static bool handleSTR(cs_insn *insn, std::string *insnDesc, std::string *insnComment, bool fatal = true);
    static bool handleADD(cs_insn *insn, std::string *insnDesc, std::string *insnComment, bool fatal = true);
    static bool handleADRP(cs_insn *insn, std::string *insnDesc, std::string *insnComment, bool fatal = true);
    static bool handleLDR(cs_insn *insn, std::string *insnDesc, std::string *insnComment, bool swMode = false, bool fatal = true);
    static bool handleADR(cs_insn *insn, std::string *insnDesc, std::string *insnComment, bool fatal = true);
    static bool handleMOV(cs_insn *insn, std::string *insnDesc, std::string *insnComment, bool fatal = true);
    static bool isRET(cs_insn *insn);
};

NS_IB_END

#endif /* ARM64Runtime_hpp */
