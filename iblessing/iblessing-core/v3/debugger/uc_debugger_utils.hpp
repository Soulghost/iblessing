//
//  uc_debugger_utils.hpp
//  iblessing-core
//
//  Created by soulghost on 2021/10/5.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef uc_debugger_utils_hpp
#define uc_debugger_utils_hpp

#include <iblessing-core/v2/common/ibtypes.h>
#include <iblessing-core/v2/vendor/unicorn/unicorn.h>
#include <iblessing-core/v3/mach-o/macho-loader.hpp>

extern std::shared_ptr<iblessing::MachOLoader> _defaultLoader;

void print_uc_mem_regions(uc_engine *uc);
void print_backtrace(uc_engine *uc, std::shared_ptr<iblessing::MachOLoader> loader = nullptr, bool beforePrologue = false);

void uc_debug_print_backtrace(uc_engine *uc, bool beforePrologue = false);
void uc_debug_print_memory(uc_engine *uc, uint64_t addr, int format, int count);
void uc_debug_set_breakpoint(uc_engine *uc, uint64_t address, std::string desc = "");
bool uc_debug_check_breakpoint(uc_engine *uc, uint64_t address);
void uc_debug_breakhere(uc_engine *uc, std::string desc = "");

#endif /* uc_debugger_utils_hpp */
