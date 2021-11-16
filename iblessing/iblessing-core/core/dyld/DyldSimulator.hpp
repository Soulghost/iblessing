//
//  DyldSimulator.hpp
//  iblessing
//
//  Created by soulghost on 2020/4/27.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef DyldSimulator_hpp
#define DyldSimulator_hpp

#include <vector>
#include <iblessing-core/infra/Object.hpp>
#include <iblessing-core/core/polyfill/mach-universal.hpp>
#include <iblessing-core/v3/dyld/dyld-sharedcache-loader.hpp>

typedef std::function<void (uint64_t addr, uint8_t type, const char *symbolName, uint8_t symbolFlags, uint64_t addend, int64_t libraryOrdinal, const char *msg)> DyldBindHandler;
typedef std::function<void (uint64_t addr, uint64_t slide, uint8_t type)> DyldRebaseHandler;

NS_IB_BEGIN

struct Entry
{
    const char*        name;
    uint64_t        address;
    uint64_t        flags;
    uint64_t        other;
    const char*        importName;
};

struct EntryWithOffset
{
    uintptr_t        nodeOffset;
    Entry            entry;
    
    bool operator<(const EntryWithOffset& other) const { return ( nodeOffset < other.nodeOffset ); }
};

class DyldSimulator {
public:
    static bool eachBind(uint8_t *mappedData, std::vector<struct ib_segment_command_64 *> segmentHeaders, ib_dyld_info_command *dyldinfo, DyldBindHandler handler);
    static void doRebase(uint64_t moduleBase, uint64_t moduleSize, uint8_t *mappedData, std::vector<struct ib_segment_command_64 *> segmentHeaders, ib_dyld_info_command *dyldinfo, DyldRebaseHandler handler);
    static void doRebase(DyldLinkContext linkContext, uint64_t moduleBase, uint64_t moduleSize, std::vector<struct ib_segment_command_64 *> segmentHeaders, ib_dyld_info_command *dyldinfo, DyldRebaseHandler handler);
    static void processExportNode(const uint8_t* const start, const uint8_t* p, const uint8_t* const end,
                                        char* cummulativeString, int curStrOffset,
                                          std::vector<EntryWithOffset>& output);
};

NS_IB_END

#endif /* DyldSimulator_hpp */
