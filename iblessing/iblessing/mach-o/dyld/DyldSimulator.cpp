//
//  DyldSimulator.cpp
//  iblessing
//
//  Created by soulghost on 2020/4/27.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "DyldSimulator.hpp"

#define printf(fmt, ...)

using namespace std;
using namespace iblessing;

static uintptr_t read_uleb128(const uint8_t*& p, const uint8_t* end)
{
    uint64_t result = 0;
    int         bit = 0;
    do {
        if (p == end)
            printf("[-] malformed uleb128\n");

        uint64_t slice = *p & 0x7f;

        if (bit > 63)
            printf("[-] uleb128 too big for uint64, bit=%d, result=0x%0llX\n", bit, result);
        else {
            result |= (slice << bit);
            bit += 7;
        }
    } while (*p++ & 0x80);
    return result;
}

static intptr_t read_sleb128(const uint8_t*& p, const uint8_t* end)
{
    int64_t result = 0;
    int bit = 0;
    uint8_t byte;
    do {
        if (p == end)
            printf("[-] malformed sleb128\n");
        byte = *p++;
        result |= (((int64_t)(byte & 0x7f)) << bit);
        bit += 7;
    } while (byte & 0x80);
    // sign extend negative numbers
    if ( (byte & 0x40) != 0 )
        result |= (-1LL) << bit;
    return result;
}


bool DyldSimulator::eachBind(uint8_t *mappedData, std::vector<struct ib_segment_command_64 *> segmentHeaders, ib_dyld_info_command *dyldinfo, DyldBindHandler handler) {
    uint32_t bind_off = dyldinfo->bind_off;
    uint32_t bind_size = dyldinfo->bind_size;
    const uint8_t * const bind_start = mappedData + bind_off;
    const uint8_t * const bind_end = bind_start + bind_size;
    const uint8_t * p = bind_start;
    bool done = false;
    uint64_t libraryOrdinal = 0;
    const char *symbolName = NULL;
    uint8_t symbolFlags = 0;
    uint8_t type = 0;
    uint64_t addend = 0;
    uint32_t segmentIndex = 0;
    uint64_t segmentEndAddress = 0;
    uint64_t address = 0;
    while (!done && (p < bind_end)) {
        uint8_t immediate = *p & IB_BIND_IMMEDIATE_MASK;
        uint8_t opcode = *p & IB_BIND_OPCODE_MASK;
        ++p;
        switch (opcode) {
            case IB_BIND_OPCODE_DONE:
                done = true;
                printf("[+] bind info parsed done\n");
                break;
            case IB_BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                libraryOrdinal = immediate;
                printf("[+] set dylib ordinal to %lld\n", libraryOrdinal);
                break;
            case IB_BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                libraryOrdinal = read_uleb128(p, bind_end);
                break;
            case IB_BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                // the special ordinals are negative numbers
                if ( immediate == 0 )
                    libraryOrdinal = 0;
                else {
                    int8_t signExtended = IB_BIND_OPCODE_MASK | immediate;
                    libraryOrdinal = signExtended;
                }
                break;
            case IB_BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                symbolName = (char*)p;
                symbolFlags = immediate;
                while (*p != '\0')
                    ++p;
                ++p;
                break;
            case IB_BIND_OPCODE_SET_TYPE_IMM:
                type = immediate;
                break;
            case IB_BIND_OPCODE_SET_ADDEND_SLEB:
                addend = read_sleb128(p, bind_end);
                break;
            case IB_BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                segmentIndex = immediate;
                if ( segmentIndex >= segmentHeaders.size() )
                    printf("[-]BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB has segment %d which is too large (0..%lu)\n",
                            segmentIndex, segmentHeaders.size() - 1);
                address = segmentHeaders[segmentIndex]->vmaddr + read_uleb128(p, bind_end);
                segmentEndAddress = address + segmentHeaders[segmentIndex]->vmsize;
                break;
            case IB_BIND_OPCODE_ADD_ADDR_ULEB:
                address += read_uleb128(p, bind_end);
                break;
            case IB_BIND_OPCODE_DO_BIND:
                if ( address >= segmentEndAddress ) {
                    printf("[-] address exceeded segment range\n");
                    return false;
                }
                   
                printf("[+] bind symbol %s at 0x%llx, and address + 8\n", symbolName, address);
                handler(address, type, symbolName, symbolFlags, addend, libraryOrdinal, "");
                address += sizeof(intptr_t);
                break;
            case IB_BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
                if ( address >= segmentEndAddress ) {
                    printf("[-] address exceeded segment range\n");
                    return false;
                }
                
                printf("[+] bind symbol %s at 0x%llx, and address + offset\n", symbolName, address);
                handler(address, type, symbolName, symbolFlags, addend, libraryOrdinal, "");
                address += read_uleb128(p, bind_end) + sizeof(intptr_t);
                break;
            case IB_BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
                if ( address >= segmentEndAddress ) {
                    printf("[-] address exceeded segment range\n");
                    return false;
                }
                
                printf("[+] bind symbol %s at 0x%llx, and address + immediate * 8 + 8 (scaled)\n", symbolName, address);
                handler(address, type, symbolName, symbolFlags, addend, libraryOrdinal, "");
                address += immediate*sizeof(intptr_t) + sizeof(intptr_t);
                break;
            case IB_BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
                uint64_t count = read_uleb128(p, bind_end);
                uint64_t skip = read_uleb128(p, bind_end);
                for (uint32_t i=0; i < count; ++i) {
                    if ( address >= segmentEndAddress )
                        if ( address >= segmentEndAddress ) {
                            printf("[-] address exceeded segment range\n");
                            return false;
                        }
                    printf("[+] bind symbol %s at 0x%llx, and address + immediate * 8 + 8 (scaled)\n", symbolName, address);
                    handler(address, type, symbolName, symbolFlags, addend, libraryOrdinal, "");
                    address += skip + sizeof(intptr_t);
                }
                break;
        }
    }
    return true;
}
