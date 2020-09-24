//
//  mach-universal.hpp
//  iblessing
//
//  Created by Soulghost on 2020/8/9.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef mach_universal_hpp
#define mach_universal_hpp

#include <cstdio>
#include <unistd.h>
#include <cstdint>

/*
* The load commands directly follow the mach_header.  The total size of all
* of the commands is given by the sizeofcmds field in the mach_header.  All
* load commands must have as their first two fields cmd and cmdsize.  The cmd
* field is filled in with a constant for that command type.  Each command type
* has a structure specifically for it.  The cmdsize field is the size in bytes
* of the particular load command structure plus anything that follows it that
* is a part of the load command (i.e. section structures, strings, etc.).  To
* advance to the next load command the cmdsize can be added to the offset or
* pointer of the current load command.  The cmdsize for 32-bit architectures
* MUST be a multiple of 4 bytes and for 64-bit architectures MUST be a multiple
* of 8 bytes (these are forever the maximum alignment of any load commands).
* The padded bytes must be zero.  All tables in the object file must also
* follow these rules so the file can be memory mapped.  Otherwise the pointers
* to these tables will not work well or at all on some machines.  With all
* padding zeroed like objects will compare byte for byte.
*/
struct ib_load_command {
    uint32_t cmd;        /* type of load command */
    uint32_t cmdsize;    /* total size of command in bytes */
};

/*
 * After MacOS X 10.1 when a new load command is added that is required to be
 * understood by the dynamic linker for the image to execute properly the
 * LC_REQ_DYLD bit will be or'ed into the load command constant.  If the dynamic
 * linker sees such a load command it it does not understand will issue a
 * "unknown load command required for execution" error and refuse to use the
 * image.  Other load commands without this bit that are not understood will
 * simply be ignored.
 */
#define IB_LC_REQ_DYLD 0x80000000

/* Constants for the cmd field of all load commands, the type */
#define    IB_LC_SEGMENT    0x1    /* segment of this file to be mapped */
#define    IB_LC_SYMTAB    0x2    /* link-edit stab symbol table info */
#define    IB_LC_SYMSEG    0x3    /* link-edit gdb symbol table info (obsolete) */
#define    IB_LC_THREAD    0x4    /* thread */
#define    IB_LC_UNIXTHREAD    0x5    /* unix thread (includes a stack) */
#define    IB_LC_LOADFVMLIB    0x6    /* load a specified fixed VM shared library */
#define    IB_LC_IDFVMLIB    0x7    /* fixed VM shared library identification */
#define    IB_LC_IDENT    0x8    /* object identification info (obsolete) */
#define    IB_LC_FVMFILE    0x9    /* fixed VM file inclusion (internal use) */
#define    IB_LC_PREPAGE      0xa     /* prepage command (internal use) */
#define    IB_LC_DYSYMTAB    0xb    /* dynamic link-edit symbol table info */
#define    IB_LC_LOAD_DYLIB    0xc    /* load a dynamically linked shared library */
#define    IB_LC_ID_DYLIB    0xd    /* dynamically linked shared lib ident */
#define    IB_LC_LOAD_DYLINKER 0xe    /* load a dynamic linker */
#define    IB_LC_ID_DYLINKER    0xf    /* dynamic linker identification */
#define    IB_LC_PREBOUND_DYLIB 0x10    /* modules prebound for a dynamically */
                /*  linked shared library */
#define    IB_LC_ROUTINES    0x11    /* image routines */
#define    IB_LC_SUB_FRAMEWORK 0x12    /* sub framework */
#define    IB_LC_SUB_UMBRELLA 0x13    /* sub umbrella */
#define    IB_LC_SUB_CLIENT    0x14    /* sub client */
#define    IB_LC_SUB_LIBRARY  0x15    /* sub library */
#define    IB_LC_TWOLEVEL_HINTS 0x16    /* two-level namespace lookup hints */
#define    IB_LC_PREBIND_CKSUM  0x17    /* prebind checksum */

/*
 * load a dynamically linked shared library that is allowed to be missing
 * (all symbols are weak imported).
 */
#define    IB_LC_LOAD_WEAK_DYLIB (0x18 | IB_LC_REQ_DYLD)

#define    IB_LC_SEGMENT_64    0x19    /* 64-bit segment of this file to be
                   mapped */
#define    IB_LC_ROUTINES_64    0x1a    /* 64-bit image routines */
#define    IB_LC_UUID        0x1b    /* the uuid */
#define    IB_LC_RPATH       (0x1c | IB_LC_REQ_DYLD)    /* runpath additions */
#define    IB_LC_CODE_SIGNATURE 0x1d    /* local of code signature */
#define    IB_LC_SEGMENT_SPLIT_INFO 0x1e /* local of info to split segments */
#define    IB_LC_REEXPORT_DYLIB (0x1f | IB_LC_REQ_DYLD) /* load and re-export dylib */
#define    IB_LC_LAZY_LOAD_DYLIB 0x20    /* delay load of dylib until first use */
#define    IB_LC_ENCRYPTION_INFO 0x21    /* encrypted segment information */
#define    IB_LC_DYLD_INFO     0x22    /* compressed dyld information */
#define    IB_LC_DYLD_INFO_ONLY (0x22|IB_LC_REQ_DYLD)    /* compressed dyld information only */
#define    IB_LC_LOAD_UPWARD_DYLIB (0x23 | IB_LC_REQ_DYLD) /* load upward dylib */
#define    IB_LC_VERSION_MIN_MACOSX 0x24   /* build for MacOSX min OS version */
#define    IB_LC_VERSION_MIN_IPHONEOS 0x25 /* build for iPhoneOS min OS version */
#define    IB_LC_FUNCTION_STARTS 0x26 /* compressed table of function start addresses */
#define    IB_LC_DYLD_ENVIRONMENT 0x27 /* string for dyld to treat
                    like environment variable */
#define    IB_LC_MAIN (0x28|IB_LC_REQ_DYLD) /* replacement for LC_UNIXTHREAD */
#define    IB_LC_DATA_IN_CODE 0x29 /* table of non-instructions in __text */
#define    IB_LC_SOURCE_VERSION 0x2A /* source version used to build binary */
#define    IB_LC_DYLIB_CODE_SIGN_DRS 0x2B /* Code signing DRs copied from linked dylibs */
#define    IB_LC_ENCRYPTION_INFO_64 0x2C /* 64-bit encrypted segment information */
#define    IB_LC_LINKER_OPTION 0x2D /* linker options in MH_OBJECT files */
#define    IB_LC_LINKER_OPTIMIZATION_HINT 0x2E /* optimization hints in MH_OBJECT files */
#define    IB_LC_VERSION_MIN_TVOS 0x2F /* build for AppleTV min OS version */
#define    IB_LC_VERSION_MIN_WATCHOS 0x30 /* build for Watch min OS version */
#define    IB_LC_NOTE 0x31 /* arbitrary data included within a Mach-O file */
#define    IB_LC_BUILD_VERSION 0x32 /* build for platform min OS version */
#define    IB_LC_DYLD_EXPORTS_TRIE (0x33 | IB_LC_REQ_DYLD) /* used with linkedit_data_command, payload is trie */
#define    IB_LC_DYLD_CHAINED_FIXUPS (0x34 | IB_LC_REQ_DYLD) /* used with linkedit_data_command */

/*
 * The 64-bit mach header appears at the very beginning of object files for
 * 64-bit architectures.
 */
struct ib_mach_header_64 {
    uint32_t    magic;        /* mach magic number identifier */
    int         cputype;    /* cpu specifier */
    int         cpusubtype;    /* machine specifier */
    uint32_t    filetype;    /* type of file */
    uint32_t    ncmds;        /* number of load commands */
    uint32_t    sizeofcmds;    /* the size of all the load commands */
    uint32_t    flags;        /* flags */
    uint32_t    reserved;    /* reserved */
};

struct ib_fat_header {
    uint32_t    magic;        /* FAT_MAGIC */
    uint32_t    nfat_arch;    /* number of structs that follow */
};

struct ib_fat_arch {
    int         cputype;    /* cpu specifier (int) */
    int         cpusubtype;    /* machine specifier (int) */
    uint32_t    offset;        /* file offset to this object file */
    uint32_t    size;        /* size of this object file */
    uint32_t    align;        /* alignment as a power of 2 */
};

/* Constant for the magic field of the mach_header_64 (64-bit architectures) */
#define IB_MH_MAGIC_64 0xfeedfacf /* the 64-bit mach magic number */
#define IB_MH_CIGAM_64 0xcffaedfe /* NXSwapInt(MH_MAGIC_64) */
#define IB_FAT_MAGIC   0xcafebabe
#define IB_FAT_CIGAM   0xbebafeca /* NXSwapLong(FAT_MAGIC) */

/*
 * The 64-bit segment load command indicates that a part of this file is to be
 * mapped into a 64-bit task's address space.  If the 64-bit segment has
 * sections then section_64 structures directly follow the 64-bit segment
 * command and their size is reflected in cmdsize.
 */
struct ib_segment_command_64 { /* for 64-bit architectures */
    uint32_t    cmd;        /* LC_SEGMENT_64 */
    uint32_t    cmdsize;    /* includes sizeof section_64 structs */
    char        segname[16];    /* segment name */
    uint64_t    vmaddr;        /* memory address of this segment */
    uint64_t    vmsize;        /* memory size of this segment */
    uint64_t    fileoff;    /* file offset of this segment */
    uint64_t    filesize;    /* amount to map from the file */
    int         maxprot;    /* maximum VM protection */
    int         initprot;    /* initial VM protection */
    uint32_t    nsects;        /* number of sections in segment */
    uint32_t    flags;        /* flags */
};

struct ib_section_64 { /* for 64-bit architectures */
    char        sectname[16];    /* name of this section */
    char        segname[16];    /* segment this section goes in */
    uint64_t    addr;        /* memory address of this section */
    uint64_t    size;        /* size in bytes of this section */
    uint32_t    offset;        /* file offset of this section */
    uint32_t    align;        /* section alignment (power of 2) */
    uint32_t    reloff;        /* file offset of relocation entries */
    uint32_t    nreloc;        /* number of relocation entries */
    uint32_t    flags;        /* flags (section type and attributes)*/
    uint32_t    reserved1;    /* reserved (for offset or index) */
    uint32_t    reserved2;    /* reserved (for count or sizeof) */
    uint32_t    reserved3;    /* reserved */
};

#define IB_SECTION_TYPE         0x000000ff    /* 256 section types */
/*
 * For the two types of symbol pointers sections and the symbol stubs section
 * they have indirect symbol table entries.  For each of the entries in the
 * section the indirect symbol table entries, in corresponding order in the
 * indirect symbol table, start at the index stored in the reserved1 field
 * of the section structure.  Since the indirect symbol table entries
 * correspond to the entries in the section the number of indirect symbol table
 * entries is inferred from the size of the section divided by the size of the
 * entries in the section.  For symbol pointers sections the size of the entries
 * in the section is 4 bytes and for symbol stubs sections the byte size of the
 * stubs is stored in the reserved2 field of the section structure.
 */
#define    IB_S_NON_LAZY_SYMBOL_POINTERS    0x6    /* section with only non-lazy
                           symbol pointers */
#define    IB_S_LAZY_SYMBOL_POINTERS        0x7    /* section with only lazy symbol
                           pointers */
#define    IB_S_SYMBOL_STUBS            0x8    /* section with only symbol
                           stubs, byte size of stub in
                           the reserved2 field */
#define    IB_S_MOD_INIT_FUNC_POINTERS    0x9    /* section with only function
                           pointers for initialization*/
#define    IB_S_MOD_TERM_FUNC_POINTERS    0xa    /* section with only function
                           pointers for termination */
#define    IB_S_COALESCED            0xb    /* section contains symbols that
                           are to be coalesced */
#define    IB_S_GB_ZEROFILL            0xc    /* zero fill on demand section
                           (that can be larger than 4
                           gigabytes) */
#define    IB_S_INTERPOSING            0xd    /* section with only pairs of
                           function pointers for
                           interposing */
#define    IB_S_16BYTE_LITERALS        0xe    /* section with only 16 byte
                           literals */
#define    IB_S_DTRACE_DOF            0xf    /* section contains
                           DTrace Object Format */
#define    IB_S_LAZY_DYLIB_SYMBOL_POINTERS    0x10    /* section with only lazy
                           symbol pointers to lazy
                           loaded dylibs */

enum IBByteOrder {
    IB_UnknownByteOrder,
    IB_LittleEndian,
    IB_BigEndian
};

extern void ib_swap_mach_header_64(struct ib_mach_header_64 *mh, enum IBByteOrder target_byte_order);
extern void ib_swap_fat_header(struct ib_fat_header *mh, enum IBByteOrder target_byte_order);
extern void ib_swap_fat_arch(struct ib_fat_arch *arch, enum IBByteOrder target_byte_order);


#pragma mark - Segments
/*
 * This is the symbol table entry structure for 64-bit architectures.
 */
struct ib_nlist_64 {
    union {
        uint32_t  n_strx; /* index into the string table */
    } n_un;
    uint8_t n_type;        /* type flag, see below */
    uint8_t n_sect;        /* section number or NO_SECT */
    uint16_t n_desc;       /* see <mach-o/stab.h> */
    uint64_t n_value;      /* value of this symbol (or stab offset) */
};

/*
 * Symbols with a index into the string table of zero (n_un.n_strx == 0) are
 * defined to have a null, "", name.  Therefore all string indexes to non null
 * names must not have a zero string index.  This is bit historical information
 * that has never been well documented.
 */

/*
 * The n_type field really contains four fields:
 *    unsigned char N_STAB:3,
 *              N_PEXT:1,
 *              N_TYPE:3,
 *              N_EXT:1;
 * which are used via the following masks.
 */
#define    IB_N_STAB    0xe0  /* if any of these bits set, a symbolic debugging entry */
#define    IB_N_PEXT    0x10  /* private external symbol bit */
#define    IB_N_TYPE    0x0e  /* mask for the type bits */
#define    IB_N_EXT    0x01  /* external symbol bit, set for external symbols */

/*
 * Only symbolic debugging entries have some of the N_STAB bits set and if any
 * of these bits are set then it is a symbolic debugging entry (a stab).  In
 * which case then the values of the n_type field (the entire field) are given
 * in <mach-o/stab.h>
 */

/*
 * Values for N_TYPE bits of the n_type field.
 */
#define    IB_N_UNDF    0x0        /* undefined, n_sect == NO_SECT */
#define    IB_N_ABS    0x2        /* absolute, n_sect == NO_SECT */
#define    IB_N_SECT    0xe        /* defined in section number n_sect */
#define    IB_N_PBUD    0xc        /* prebound undefined (defined in a dylib) */
#define    IB_N_INDR    0xa        /* indirect */

/*
 * If the type is N_INDR then the symbol is defined to be the same as another
 * symbol.  In this case the n_value field is an index into the string table
 * of the other symbol's name.  When the other symbol is defined then they both
 * take on the defined type and value.
 */

/*
 * If the type is N_SECT then the n_sect field contains an ordinal of the
 * section the symbol is defined in.  The sections are numbered from 1 and
 * refer to sections in order they appear in the load commands for the file
 * they are in.  This means the same ordinal may very well refer to different
 * sections in different files.
 *
 * The n_value field for all symbol table entries (including N_STAB's) gets
 * updated by the link editor based on the value of it's n_sect field and where
 * the section n_sect references gets relocated.  If the value of the n_sect
 * field is NO_SECT then it's n_value field is not changed by the link editor.
 */
#define    IB_NO_SECT        0    /* symbol is not in any section */
#define    IB_MAX_SECT    255    /* 1 thru 255 inclusive */

/*
 * The dyld_info_command contains the file offsets and sizes of
 * the new compressed form of the information dyld needs to
 * load the image.  This information is used by dyld on Mac OS X
 * 10.6 and later.  All information pointed to by this command
 * is encoded using byte streams, so no endian swapping is needed
 * to interpret it.
 */
struct ib_dyld_info_command {
   uint32_t   cmd;        /* LC_DYLD_INFO or LC_DYLD_INFO_ONLY */
   uint32_t   cmdsize;        /* sizeof(struct dyld_info_command) */

    /*
     * Dyld rebases an image whenever dyld loads it at an address different
     * from its preferred address.  The rebase information is a stream
     * of byte sized opcodes whose symbolic names start with REBASE_OPCODE_.
     * Conceptually the rebase information is a table of tuples:
     *    <seg-index, seg-offset, type>
     * The opcodes are a compressed way to encode the table by only
     * encoding when a column changes.  In addition simple patterns
     * like "every n'th offset for m times" can be encoded in a few
     * bytes.
     */
    uint32_t   rebase_off;    /* file offset to rebase info  */
    uint32_t   rebase_size;    /* size of rebase info   */
    
    /*
     * Dyld binds an image during the loading process, if the image
     * requires any pointers to be initialized to symbols in other images.
     * The bind information is a stream of byte sized
     * opcodes whose symbolic names start with BIND_OPCODE_.
     * Conceptually the bind information is a table of tuples:
     *    <seg-index, seg-offset, type, symbol-library-ordinal, symbol-name, addend>
     * The opcodes are a compressed way to encode the table by only
     * encoding when a column changes.  In addition simple patterns
     * like for runs of pointers initialzed to the same value can be
     * encoded in a few bytes.
     */
    uint32_t   bind_off;    /* file offset to binding info   */
    uint32_t   bind_size;    /* size of binding info  */
        
    /*
     * Some C++ programs require dyld to unique symbols so that all
     * images in the process use the same copy of some code/data.
     * This step is done after binding. The content of the weak_bind
     * info is an opcode stream like the bind_info.  But it is sorted
     * alphabetically by symbol name.  This enable dyld to walk
     * all images with weak binding information in order and look
     * for collisions.  If there are no collisions, dyld does
     * no updating.  That means that some fixups are also encoded
     * in the bind_info.  For instance, all calls to "operator new"
     * are first bound to libstdc++.dylib using the information
     * in bind_info.  Then if some image overrides operator new
     * that is detected when the weak_bind information is processed
     * and the call to operator new is then rebound.
     */
    uint32_t   weak_bind_off;    /* file offset to weak binding info   */
    uint32_t   weak_bind_size;  /* size of weak binding info  */
    
    /*
     * Some uses of external symbols do not need to be bound immediately.
     * Instead they can be lazily bound on first use.  The lazy_bind
     * are contains a stream of BIND opcodes to bind all lazy symbols.
     * Normal use is that dyld ignores the lazy_bind section when
     * loading an image.  Instead the static linker arranged for the
     * lazy pointer to initially point to a helper function which
     * pushes the offset into the lazy_bind area for the symbol
     * needing to be bound, then jumps to dyld which simply adds
     * the offset to lazy_bind_off to get the information on what
     * to bind.
     */
    uint32_t   lazy_bind_off;    /* file offset to lazy binding info */
    uint32_t   lazy_bind_size;  /* size of lazy binding infs */
    
    /*
     * The symbols exported by a dylib are encoded in a trie.  This
     * is a compact representation that factors out common prefixes.
     * It also reduces LINKEDIT pages in RAM because it encodes all
     * information (name, address, flags) in one small, contiguous range.
     * The export area is a stream of nodes.  The first node sequentially
     * is the start node for the trie.
     *
     * Nodes for a symbol start with a uleb128 that is the length of
     * the exported symbol information for the string so far.
     * If there is no exported symbol, the node starts with a zero byte.
     * If there is exported info, it follows the length.
     *
     * First is a uleb128 containing flags. Normally, it is followed by
     * a uleb128 encoded offset which is location of the content named
     * by the symbol from the mach_header for the image.  If the flags
     * is EXPORT_SYMBOL_FLAGS_REEXPORT, then following the flags is
     * a uleb128 encoded library ordinal, then a zero terminated
     * UTF8 string.  If the string is zero length, then the symbol
     * is re-export from the specified dylib with the same name.
     * If the flags is EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER, then following
     * the flags is two uleb128s: the stub offset and the resolver offset.
     * The stub is used by non-lazy pointers.  The resolver is used
     * by lazy pointers and must be called to get the actual address to use.
     *
     * After the optional exported symbol information is a byte of
     * how many edges (0-255) that this node has leaving it,
     * followed by each edge.
     * Each edge is a zero terminated UTF8 of the addition chars
     * in the symbol, followed by a uleb128 offset for the node that
     * edge points to.
     *
     */
    uint32_t   export_off;    /* file offset to lazy binding info */
    uint32_t   export_size;    /* size of lazy binding infs */
};

/*
 * The following are used to encode rebasing information
 */
#define IB_REBASE_TYPE_POINTER                    1
#define IB_REBASE_TYPE_TEXT_ABSOLUTE32                2
#define IB_REBASE_TYPE_TEXT_PCREL32                3

#define IB_REBASE_OPCODE_MASK                    0xF0
#define IB_REBASE_IMMEDIATE_MASK                    0x0F
#define IB_REBASE_OPCODE_DONE                    0x00
#define IB_REBASE_OPCODE_SET_TYPE_IMM                0x10
#define IB_REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB        0x20
#define IB_REBASE_OPCODE_ADD_ADDR_ULEB                0x30
#define IB_REBASE_OPCODE_ADD_ADDR_IMM_SCALED            0x40
#define IB_REBASE_OPCODE_DO_REBASE_IMM_TIMES            0x50
#define IB_REBASE_OPCODE_DO_REBASE_ULEB_TIMES            0x60
#define IB_REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB            0x70
#define IB_REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB    0x80


/*
 * The following are used to encode binding information
 */
#define IB_BIND_TYPE_POINTER                    1
#define IB_BIND_TYPE_TEXT_ABSOLUTE32                2
#define IB_BIND_TYPE_TEXT_PCREL32                    3

#define IB_BIND_SPECIAL_DYLIB_SELF                     0
#define IB_BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE            -1
#define IB_BIND_SPECIAL_DYLIB_FLAT_LOOKUP                -2
#define IB_BIND_SPECIAL_DYLIB_WEAK_LOOKUP                -3

#define IB_BIND_SYMBOL_FLAGS_WEAK_IMPORT                0x1
#define IB_BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION            0x8

#define IB_BIND_OPCODE_MASK                    0xF0
#define IB_BIND_IMMEDIATE_MASK                    0x0F
#define IB_BIND_OPCODE_DONE                    0x00
#define IB_BIND_OPCODE_SET_DYLIB_ORDINAL_IMM            0x10
#define IB_BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB            0x20
#define IB_BIND_OPCODE_SET_DYLIB_SPECIAL_IMM            0x30
#define IB_BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM        0x40
#define IB_BIND_OPCODE_SET_TYPE_IMM                0x50
#define IB_BIND_OPCODE_SET_ADDEND_SLEB                0x60
#define IB_BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB            0x70
#define IB_BIND_OPCODE_ADD_ADDR_ULEB                0x80
#define IB_BIND_OPCODE_DO_BIND                    0x90
#define IB_BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB            0xA0
#define IB_BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED            0xB0
#define IB_BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB        0xC0
#define IB_BIND_OPCODE_THREADED                    0xD0
#define IB_BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB 0x00
#define IB_BIND_SUBOPCODE_THREADED_APPLY                 0x01

/*
 * The following are used on the flags byte of a terminal node
 * in the export information.
 */
#define IB_EXPORT_SYMBOL_FLAGS_KIND_MASK                0x03
#define IB_EXPORT_SYMBOL_FLAGS_KIND_REGULAR            0x00
#define IB_EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL            0x01
#define IB_EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE            0x02
#define IB_EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION            0x04
#define IB_EXPORT_SYMBOL_FLAGS_REEXPORT                0x08
#define IB_EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER            0x10

/*
 * The symtab_command contains the offsets and sizes of the link-edit 4.3BSD
 * "stab" style symbol table information as described in the header files
 * <nlist.h> and <stab.h>.
 */
struct ib_symtab_command {
    uint32_t    cmd;        /* LC_SYMTAB */
    uint32_t    cmdsize;    /* sizeof(struct symtab_command) */
    uint32_t    symoff;        /* symbol table offset */
    uint32_t    nsyms;        /* number of symbol table entries */
    uint32_t    stroff;        /* string table offset */
    uint32_t    strsize;    /* string table size in bytes */
};

/*
 * This is the second set of the symbolic information which is used to support
 * the data structures for the dynamically link editor.
 *
 * The original set of symbolic information in the symtab_command which contains
 * the symbol and string tables must also be present when this load command is
 * present.  When this load command is present the symbol table is organized
 * into three groups of symbols:
 *    local symbols (static and debugging symbols) - grouped by module
 *    defined external symbols - grouped by module (sorted by name if not lib)
 *    undefined external symbols (sorted by name if MH_BINDATLOAD is not set,
 *                         and in order the were seen by the static
 *                    linker if MH_BINDATLOAD is set)
 * In this load command there are offsets and counts to each of the three groups
 * of symbols.
 *
 * This load command contains a the offsets and sizes of the following new
 * symbolic information tables:
 *    table of contents
 *    module table
 *    reference symbol table
 *    indirect symbol table
 * The first three tables above (the table of contents, module table and
 * reference symbol table) are only present if the file is a dynamically linked
 * shared library.  For executable and object modules, which are files
 * containing only one module, the information that would be in these three
 * tables is determined as follows:
 *     table of contents - the defined external symbols are sorted by name
 *    module table - the file contains only one module so everything in the
 *               file is part of the module.
 *    reference symbol table - is the defined and undefined external symbols
 *
 * For dynamically linked shared library files this load command also contains
 * offsets and sizes to the pool of relocation entries for all sections
 * separated into two groups:
 *    external relocation entries
 *    local relocation entries
 * For executable and object modules the relocation entries continue to hang
 * off the section structures.
 */
struct ib_dysymtab_command {
    uint32_t cmd;    /* LC_DYSYMTAB */
    uint32_t cmdsize;    /* sizeof(struct dysymtab_command) */

    /*
     * The symbols indicated by symoff and nsyms of the LC_SYMTAB load command
     * are grouped into the following three groups:
     *    local symbols (further grouped by the module they are from)
     *    defined external symbols (further grouped by the module they are from)
     *    undefined symbols
     *
     * The local symbols are used only for debugging.  The dynamic binding
     * process may have to use them to indicate to the debugger the local
     * symbols for a module that is being bound.
     *
     * The last two groups are used by the dynamic binding process to do the
     * binding (indirectly through the module table and the reference symbol
     * table when this is a dynamically linked shared library file).
     */
    uint32_t ilocalsym;    /* index to local symbols */
    uint32_t nlocalsym;    /* number of local symbols */

    uint32_t iextdefsym;/* index to externally defined symbols */
    uint32_t nextdefsym;/* number of externally defined symbols */

    uint32_t iundefsym;    /* index to undefined symbols */
    uint32_t nundefsym;    /* number of undefined symbols */

    /*
     * For the for the dynamic binding process to find which module a symbol
     * is defined in the table of contents is used (analogous to the ranlib
     * structure in an archive) which maps defined external symbols to modules
     * they are defined in.  This exists only in a dynamically linked shared
     * library file.  For executable and object modules the defined external
     * symbols are sorted by name and is use as the table of contents.
     */
    uint32_t tocoff;    /* file offset to table of contents */
    uint32_t ntoc;    /* number of entries in table of contents */

    /*
     * To support dynamic binding of "modules" (whole object files) the symbol
     * table must reflect the modules that the file was created from.  This is
     * done by having a module table that has indexes and counts into the merged
     * tables for each module.  The module structure that these two entries
     * refer to is described below.  This exists only in a dynamically linked
     * shared library file.  For executable and object modules the file only
     * contains one module so everything in the file belongs to the module.
     */
    uint32_t modtaboff;    /* file offset to module table */
    uint32_t nmodtab;    /* number of module table entries */

    /*
     * To support dynamic module binding the module structure for each module
     * indicates the external references (defined and undefined) each module
     * makes.  For each module there is an offset and a count into the
     * reference symbol table for the symbols that the module references.
     * This exists only in a dynamically linked shared library file.  For
     * executable and object modules the defined external symbols and the
     * undefined external symbols indicates the external references.
     */
    uint32_t extrefsymoff;    /* offset to referenced symbol table */
    uint32_t nextrefsyms;    /* number of referenced symbol table entries */

    /*
     * The sections that contain "symbol pointers" and "routine stubs" have
     * indexes and (implied counts based on the size of the section and fixed
     * size of the entry) into the "indirect symbol" table for each pointer
     * and stub.  For every section of these two types the index into the
     * indirect symbol table is stored in the section header in the field
     * reserved1.  An indirect symbol table entry is simply a 32bit index into
     * the symbol table to the symbol that the pointer or stub is referring to.
     * The indirect symbol table is ordered to match the entries in the section.
     */
    uint32_t indirectsymoff; /* file offset to the indirect symbol table */
    uint32_t nindirectsyms;  /* number of indirect symbol table entries */

    /*
     * To support relocating an individual module in a library file quickly the
     * external relocation entries for each module in the library need to be
     * accessed efficiently.  Since the relocation entries can't be accessed
     * through the section headers for a library file they are separated into
     * groups of local and external entries further grouped by module.  In this
     * case the presents of this load command who's extreloff, nextrel,
     * locreloff and nlocrel fields are non-zero indicates that the relocation
     * entries of non-merged sections are not referenced through the section
     * structures (and the reloff and nreloc fields in the section headers are
     * set to zero).
     *
     * Since the relocation entries are not accessed through the section headers
     * this requires the r_address field to be something other than a section
     * offset to identify the item to be relocated.  In this case r_address is
     * set to the offset from the vmaddr of the first LC_SEGMENT command.
     * For MH_SPLIT_SEGS images r_address is set to the the offset from the
     * vmaddr of the first read-write LC_SEGMENT command.
     *
     * The relocation entries are grouped by module and the module table
     * entries have indexes and counts into them for the group of external
     * relocation entries for that the module.
     *
     * For sections that are merged across modules there must not be any
     * remaining external relocation entries for them (for merged sections
     * remaining relocation entries must be local).
     */
    uint32_t extreloff;    /* offset to external relocation entries */
    uint32_t nextrel;    /* number of external relocation entries */

    /*
     * All the local relocation entries are grouped together (they are not
     * grouped by their module since they are only used if the object is moved
     * from it staticly link edited address).
     */
    uint32_t locreloff;    /* offset to local relocation entries */
    uint32_t nlocrel;    /* number of local relocation entries */

};

/*
 * An indirect symbol table entry is simply a 32bit index into the symbol table
 * to the symbol that the pointer or stub is refering to.  Unless it is for a
 * non-lazy symbol pointer section for a defined symbol which strip(1) as
 * removed.  In which case it has the value INDIRECT_SYMBOL_LOCAL.  If the
 * symbol was also absolute INDIRECT_SYMBOL_ABS is or'ed with that.
 */
#define IB_INDIRECT_SYMBOL_LOCAL    0x80000000
#define IB_INDIRECT_SYMBOL_ABS    0x40000000

/*
 * The entry_point_command is a replacement for thread_command.
 * It is used for main executables to specify the location (file offset)
 * of main().  If -stack_size was used at link time, the stacksize
 * field will contain the stack size need for the main thread.
 */
struct ib_entry_point_command {
    uint32_t  cmd;    /* LC_MAIN only used in MH_EXECUTE filetypes */
    uint32_t  cmdsize;    /* 24 */
    uint64_t  entryoff;    /* file (__TEXT) offset of main() */
    uint64_t  stacksize;/* if not zero, initial stack size */
};

#define R_SCATTERED 0x80000000    /* mask to be applied to the r_address field
                   of a relocation_info structure to tell that
                   is is really a scattered_relocation_info
                   stucture */
struct scattered_relocation_info {
//#ifdef __BIG_ENDIAN__
//   uint32_t    r_scattered:1,    /* 1=scattered, 0=non-scattered (see above) */
//        r_pcrel:1,     /* was relocated pc relative already */
//        r_length:2,    /* 0=byte, 1=word, 2=long, 3=quad */
//        r_type:4,    /* if not 0, machine specific relocation type */
//           r_address:24;    /* offset in the section to what is being
//                   relocated */
//   int32_t    r_value;    /* the value the item to be relocated is
//                   refering to (without any offset added) */
//#endif /* __BIG_ENDIAN__ */
//#ifdef __LITTLE_ENDIAN__
   uint32_t
        r_address:24,    /* offset in the section to what is being
                   relocated */
        r_type:4,    /* if not 0, machine specific relocation type */
        r_length:2,    /* 0=byte, 1=word, 2=long, 3=quad */
        r_pcrel:1,     /* was relocated pc relative already */
        r_scattered:1;    /* 1=scattered, 0=non-scattered (see above) */
   int32_t    r_value;    /* the value the item to be relocated is
                   refering to (without any offset added) */
//#endif /* __LITTLE_ENDIAN__ */
};

#endif /* mach_universal_hpp */
