#include <cstdio>
#include <cassert>
#include <unicorn/unicorn.h>
#include <capstone/capstone.h>

static void insn_hook_callback(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    void *codes = malloc(sizeof(uint32_t));
    uc_err err = uc_mem_read(uc, address, codes, sizeof(uint32_t));
    if (err != UC_ERR_OK) {
        free(codes);
        return;
    }

    cs_insn *insn = nullptr;
    csh handle;
    assert(cs_open(CS_ARCH_X86, CS_MODE_32, &handle) == CS_ERR_OK);
    // enable detail
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    size_t count = cs_disasm(handle, (uint8_t *)codes, 1, address, 0, &insn);
    if (count != 1) {
        if (insn && count > 0) {
            cs_free(insn, count);
        }
        free(codes);
        return;
    }
    printf("the disasm code is %s %s\n", insn->mnemonic, insn->op_str);
}


int emulator_startup() {
    // code to be emulated
    #define X86_CODE32 "\x41\x4a" // INC ecx; DEC edx

    // memory address where emulation starts
    #define ADDRESS 0x1000000

    uc_engine *uc;
    uc_err err;
    int r_ecx = 0x1234;
    int r_edx = 0x7890;

    printf("Emulate i386 code\n");

    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err != UC_ERR_OK) {
        return -1;
    }

    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);
    uc_mem_write(uc, ADDRESS, X86_CODE32, sizeof(X86_CODE32) - 1);
    uc_reg_write(uc, UC_X86_REG_ECX ,&r_ecx);
    uc_reg_write(uc, UC_X86_REG_EDX, &r_edx);

    printf("start emu\n");
    uc_hook insn_hook;
    uc_hook_add(uc, &insn_hook, UC_HOOK_CODE, (void *)insn_hook_callback, NULL, 1, 0);
    uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32) - 1, 0, 0);
    printf("end emu\n");

    uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &r_edx);
    printf(">>> ECX = 0x%x\n", r_ecx);
    printf(">>> EDX = 0x%x\n", r_edx);
    uc_close(uc);
    return 0;
}

int main(int argc, const char *argv[]) {
    // ascii art
    printf("\n\
           ☠️\n\
           ██╗██████╗ ██╗     ███████╗███████╗███████╗██╗███╗   ██╗ ██████╗\n\
           ██║██╔══██╗██║     ██╔════╝██╔════╝██╔════╝██║████╗  ██║██╔════╝\n\
           ██║██████╔╝██║     █████╗  ███████╗███████╗██║██╔██╗ ██║██║  ███╗\n\
           ██║██╔══██╗██║     ██╔══╝  ╚════██║╚════██║██║██║╚██╗██║██║   ██║\n\
           ██║██████╔╝███████╗███████╗███████║███████║██║██║ ╚████║╚██████╔╝\n\
           ╚═╝╚═════╝ ╚══════╝╚══════╝╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝\n\
           \n");
    
    // hello emu
    return emulator_startup();
}