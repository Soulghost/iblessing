#include <iblessing/mach-o.h>
#include <iblessing/memory.h>
#include <iblessing/objc.h>

using namespace iblessing;

int main(int argc, char **argv) {
    char *filePath = argv[1];
    // load mach-o
    MachO *macho = MachO::createFromFile(filePath);
    assert(macho->loadSync() == IB_SUCCESS);

    // load memory
    Memory *mem = Memory::createFromMachO(macho);
    assert(mem != nullptr);

    // load objc-runtime
    ObjcRuntime *rt = ObjcRuntime::createFromMemory(mem);
    assert(rt->realizeAll() == IB_SUCCESS);

    for (ObjcClass *classInfo : rt->realizedClasses) {
        ObjcClass *currentClass = classInfo;
        while (currentClass) {
            vector<ObjcMethod *> methods = classInfo->getMethods();
            vector<ObjcIvar *> ivars = classInfo->getIvars();
            // print class / method / props here

            currentClass = classInfo->superClassInfo;
        }
    }

    return 0;
}