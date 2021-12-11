//
//  codesign.h
//  iblessing
//
//  Created by soulghost on 2021/12/10.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef codesign_h
#define codesign_h

/* csops  operations */
#define CS_OPS_STATUS           0       /* return status */
#define CS_OPS_MARKINVALID      1       /* invalidate process */
#define CS_OPS_MARKHARD         2       /* set HARD flag */
#define CS_OPS_MARKKILL         3       /* set KILL flag (sticky) */
#ifdef KERNEL_PRIVATE
/* CS_OPS_PIDPATH        4    */
#endif
#define CS_OPS_CDHASH           5       /* get code directory hash */
#define CS_OPS_PIDOFFSET        6       /* get offset of active Mach-o slice */
#define CS_OPS_ENTITLEMENTS_BLOB 7      /* get entitlements blob */
#define CS_OPS_MARKRESTRICT     8       /* set RESTRICT flag (sticky) */
#define CS_OPS_SET_STATUS       9       /* set codesign flags */
#define CS_OPS_BLOB             10      /* get codesign blob */
#define CS_OPS_IDENTITY         11      /* get codesign identity */
#define CS_OPS_CLEARINSTALLER   12      /* clear INSTALLER flag */
#define CS_OPS_CLEARPLATFORM 13 /* clear platform binary status (DEVELOPMENT-only) */
#define CS_OPS_TEAMID       14  /* get team id */
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */

#define CS_MAX_TEAMID_LEN       64

/* code signing attributes of a process */
#define CS_VALID                    0x00000001  /* dynamically valid */
#define CS_ADHOC                    0x00000002  /* ad hoc signed */
#define CS_GET_TASK_ALLOW           0x00000004  /* has get-task-allow entitlement */
#define CS_INSTALLER                0x00000008  /* has installer entitlement */

#define CS_FORCED_LV                0x00000010  /* Library Validation required by Hardened System Policy */
#define CS_INVALID_ALLOWED          0x00000020  /* (macOS Only) Page invalidation allowed by task port policy */

#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_CHECK_EXPIRATION         0x00000400  /* force expiration checking */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */

#define CS_ENFORCEMENT              0x00001000  /* require enforcement */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_ENTITLEMENTS_VALIDATED   0x00004000  /* code signature permits restricted entitlements */
#define CS_NVRAM_UNRESTRICTED       0x00008000  /* has com.apple.rootless.restricted-nvram-variables.heritable entitlement */

#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
#define CS_LINKER_SIGNED            0x00020000  /* Automatically signed by the linker */

#define CS_ALLOWED_MACHO            (CS_ADHOC | CS_HARD | CS_KILL | CS_CHECK_EXPIRATION | \
                                 CS_RESTRICT | CS_ENFORCEMENT | CS_REQUIRE_LV | CS_RUNTIME | CS_LINKER_SIGNED)

#define CS_EXEC_SET_HARD            0x00100000  /* set CS_HARD on any exec'ed process */
#define CS_EXEC_SET_KILL            0x00200000  /* set CS_KILL on any exec'ed process */
#define CS_EXEC_SET_ENFORCEMENT     0x00400000  /* set CS_ENFORCEMENT on any exec'ed process */
#define CS_EXEC_INHERIT_SIP         0x00800000  /* set CS_INSTALLER on any exec'ed process */

#define CS_KILLED                   0x01000000  /* was killed by kernel for invalidity */
#define CS_DYLD_PLATFORM            0x02000000  /* dyld used to load this is a platform binary */
#define CS_PLATFORM_BINARY          0x04000000  /* this is a platform binary */
#define CS_PLATFORM_PATH            0x08000000  /* platform binary by the fact of path (osx only) */

#define CS_DEBUGGED                 0x10000000  /* process is currently or has previously been debugged and allowed to run with invalid pages */
#define CS_SIGNED                   0x20000000  /* process has a signature (may have gone invalid) */
#define CS_DEV_CODE                 0x40000000  /* code is dev signed, cannot be loaded into prod signed code (will go away with rdar://problem/28322552) */
#define CS_DATAVAULT_CONTROLLER     0x80000000  /* has Data Vault controller entitlement */

#define CS_ENTITLEMENT_FLAGS        (CS_GET_TASK_ALLOW | CS_INSTALLER | CS_DATAVAULT_CONTROLLER | CS_NVRAM_UNRESTRICTED)

/* executable segment flags */

#define CS_EXECSEG_MAIN_BINARY          0x1             /* executable segment denotes main binary */
#define CS_EXECSEG_ALLOW_UNSIGNED       0x10            /* allow unsigned pages (for debugging) */
#define CS_EXECSEG_DEBUGGER             0x20            /* main binary is debugger */
#define CS_EXECSEG_JIT                  0x40            /* JIT enabled */
#define CS_EXECSEG_SKIP_LV              0x80            /* OBSOLETE: skip library validation */
#define CS_EXECSEG_CAN_LOAD_CDHASH      0x100           /* can bless cdhash for execution */
#define CS_EXECSEG_CAN_EXEC_CDHASH      0x200           /* can execute blessed cdhash */

#endif /* codesign_h */
