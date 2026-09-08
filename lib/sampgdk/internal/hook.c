/* Copyright (C) 2012-2016 Zeex
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <sampgdk/bool.h>
#include <sampgdk/platform.h>

#if SAMPGDK_WINDOWS
  #include <windows.h>
#else
  #include <stdint.h>
  #include <unistd.h>
  #include <sys/mman.h>
#endif

#include "log.h"
#include "hook.h"
#include "types.h"

#define _SAMPGDK_HOOK_JMP_SIZE 5
#define _SAMPGDK_HOOK_MAX_INSN_LEN 15
#define _SAMPGDK_HOOK_TRAMPOLINE_SIZE \
  (_SAMPGDK_HOOK_JMP_SIZE + _SAMPGDK_HOOK_MAX_INSN_LEN - 1)

#pragma pack(push, 1)

struct _sampgdk_hook_jmp {
  uint8_t opcode;
  int32_t offset;
};

#pragma pack(pop)

// To prevent SELinux from triggering an "execheap" AVC denial, the trampoline must be allocated in a separate memory region with mmap
// Windows does not need special memory handling
struct _sampgdk_hook {
#if SAMPGDK_WINDOWS
  uint8_t trampoline[_SAMPGDK_HOOK_TRAMPOLINE_SIZE];
#else
  uint8_t *trampoline;
  size_t trampoline_size;
#endif
};

#if SAMPGDK_WINDOWS

static void *_sampgdk_hook_unprotect(void *address, size_t size) {
  DWORD old;

  if (VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &old) == 0) {
    return NULL;
  }

  return address;
}

#else /* SAMPGDK_WINDOWS */

// The "unprotect" function name is misleading, but was kept here to make the code more consistent with Windows memory handling.
// This function changes the memory regions permissions to read/write (without execute)
static void *_sampgdk_hook_unprotect(void *address, size_t size) {
  long pagesize;

  pagesize = sysconf(_SC_PAGESIZE);
  address = (void *)((long)address & ~(pagesize - 1));

  if (mprotect(address, size, PROT_READ | PROT_WRITE) != 0) {
    return NULL;
  }

  return address;
}

// This function changes the memory region's permissions to read/execute (without write)
// SELinux does not like memory region's that are both writable and executable at the same time, so we just remove the write permission for that memory region
static void *_sampgdk_hook_protect(void *address, size_t size) {
  long pagesize;

  pagesize = sysconf(_SC_PAGESIZE);
  address = (void *)((long)address & ~(pagesize - 1));

  if (mprotect(address, size, PROT_READ | PROT_EXEC) != 0) {
    return NULL;
  }

  return address;
}

#endif /* !SAMPGDK_WINDOWS */


static size_t _sampgdk_hook_disasm(uint8_t *code, int *reloc) {
  enum flags {
    MODRM      = 1,
    REG_OPCODE = 1 << 1,
    IMM8       = 1 << 2,
    IMM16      = 1 << 3,
    IMM32      = 1 << 4,
    PLUS_R     = 1 << 5,
    RELOC      = 1 << 6
  };

  static int prefixes[] = {
    0xF0, 0xF2, 0xF3,
    0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65,
    0x66,
    0x67
  };

  struct opcode_info {
    int opcode;
    int reg_opcode;
    int flags;
  };

  static struct opcode_info opcodes[] = {
    /* CALL rel32       */ {0xE8, 0, IMM32 | RELOC},
    /* CALL r/m32       */ {0xFF, 2, MODRM | REG_OPCODE},
    /* JMP rel32        */ {0xE9, 0, IMM32 | RELOC},
    /* JMP r/m32        */ {0xFF, 4, MODRM | REG_OPCODE},
    /* LEA r16,m        */ {0x8D, 0, MODRM},
    /* MOV r/m8,r8      */ {0x88, 0, MODRM},
    /* MOV r/m32,r32    */ {0x89, 0, MODRM},
    /* MOV r8,r/m8      */ {0x8A, 0, MODRM},
    /* MOV r32,r/m32    */ {0x8B, 0, MODRM},
    /* MOV r/m16,Sreg   */ {0x8C, 0, MODRM},
    /* MOV Sreg,r/m16   */ {0x8E, 0, MODRM},
    /* MOV AL,moffs8    */ {0xA0, 0, IMM8},
    /* MOV EAX,moffs32  */ {0xA1, 0, IMM32},
    /* MOV moffs8,AL    */ {0xA2, 0, IMM8},
    /* MOV moffs32,EAX  */ {0xA3, 0, IMM32},
    /* MOV r8, imm8     */ {0xB0, 0, PLUS_R | IMM8},
    /* MOV r32, imm32   */ {0xB8, 0, PLUS_R | IMM32},
    /* MOV r/m8, imm8   */ {0xC6, 0, MODRM | REG_OPCODE | IMM8},
    /* MOV r/m32, imm32 */ {0xC7, 0, MODRM | REG_OPCODE | IMM32},
    /* POP r/m32        */ {0x8F, 0, MODRM | REG_OPCODE},
    /* POP r32          */ {0x58, 0, PLUS_R},
    /* PUSH r/m32       */ {0xFF, 6, MODRM | REG_OPCODE},
    /* PUSH r32         */ {0x50, 0, PLUS_R},
    /* PUSH imm8        */ {0x6A, 0, IMM8},
    /* PUSH imm32       */ {0x68, 0, IMM32},
    /* RET              */ {0xC3, 0, 0},
    /* RET imm16        */ {0xC2, 0, IMM16},
    /* SUB r/m32, imm8  */ {0x83, 5, MODRM | REG_OPCODE | IMM8},
    /* SUB r/m32, r32   */ {0x29, 0, MODRM},
    /* SUB r32, r/m32   */ {0x2B, 0, MODRM}
  };

  int i;
  int len = 0;
  int opcode = 0;

  for (i = 0; i < sizeof(prefixes) / sizeof(*prefixes); i++) {
    if (code[len] == prefixes[i]) {
      len++;
    }
  }

  for (i = 0; i < sizeof(opcodes) / sizeof(*opcodes); i++) {
    bool found = false;

    if (code[len] == opcodes[i].opcode) {
      found = !(opcodes[i].flags & REG_OPCODE)
            || ((code[len + 1] >> 3) & 7) == opcodes[i].reg_opcode;
    }
    if ((opcodes[i].flags & PLUS_R)
        && (code[len] & 0xF8) == opcodes[i].opcode) {
      found = true;
    }

    if (found) {
      opcode = code[len++];
      break;
    }
  }

  if (opcode == 0) {
    return 0;
  }

  if (reloc != NULL && opcodes[i].flags & RELOC) {
    *reloc = len; /* relative call or jump */
  }

  if (opcodes[i].flags & MODRM) {
    int modrm = code[len++];
    int mod = modrm >> 6;
    int rm = modrm & 7;

    if (mod != 3 && rm == 4) {
      len++; /* for SIB */
    }

    if (mod == 1) len += 1; /* [reg + disp8] */
    if (mod == 2) len += 4; /* [reg + disp32] */

    if (mod == 0 && rm == 5) {
      len += 4; /* [disp32] */
    }
  }

  if (opcodes[i].flags & IMM8)  len += 1;
  if (opcodes[i].flags & IMM16) len += 2;
  if (opcodes[i].flags & IMM32) len += 4;

  return len;
}

static void _sampgdk_hook_write_jmp(void *src, void *dst, int32_t offset) {
  struct _sampgdk_hook_jmp jmp;

  jmp.opcode = 0xE9;
  jmp.offset = (uint8_t *)dst - ((uint8_t *)src + sizeof(jmp));

  memcpy((uint8_t *)src + offset, &jmp, sizeof(jmp));
}

sampgdk_hook_t sampgdk_hook_new(void *src, void *dst) {
  struct _sampgdk_hook *hook;
  size_t orig_size = 0;
  size_t insn_len = 0;

  if ((hook = (sampgdk_hook_t)malloc(sizeof(*hook))) == NULL) {
    return NULL;
  }

#if SAMPGDK_WINDOWS

  // In Windows, we can simply allocate the trampoline in heap memory, no special memory handling required
  _sampgdk_hook_unprotect(src, _SAMPGDK_HOOK_JMP_SIZE);
  _sampgdk_hook_unprotect(hook->trampoline,
                          _SAMPGDK_HOOK_TRAMPOLINE_SIZE);

#else

  // On Linux, the trampoline needs to be allocated in a separate memory region
  // We can then control the memory region's permissions properly
  long pagesize = sysconf(_SC_PAGESIZE);

  hook->trampoline_size = (size_t)pagesize;
  hook->trampoline = mmap(
    NULL,
    hook->trampoline_size,
    PROT_READ | PROT_WRITE,
    MAP_PRIVATE | MAP_ANONYMOUS,
    -1,
    0
  );

  if (hook->trampoline == MAP_FAILED) {
    free(hook);
    return NULL;
  }

  _sampgdk_hook_unprotect(src, _SAMPGDK_HOOK_JMP_SIZE);

#endif

  /* We can't just jump to src + 5 as we could end up in the middle of
   * some instruction. So we need to determine the instruction length.
   */
  while (orig_size < _SAMPGDK_HOOK_JMP_SIZE) {
    uint8_t *insn = (uint8_t *)src + orig_size;
    int reloc = 0;

    if ((insn_len = _sampgdk_hook_disasm(insn, &reloc)) == 0) {
      sampgdk_log_error("Unsupported instruction");
      break;
    }

    memcpy(hook->trampoline + orig_size, insn, insn_len);

    /* If the original code contains a relative JMP/CALL relocate its
     * destination address.
     */
    if (reloc != 0) {
      int32_t *offset = (int32_t *)(hook->trampoline + orig_size + reloc);
      *offset -= (intptr_t)hook->trampoline - (intptr_t)src;
    }

    orig_size += insn_len;
  }

  if (insn_len > 0) {
    _sampgdk_hook_write_jmp(hook->trampoline, src, orig_size);
    _sampgdk_hook_write_jmp(src, dst, 0);
  } else {
    _sampgdk_hook_write_jmp(hook->trampoline, src, 0);
  }

#if !SAMPGDK_WINDOWS
  // On Linux we are using a separate memory region allocated by mmap for the trampoline
  // To prevent SELinux from triggering an "execheap" AVC denial, we need to change the permissions for the trampoline and "src" memory regions to read/execute only
  _sampgdk_hook_protect(hook->trampoline, hook->trampoline_size);
  _sampgdk_hook_protect(src, _SAMPGDK_HOOK_JMP_SIZE);
#endif

  return hook;
}

void sampgdk_hook_free(sampgdk_hook_t hook) {
#if !SAMPGDK_WINDOWS
  // On Linux we need to release the trampoline memory region that we previously allocated using mmap
  munmap(hook->trampoline, hook->trampoline_size);
#endif

  free(hook);
}

void *sampgdk_hook_trampoline(sampgdk_hook_t hook) {
  return hook->trampoline;
}
