# MCP Pwntools

MCP server exposing pwntools functionality for binary exploitation.

## When to use this skill

Use this skill when you need to:
- Pack/unpack data
- Assemble/disassemble code
- Generate shellcode
- Manipulate ELF files
- Interact with processes
- Build ROP chains

## Tools

**Packing/Unpacking:**
- `p8`, `p16`, `p32`, `p64`, `u8`, `u16`, `u32`, `u64`, `flat`

**Assembly/Disassembly:**
- `asm`, `disasm`

**Shellcode:**
- `shellcraft`, `shellcraft_setreuid`, `shellcraft_dupsh`

**ELF Manipulation:**
- `elf_load`, `elf_asm`, `elf_read`, `elf_write`

**Process Interaction:**
- `process_create`, `remote_connect`, `listen`

**ROP:**
- `rop_load`, `rop_call`

**Exploitation:**
- `fmtstr_payload`, `fmtstr_split`

**Utilities:**
- `hexdump`, `cyclic`, `cyclic_find`, `fit`
- `enhex`, `unhex`, `context_set`, `context_get`

**Logging:**
- `log_debug`, `log_info`, `log_success`, `log_warn`, `log_error`

## Install

```bash
pip install mcp-pwntools
```