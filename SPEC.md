# SPEC.md — mcp-pwntools

## Purpose
An MCP (Model Context Protocol) server that exposes all pwntools 4.15.0 functionality as MCP tools and resources, enabling LLMs to use pwntools capabilities for binary exploitation tasks.

## Scope
- Expose pwntools 4.15.0 via MCP protocol using FastMCP
- Support stdio transport for local execution
- Provide tools for: ELF manipulation, assembly/disassembly, packing/unpacking, process interaction, ROP chain building, shellcode generation, memory leak exploitation, format string exploitation

## Public API / Interface

### MCP Server
- Name: mcp-pwntools
- Transport: stdio
- Protocol: MCP (Model Context Protocol)

### Tools Categories

**1. Packing/Unpacking**
- `p8`, `p16`, `p32`, `p64` - pack integers to bytes
- `u8`, `u16`, `u32`, `u64` - unpack bytes to integers
- `flat` - flatten arguments into bytes

**2. Assembly/Disassembly**
- `asm` - assemble code to bytes
- `disasm` - disassemble bytes to code

**3. Shellcode Generation**
- `shellcraft` - generate shellcode for various architectures

**4. ELF Manipulation**
- `ELF` - load and manipulate ELF binaries

**5. Process Interaction**
- `process` - create and interact with local processes
- `remote` - connect to remote services
- `listen` - create a listening socket
- `ssh` - SSH connections

**6. ROP**
- `ROP` - ROP chain builder

**7. Memory Exploitation**
- `DynELF` - dynamic ELF resolution
- `MemLeak` - memory leak helper
- `FmtStr` - format string exploitation

**8. Utilities**
- `cyclic`, `cyclic_find` - pattern generation for offset finding
- `hexdump` - hexdump utility
- `fit` - buffer fitting
- `context` - global context for arch/OS/endian

### Resources
- `elf://<path>` - Load ELF file as resource

### Error Handling
- All pwntools exceptions are wrapped and exposed via MCP
- Invalid arguments raise appropriate exceptions

## Data Formats
- Input: JSON (via MCP protocol)
- Output: JSON (serialized pwntools results)

## Edge Cases
- Handle missing binaries gracefully
- Handle connection failures
- Handle assembly failures
- Handle invalid ELF files

## Performance & Constraints
- pwntools is required at runtime
- Lazy initialization of heavy components
