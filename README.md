# mcp-pwntools

MCP server exposing pwntools 4.15.0 functionality for binary exploitation tasks.

[![PyPI](https://img.shields.io/pypi/v/mcp-pwntools.svg)](https://pypi.org/project/mcp-pwntools/)
[![Python](https://img.shields.io/pypi/pyversions/mcp-pwntools.svg)](https://pypi.org/project/mcp-pwntools/)

## Install

```bash
pip install mcp-pwntools
```

## MCP Server

This package exposes pwntools functionality via the MCP (Model Context Protocol).

### Tools

The server provides the following tool categories:

- **Packing/Unpacking**: `p8`, `p16`, `p32`, `p64`, `u8`, `u16`, `u32`, `u64`, `flat`
- **Assembly/Disassembly**: `asm`, `disasm`
- **Shellcode Generation**: `shellcraft`, `shellcraft_setreuid`, `shellcraft_dupsh`
- **ELF Manipulation**: `elf_load`, `elf_asm`, `elf_read`, `elf_write`
- **Process Interaction**: `process_create`, `remote_connect`, `listen`
- **ROP**: `rop_load`, `rop_call`
- **Exploitation**: `fmtstr_payload`, `fmtstr_split`
- **Utilities**: `hexdump`, `cyclic`, `cyclic_find`, `fit`, `enhex`, `unhex`, `context_set`, `context_get`
- **Logging**: `log_debug`, `log_info`, `log_success`, `log_warn`, `log_error`

### Resources

- `elf://<path>` - Load ELF file information
- `context://settings` - Get current pwntools context

### Usage

Run the MCP server:

```bash
mcp-pwntools
```

### Configuration (mcp.json)

```json
{
  "mcpServers": {
    "pwntools": {
      "command": "mcp-pwntools",
      "env": {}
    }
  }
}
```

## Development

```bash
git clone https://github.com/daedalus/mcp-pwntools.git
cd mcp-pwntools
pip install -e ".[test]"

# run tests
pytest

# format
ruff format src/ tests/

# lint
ruff check src/ tests/

# type check
mypy src/
```

## mcp-name

mcp-name: io.github.daedalus/mcp-pwntools
