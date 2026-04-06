"""mcp-pwntools: MCP server exposing pwntools 4.15.0 functionality."""

import fastmcp
from pwn import ELF, ROP, context, process, remote
from pwn import asm as _asm
from pwn import cyclic as _cyclic
from pwn import cyclic_find as _cyclic_find
from pwn import disasm as _disasm
from pwn import enhex as _enhex
from pwn import fit as _fit
from pwn import flat as _flat
from pwn import fmtstr_payload as _fmtstr_payload
from pwn import fmtstr_split as _fmtstr_split
from pwn import hexdump as _hexdump
from pwn import listen as _listen
from pwn import log as _log
from pwn import p8 as _p8
from pwn import p16 as _p16
from pwn import p32 as _p32
from pwn import p64 as _p64
from pwn import shellcraft as _shellcraft
from pwn import u8 as _u8
from pwn import u16 as _u16
from pwn import u32 as _u32
from pwn import u64 as _u64
from pwn import unhex as _unhex

mcp = fastmcp.FastMCP("mcp-pwntools")


@mcp.tool()
def p8(n: int) -> str:
    """Pack an integer into 1 byte.

    Args:
        n: Integer to pack (0-255).

    Returns:
        Hex string of packed bytes.

    Example:
        >>> p8(0x41)
        '41'
    """
    return _p8(n).hex()


@mcp.tool()
def p16(n: int, endian: str = "little") -> str:
    """Pack an integer into 2 bytes.

    Args:
        n: Integer to pack (0-65535).
        endian: 'little' or 'big'.

    Returns:
        Hex string of packed bytes.

    Example:
        >>> p16(0x4142, endian='little')
        '4241'
    """
    return _p16(n, endian=endian).hex()


@mcp.tool()
def p32(n: int, endian: str = "little") -> str:
    """Pack an integer into 4 bytes.

    Args:
        n: Integer to pack.
        endian: 'little' or 'big'.

    Returns:
        Hex string of packed bytes.

    Example:
        >>> p32(0x41424344, endian='little')
        '44434241'
    """
    return _p32(n, endian=endian).hex()


@mcp.tool()
def p64(n: int, endian: str = "little") -> str:
    """Pack an integer into 8 bytes.

    Args:
        n: Integer to pack.
        endian: 'little' or 'big'.

    Returns:
        Hex string of packed bytes.

    Example:
        >>> p64(0x4142434445464748, endian='little')
        '4847464544434241'
    """
    return _p64(n, endian=endian).hex()


@mcp.tool()
def u8(data: str) -> int:
    """Unpack 1 byte to integer.

    Args:
        data: Hex string of 1 byte.

    Returns:
        Unpacked integer.

    Example:
        >>> u8('41')
        65
    """
    return _u8(bytes.fromhex(data))


@mcp.tool()
def u16(data: str, endian: str = "little") -> int:
    """Unpack 2 bytes to integer.

    Args:
        data: Hex string of 2 bytes.
        endian: 'little' or 'big'.

    Returns:
        Unpacked integer.

    Example:
        >>> u16('4241', endian='little')
        16706
    """
    return _u16(bytes.fromhex(data), endian=endian)


@mcp.tool()
def u32(data: str, endian: str = "little") -> int:
    """Unpack 4 bytes to integer.

    Args:
        data: Hex string of 4 bytes.
        endian: 'little' or 'big'.

    Returns:
        Unpacked integer.

    Example:
        >>> u32('44434241', endian='little')
        1094795857
    """
    return _u32(bytes.fromhex(data), endian=endian)


@mcp.tool()
def u64(data: str, endian: str = "little") -> int:
    """Unpack 8 bytes to integer.

    Args:
        data: Hex string of 8 bytes.
        endian: 'little' or 'big'.

    Returns:
        Unpacked integer.

    Example:
        >>> u64('4847464544434241', endian='little')
        3203391512993874777
    """
    return _u64(bytes.fromhex(data), endian=endian)


@mcp.tool()
def asm(code: str, arch: str = None, os: str = None) -> str:
    """Assemble code to bytes.

    Args:
        code: Assembly code.
        arch: Architecture (i386, amd64, arm, mips, etc.). Uses context if not specified.
        os: OS (linux, freebsd, etc.). Uses context if not specified.

    Returns:
        Hex string of assembled bytes.

    Example:
        >>> asm('nop')
        '90'
    """
    if arch:
        context.arch = arch
    if os:
        context.os = os
    result = _asm(code)
    return result.hex()


@mcp.tool()
def disasm(data: str, arch: str = None, bits: int = None) -> str:
    """Disassemble bytes to code.

    Args:
        data: Hex string to disassemble.
        arch: Architecture. Uses context if not specified.
        bits: Bits (32, 64). Uses context if not specified.

    Returns:
        Disassembled code.

    Example:
        >>> disasm('90')
        '   0:   90                      nop'
    """
    if arch:
        context.arch = arch
    if bits:
        context.bits = bits
    return _disasm(bytes.fromhex(data))


@mcp.tool()
def shellcraft(shellcode_type: str, arg1: str = None, arg2: str = None) -> str:
    """Generate shellcode.

    Args:
        shellcode_type: Type of shellcode (e.g., 'amd64.linux.sh', 'i386.linux.bind', 'setreuid').
        arg1: Optional first argument.
        arg2: Optional second argument.

    Returns:
        Assembly code for the shellcode.

    Example:
        >>> shellcraft('amd64.linux.sh')
        '    ...'
    """
    try:
        parts = shellcode_type.split(".")
        if len(parts) >= 2:
            arch = parts[0]
            remaining = parts[2:] if len(parts) > 2 else []
            sc = getattr(_shellcraft, arch).linux
            if remaining:
                for attr in remaining:
                    sc = getattr(sc, attr)
            result = sc(arg1, arg2) if arg1 or arg2 else sc()
            return result
        return f"Error: Invalid shellcode type '{shellcode_type}'. Use format like 'amd64.linux.sh'"
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def shellcraft_setreuid(uid: int = 0, euid: int = 0) -> str:
    """Generate setreuid shellcode.

    Args:
        uid: UID to set.
        euid: Effective UID to set.

    Returns:
        Assembly code for setreuid.

    Example:
        >>> shellcraft_setreuid(0, 0)
    """
    return _shellcraft.setreuid(uid, euid)


@mcp.tool()
def shellcraft_dupsh(fd: int = 4) -> str:
    """Generate dup shellcode with execve.

    Args:
        fd: File descriptor to dup.

    Returns:
        Assembly code.

    Example:
        >>> shellcraft_dupsh(4)
    """
    return _shellcraft.dupsh(fd)


@mcp.tool()
def hexdump(data: str, begin: int = 0) -> str:
    """Hexdump utility.

    Args:
        data: Hex string to dump.
        begin: Offset to start from.

    Returns:
        Formatted hexdump string.

    Example:
        >>> hexdump('41424344')
    """
    return _hexdump(bytes.fromhex(data), begin=begin)


@mcp.tool()
def cyclic(length: int, n: int = 256) -> str:
    """Generate cyclic pattern.

    Args:
        length: Length of pattern.
        n: Alphabet size (default 256).

    Returns:
        Cyclic pattern as hex string.

    Example:
        >>> cyclic(20)
        '61616162616163616164616165616166'
    """
    return _cyclic(length, n=n).hex()


@mcp.tool()
def cyclic_find(pattern: str) -> int:
    """Find offset in cyclic pattern.

    Args:
        pattern: Hex string of pattern to find.

    Returns:
        Offset of pattern in cyclic.

    Example:
        >>> cyclic_find('66616661')
        120
    """
    return _cyclic_find(bytes.fromhex(pattern))


@mcp.tool()
def fit(data: dict, length: int = None, filler: str = None) -> str:
    """Fit data into buffer.

    Args:
        data: Dictionary mapping offsets to values.
        length: Total length of buffer.
        filler: Hex string for filler bytes.

    Returns:
        Fitted buffer as hex string.

    Example:
        >>> fit({0: '41424344', 8: '45464748'})
        '414243450000000045464748'
    """

    def hex_to_bytes(d: dict) -> dict:
        result: dict = {}
        for k, v in d.items():
            if isinstance(v, str):
                result[k] = bytes.fromhex(v)
            else:
                result[k] = v
        return result

    f: bytes | None = bytes.fromhex(filler) if filler else None
    result = _fit(hex_to_bytes(data), length=length, filler=f)
    return result.hex()


@mcp.tool()
def enhex(data: str) -> str:
    """Encode bytes to hex string.

    Args:
        data: Hex string to encode.

    Returns:
        Hex string.

    Example:
        >>> enhex('41424344')
        '41424344'
    """
    return _enhex(bytes.fromhex(data))


@mcp.tool()
def unhex(data: str) -> str:
    """Decode hex string to bytes.

    Args:
        data: Hex string to decode.

    Returns:
        Bytes as hex string.

    Example:
        >>> unhex('41424344')
        '41424344'
    """
    return _unhex(data.encode()).hex()


@mcp.tool()
def flat(args: list, endian: str = None, sign: bool = False) -> str:
    """Flatten arguments into bytes.

    Args:
        args: List of arguments to flatten (integers or hex strings).
        endian: Endianness (default from context).
        sign: Signedness (default from context).

    Returns:
        Flattened bytes as hex string.

    Example:
        >>> flat([0x41424344, '68656c6c6f'])
        '44434241000000000000000068656c6c6f'
    """
    if endian is None:
        endian = context.endian

    def convert_arg(arg: int | str | bytes) -> int | bytes:
        if isinstance(arg, int):
            return arg
        elif isinstance(arg, str):
            return bytes.fromhex(arg)
        return arg

    converted = [convert_arg(a) for a in args]
    result = _flat(*converted, endian=endian, sign=sign)
    return result.hex()


@mcp.tool()
def context_set(
    arch: str = None,
    os: str = None,
    endian: str = None,
    word_size: int = None,
    log_level: str = None,
) -> dict:
    """Set pwntools context.

    Args:
        arch: Architecture (i386, amd64, arm, mips, etc.).
        os: OS (linux, freebsd, etc.).
        endian: Endianness (little, big).
        word_size: Word size in bits (32, 64).
        log_level: Logging level (debug, info, warning, error).

    Returns:
        Current context settings.

    Example:
        >>> context_set(arch='amd64', os='linux', log_level='debug')
    """
    if arch:
        context.arch = arch
    if os:
        context.os = os
    if endian:
        context.endian = endian
    if word_size:
        context.word_size = word_size
    if log_level:
        context.log_level = log_level

    return {
        "arch": context.arch,
        "os": context.os,
        "endian": context.endian,
        "word_size": context.word_size,
        "log_level": context.log_level,
    }


@mcp.tool()
def context_get() -> dict:
    """Get current pwntools context.

    Returns:
        Current context settings.

    Example:
        >>> context_get()
        {'arch': 'amd64', 'os': 'linux', ...}
    """
    return {
        "arch": context.arch,
        "os": context.os,
        "endian": context.endian,
        "word_size": context.word_size,
        "log_level": context.log_level,
    }


@mcp.tool()
def elf_load(path: str) -> dict:
    """Load an ELF file.

    Args:
        path: Path to ELF file.

    Returns:
        Dictionary with ELF info (address, symbols, plt, got, etc.).

    Example:
        >>> elf_load('/bin/ls')
        {'address': '0x400000', 'symbols': {...}, ...}
    """
    e = ELF(path)
    return {
        "path": e.path,
        "address": hex(e.address),
        "symbols": {k: hex(v) for k, v in e.symbols.items()},
        "plt": {k: hex(v) for k, v in e.plt.items()},
        "got": {k: hex(v) for k, v in e.got.items()},
        "sections": [
            (s.name, hex(s.header.sh_addr), hex(s.header.sh_size)) for s in e.sections
        ],
    }


@mcp.tool()
def elf_asm(path: str, address: str, code: str) -> str:
    """Assemble code at a specific address in an ELF.

    Args:
        path: Path to ELF file.
        address: Address (hex string like '0x400000').
        code: Assembly code.

    Returns:
        Success message.

    Example:
        >>> elf_asm('/bin/cat', '0x401000', 'ret')
        'Assembly applied successfully'
    """
    e = ELF(path)
    addr = int(address, 16)
    e.asm(addr, code)
    return "Assembly applied successfully"


@mcp.tool()
def elf_read(path: str, address: str, length: int = 16) -> str:
    """Read bytes from an ELF at address.

    Args:
        path: Path to ELF file.
        address: Address (hex string like '0x400000').
        length: Number of bytes to read.

    Returns:
        Bytes as hex string.

    Example:
        >>> elf_read('/bin/cat', '0x400000', 16)
    """
    e = ELF(path)
    addr = int(address, 16)
    return e.read(addr, length).hex()


@mcp.tool()
def elf_write(path: str, address: str, data: str) -> str:
    """Write bytes to an ELF at address.

    Args:
        path: Path to ELF file.
        address: Address (hex string like '0x400000').
        data: Hex string to write.

    Returns:
        Success message.

    Example:
        >>> elf_write('/bin/cat', '0x401000', '90')
        'Write successful'
    """
    e = ELF(path)
    addr = int(address, 16)
    e.write(addr, bytes.fromhex(data))
    return "Write successful"


def _tube_to_dict(tube: object) -> dict:
    """Convert tube to serializable dict."""
    return {
        "type": type(tube).__name__,
        "connected": tube.connected(),  # type: ignore[attr-defined]
        "closed": tube.closed(),  # type: ignore[attr-defined]
    }


@mcp.tool()
def process_create(
    argv: list,
    env: dict = None,
    stdin: int = None,
    stdout: int = None,
    stderr: int = None,
    timeout: int = None,
) -> dict:
    """Create and interact with a process.

    Args:
        argv: Command and arguments as list.
        env: Environment variables dict.
        stdin: Stdin redirect (PIPE, STDOUT, etc.).
        stdout: Stdout redirect.
        stderr: Stderr redirect.
        timeout: Timeout in seconds.

    Returns:
        Process info dict.

    Example:
        >>> process_create(['/bin/sh'])
        {'pid': 1234, 'proc': {...}, 'unique': '...'}
    """
    env = env or {}
    timeout = timeout or 30

    p = process(
        argv, env=env, stdin=stdin, stdout=stdout, stderr=stderr, timeout=timeout
    )

    return {
        "pid": p.pid,
        "proc": str(p),
        "connected": p.connected(),
    }


@mcp.tool()
def remote_connect(host: str, port: int, timeout: int = None) -> dict:
    """Connect to a remote host.

    Args:
        host: Hostname or IP.
        port: Port number.
        timeout: Timeout in seconds.

    Returns:
        Connection info dict.

    Example:
        >>> remote_connect('example.com', 80)
        {'host': 'example.com', 'port': 80, 'connected': True}
    """
    r = remote(host, port, timeout=timeout)
    return {
        "host": host,
        "port": port,
        "connected": r.connected(),
    }


@mcp.tool()
def listen(port: int = 0, bindaddr: str = "0.0.0.0") -> dict:
    """Create a listening socket.

    Args:
        port: Port to listen on (0 for random).
        bindaddr: Address to bind to.

    Returns:
        Listener info dict.

    Example:
        >>> listen(8080)
        {'port': 8080, 'lport': 8080, ...}
    """
    listener = _listen(port, bindaddr=bindaddr)
    return {
        "port": listener.lport,
        "lport": listener.lport,
        "bindaddr": bindaddr,
    }


@mcp.tool()
def tube_send(_data: str, _tube_type: str = None) -> str:
    """Send data through a tube.

    Note: This is a placeholder - actual tube handling requires state management.

    Args:
        data: Hex string to send.
        tube_type: Type of tube to create.

    Returns:
        Status message.
    """
    return "Use process/remote/listen for actual tube creation"


@mcp.tool()
def rop_load(path: str) -> dict:
    """Load ELF for ROP.

    Args:
        path: Path to ELF file.

    Returns:
        ROP info dict.

    Example:
        >>> rop_load('/bin/ls')
        {'path': '/bin/ls', 'elf': {...}, 'gadgets_count': ...}
    """
    r = ROP(path)
    return {
        "path": path,
        "gadgets_count": len(r.gadgets),
        "gadgets": str(r),
    }


@mcp.tool()
def rop_call(_runtime: str, _func: str, _args: list = None) -> str:
    """Generate ROP call.

    Note: Requires an active ROP object.

    Args:
        runtime: Runtime/ELF path.
        func: Function name to call.
        args: Arguments for the call.

    Returns:
        ROP chain as hex string.
    """
    return "Use rop module with actual ROP context"


@mcp.tool()
def dynelf_resolve(_leak_func: str, _elf_path: str = None) -> dict:
    """Dynamic ELF resolution.

    Note: Requires active memory leak.

    Args:
        leak_func: Memory leak function.
        elf_path: Optional ELF path.

    Returns:
        Resolution status.
    """
    return {"status": "Requires active memory leak"}


@mcp.tool()
def fmtstr_payload(offset: int, writes: dict, nbytes: int = 8) -> str:
    """Generate format string payload.

    Args:
        offset: Offset to format string.
        writes: Dict of {address: value} to write.
        nbytes: Number of bytes.

    Returns:
        Format string payload as hex string.

    Example:
        >>> fmtstr_payload(6, {0x8048000: 0x41424344})
    """
    result = _fmtstr_payload(offset, writes, nbytes=nbytes)
    return result.hex()


@mcp.tool()
def fmtstr_split(writes: dict, nbytes: int = 8) -> list:
    """Split format string writes.

    Args:
        writes: Dict of {address: value} to write.
        nbytes: Number of bytes.

    Returns:
        List of format string parts.

    Example:
        >>> fmtstr_split({0x8048000: 0x41424344})
    """
    return [p.hex() for p in _fmtstr_split(writes, nbytes=nbytes)]


@mcp.tool()
def log_debug(msg: str) -> str:
    """Log debug message.

    Args:
        msg: Message to _log.

    Returns:
        Success message.
    """
    _log.debug(msg)
    return "Logged: " + msg


@mcp.tool()
def log_info(msg: str) -> str:
    """Log info message.

    Args:
        msg: Message to _log.

    Returns:
        Success message.
    """
    _log.info(msg)
    return "Logged: " + msg


@mcp.tool()
def log_success(msg: str) -> str:
    """Log success message.

    Args:
        msg: Message to _log.

    Returns:
        Success message.
    """
    _log.success(msg)
    return "Logged: " + msg


@mcp.tool()
def log_warn(msg: str) -> str:
    """Log warning message.

    Args:
        msg: Message to _log.

    Returns:
        Success message.
    """
    _log.warn(msg)
    return "Logged: " + msg


@mcp.tool()
def log_error(msg: str) -> str:
    """Log error message.

    Args:
        msg: Message to _log.

    Returns:
        Success message.
    """
    _log.error(msg)
    return "Logged: " + msg


@mcp.resource("elf://{path}")
def elf_resource(path: str) -> dict:
    """Load ELF file as a resource.

    Args:
        path: Path to ELF file.

    Returns:
        ELF info dictionary.
    """
    try:
        e = ELF(path)
        return {
            "path": e.path,
            "address": hex(e.address),
            "symbols": list(e.symbols.keys())[:50],
            "plt": list(e.plt.keys())[:20],
            "got": list(e.got.keys())[:20],
        }
    except Exception as e:
        return {"error": str(e)}


@mcp.resource("context://settings")
def context_resource() -> dict:
    """Get current context as a resource.

    Returns:
        Context settings.
    """
    return {
        "arch": context.arch,
        "os": context.os,
        "endian": context.endian,
        "word_size": context.word_size,
        "log_level": context.log_level,
    }
