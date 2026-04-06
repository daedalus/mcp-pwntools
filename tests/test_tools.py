"""Test mcp-pwntools tools."""

from mcp_pwntools.mcp import (
    asm,
    context_get,
    context_resource,
    context_set,
    cyclic,
    cyclic_find,
    disasm,
    elf_asm,
    elf_load,
    elf_read,
    elf_write,
    enhex,
    fit,
    flat,
    hexdump,
    log_debug,
    log_info,
    log_success,
    p8,
    p16,
    p32,
    p64,
    shellcraft,
    shellcraft_dupsh,
    u8,
    u16,
    u32,
    u64,
    unhex,
)


class TestPacking:
    """Test packing/unpacking tools."""

    def test_p8(self) -> None:
        """Test p8 packing."""
        result = p8(0x41)
        assert result == "41"

    def test_p16_little(self) -> None:
        """Test p16 little endian."""
        result = p16(0x4142, endian="little")
        assert result == "4241"

    def test_p16_big(self) -> None:
        """Test p16 big endian."""
        result = p16(0x4142, endian="big")
        assert result == "4142"

    def test_p32(self) -> None:
        """Test p32 packing."""
        result = p32(0x41424344, endian="little")
        assert result == "44434241"

    def test_p64(self) -> None:
        """Test p64 packing."""
        result = p64(0x4142434445464748, endian="little")
        assert result == "4847464544434241"

    def test_u8(self) -> None:
        """Test u8 unpacking."""
        result = u8("41")
        assert result == 65

    def test_u16(self) -> None:
        """Test u16 unpacking."""
        result = u16("4241", endian="little")
        assert result == 16706

    def test_u32(self) -> None:
        """Test u32 unpacking."""
        result = u32("44434241", endian="little")
        assert result > 0

    def test_u64(self) -> None:
        """Test u64 unpacking."""
        result = u64("4847464544434241", endian="little")
        assert result > 0


class TestAssembly:
    """Test assembly/disassembly tools."""

    def test_asm_nop(self) -> None:
        """Test assembling nop."""
        result = asm("nop")
        assert result == "90"

    def test_asm_mov(self) -> None:
        """Test assembling mov."""
        result = asm("mov eax, 0")
        assert len(result) > 0

    def test_disasm_nop(self) -> None:
        """Test disassembling nop."""
        result = disasm("90")
        assert "nop" in result.lower()


class TestShellcode:
    """Test shellcode generation tools."""

    def test_shellcraft(self) -> None:
        """Test shellcode generation."""
        result = shellcraft("amd64.linux.sh")
        assert len(result) > 0


class TestUtils:
    """Test utility tools."""

    def test_cyclic(self) -> None:
        """Test cyclic pattern generation."""
        result = cyclic(20)
        assert len(result) > 0

    def test_unhex(self) -> None:
        """Test unhex."""
        result = unhex("41424344")
        assert result == "41424344"


class TestContext:
    """Test context tools."""

    def test_context_get(self) -> None:
        """Test getting context."""
        result = context_get()
        assert "arch" in result
        assert "os" in result

    def test_context_set_arch(self) -> None:
        """Test setting context arch."""
        result = context_set(arch="amd64")
        assert result["arch"] == "amd64"


class TestELF:
    """Test ELF tools."""

    def test_elf_load(self) -> None:
        """Test loading ELF."""
        result = elf_load("/bin/ls")
        assert "address" in result
        assert "path" in result


class TestLogging:
    """Test logging tools."""

    def test_log_debug(self) -> None:
        """Test debug logging."""
        result = log_debug("test")
        assert "test" in result

    def test_log_info(self) -> None:
        """Test info logging."""
        result = log_info("test")
        assert "test" in result

    def test_log_success(self) -> None:
        """Test success logging."""
        result = log_success("test")
        assert "test" in result


class TestResources:
    """Test resource endpoints."""

    def test_context_resource(self) -> None:
        """Test context resource."""
        result = context_resource()
        assert "arch" in result
        assert "os" in result


class TestPackingExtended:
    """Test extended packing/unpacking tools."""

    def test_cyclic_find(self) -> None:
        """Test cyclic find."""
        pattern = cyclic(20)
        result = cyclic_find(pattern[:4])
        assert isinstance(result, int)

    def test_hexdump(self) -> None:
        """Test hexdump."""
        result = hexdump("4142434445464748")
        assert len(result) > 0

    def test_enhex(self) -> None:
        """Test enhex."""
        result = enhex("41424344")
        assert result == "41424344"

    def test_fit(self) -> None:
        """Test fit."""
        result = fit({0: "41424344", 8: "45464748"}, filler="00")
        assert len(result) > 0

    def test_flat(self) -> None:
        """Test flat."""
        result = flat([0x41424344, "68656c6c6f"])
        assert len(result) > 0


class TestELFExtended:
    """Test extended ELF tools."""

    def test_elf_asm(self) -> None:
        """Test ELF assembly."""
        import os
        import shutil
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False) as f:
            shutil.copy("/bin/ls", f.name)
            result = elf_asm(f.name, "0x401000", "nop")
            os.unlink(f.name)
            assert "success" in result.lower()

    def test_elf_read(self) -> None:
        """Test ELF read."""
        result = elf_read("/bin/ls", "0x1000", 16)
        assert len(result) > 0

    def test_elf_write(self) -> None:
        """Test ELF write."""
        import os
        import shutil
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False) as f:
            shutil.copy("/bin/ls", f.name)
            result = elf_write(f.name, "0x401000", "90")
            os.unlink(f.name)
            assert "success" in result.lower()


class TestShellcodeExtended:
    """Test extended shellcode tools."""

    def test_shellcraft_dupsh(self) -> None:
        """Test shellcraft dupsh."""
        result = shellcraft_dupsh(4)
        assert len(result) > 0


class TestContextExtended:
    """Test extended context tools."""

    def test_context_set_multiple(self) -> None:
        """Test setting multiple context values."""
        result = context_set(arch="amd64", os="linux")
        assert result["arch"] == "amd64"
        assert result["os"] == "linux"


class TestLoggingExtended:
    """Test extended logging tools."""

    def test_log_warn(self) -> None:
        """Test warn logging."""
        result = log_success("test")
        assert "test" in result
