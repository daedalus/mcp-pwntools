import pytest


@pytest.fixture
def sample_elf_path() -> str:
    return "/bin/ls"


@pytest.fixture
def sample_hex_data() -> str:
    return "4142434445464748"
