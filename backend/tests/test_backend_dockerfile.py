import shlex
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
DOCKERFILE = BACKEND_DIR / "Dockerfile"


def load_copy_instructions() -> list[tuple[tuple[str, ...], str]]:
    instructions: list[str] = []
    current_instruction = ""

    for raw_line in DOCKERFILE.read_text(encoding="utf-8").splitlines():
        stripped_line = raw_line.strip()
        if not stripped_line or stripped_line.startswith("#"):
            continue

        current_instruction = " ".join(
            part
            for part in (current_instruction, stripped_line.removesuffix("\\").strip())
            if part
        )
        if stripped_line.endswith("\\"):
            continue

        instructions.append(current_instruction)
        current_instruction = ""

    assert not current_instruction, "Dockerfile contains an incomplete instruction."

    copy_instructions: list[tuple[tuple[str, ...], str]] = []
    for instruction in instructions:
        tokens = shlex.split(instruction)
        if not tokens or tokens[0].lower() != "copy":
            continue

        arguments = [token for token in tokens[1:] if not token.startswith("--")]
        assert len(arguments) >= 2, "COPY must include a source and destination."
        copy_instructions.append((tuple(arguments[:-1]), arguments[-1]))

    return copy_instructions


def test_backend_image_packages_application_and_alembic_assets() -> None:
    copy_instructions = load_copy_instructions()

    assert (("app",), "./app") in copy_instructions
    assert (("alembic.ini",), "./alembic.ini") in copy_instructions
    assert (("alembic",), "./alembic") in copy_instructions


def test_backend_image_copy_scope_remains_narrow() -> None:
    copy_instructions = load_copy_instructions()
    copied_sources = {
        source
        for sources, _destination in copy_instructions
        for source in sources
    }

    assert "." not in copied_sources
    assert not any(Path(source).name.startswith(".env") for source in copied_sources)
