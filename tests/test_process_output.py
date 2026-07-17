"""Unit tests for fast process stdout draining."""

from __future__ import annotations

import select
import subprocess
import sys
import time

from apb.server import engine


def test_consume_process_output_chunk_handles_partial_lines():
    partial = bytearray()
    lines: list[str] = []

    engine.consume_process_output_chunk(b"hello ", partial, lines.append)
    assert lines == []
    assert bytes(partial) == b"hello "

    engine.consume_process_output_chunk(b"world\nnext\npartial", partial, lines.append)
    assert lines == ["hello world", "next"]
    assert bytes(partial) == b"partial"

    engine.flush_partial_process_output(partial, lines.append)
    assert lines == ["hello world", "next", "partial"]
    assert partial == bytearray()


def test_drain_process_stdout_keeps_up_with_high_volume():
    """Flooding stdout must be drained quickly without per-line sleeps."""
    line_count = 20000
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            f"import sys\n"
            f"write = sys.stdout.buffer.write\n"
            f"for i in range({line_count}):\n"
            f"    write(f'line-{{i}}\\n'.encode())\n"
            f"sys.stdout.buffer.flush()\n",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )
    assert process.stdout is not None
    stdout_fd = process.stdout.fileno()
    engine.set_fd_nonblocking(stdout_fd)

    partial = bytearray()
    lines: list[str] = []
    started = time.monotonic()

    while True:
        process_done = process.poll() is not None
        wait_timeout = 0.0 if process_done else 1.0
        if select.select([stdout_fd], [], [], wait_timeout)[0]:
            if not engine.drain_process_stdout(stdout_fd, partial, lines.append):
                break
        elif process_done:
            engine.drain_process_stdout(stdout_fd, partial, lines.append)
            engine.flush_partial_process_output(partial, lines.append)
            break

    process.wait(timeout=10)
    elapsed = time.monotonic() - started

    assert process.returncode == 0
    assert len(lines) == line_count
    assert lines[0] == "line-0"
    assert lines[-1] == f"line-{line_count - 1}"
    # Old loop slept 0.1s per line (~2000s for 20k lines). Fast drain should finish quickly.
    assert elapsed < 15.0
