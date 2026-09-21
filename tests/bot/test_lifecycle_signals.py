"""Linux-only OS boundary: signals target only this test's disposable Popen."""
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import threading
import time

import pytest


pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux OS signal evidence required')


def run_owned_child(tmp_path: Path, signum: int, barrier: str) -> list[str]:
    source = Path(__file__).resolve().parents[2]
    bootstrap = (
        'import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); '
        'from tests.bot.lifecycle_signal_child import run_child; '
        'run_child(sys.argv[2], Path(sys.argv[3]))')
    env = {key: os.environ[key] for key in ('PATH', 'SYSTEMROOT', 'TEMP', 'TMP') if key in os.environ}
    env['VPS_APPLY_ENABLED'] = 'false'
    child = subprocess.Popen(
        [sys.executable, '-I', '-B', '-c', bootstrap, str(source), barrier, str(tmp_path)],
        cwd=tmp_path, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, bufsize=0)
    records = queue.Queue(maxsize=66)
    overflow = threading.Event()
    stderr_seen = threading.Event()

    def read_stdout():
        total = 0
        try:
            for _ in range(65):
                line = child.stdout.readline(16385)
                if not line:
                    return
                total += len(line)
                if total > 16384 or not line.endswith(b'\n'):
                    overflow.set()
                    return
                records.put_nowait(line.decode('ascii').strip())
            overflow.set()
        except (UnicodeError, queue.Full):
            overflow.set()

    def read_stderr():
        total = 0
        while True:
            data = child.stderr.read(1024)
            if not data:
                return
            stderr_seen.set()
            total += len(data)
            if total > 16384:
                overflow.set()
                return

    readers = [threading.Thread(target=read_stdout, daemon=True),
               threading.Thread(target=read_stderr, daemon=True)]
    for reader in readers:
        reader.start()
    trace = []
    deadline = time.monotonic() + 10
    sent = False
    expected = {
        'PRE_LOOP': ['BARRIER:PRE_LOOP', 'STOP_ACCEPTED', 'CLOSED'],
        'FACTORY_DISPATCHED': ['BARRIER:FACTORY_DISPATCHED', 'STOP_ACCEPTED', 'RELEASE',
                               'WORKFLOW_CLOSE', 'SESSION_CLOSE', 'LOCK_EXIT', 'CLOSED'],
        'READY': ['READY', 'BARRIER:READY', 'STOP_ACCEPTED', 'STOPPING',
                  'WORKFLOW_CLOSE', 'SESSION_CLOSE', 'LOCK_EXIT', 'CLOSED'],
    }[barrier]
    def command(value):
        child.stdin.write((value + '\n').encode('ascii'))
        child.stdin.flush()
    try:
        while trace != expected:
            assert time.monotonic() < deadline, 'Synthetic child deadline exceeded'
            assert not overflow.is_set(), 'Synthetic child output cap exceeded'
            try:
                record = records.get(timeout=min(0.1, max(0.001, deadline-time.monotonic())))
            except queue.Empty:
                if child.poll() is not None and not readers[0].is_alive():
                    pytest.fail('Synthetic child exited before terminal trace')
                continue
            trace.append(record)
            assert len(trace) <= 64 and trace == expected[:len(trace)], 'Invalid synthetic trace order'
            if record == 'BARRIER:' + barrier:
                assert not sent and child.poll() is None
                child.send_signal(signum)
                sent = True
                if barrier == 'PRE_LOOP':
                    command('GO')
            elif record == 'STOP_ACCEPTED' and barrier == 'FACTORY_DISPATCHED':
                command('RELEASE')
        assert child.wait(timeout=max(0.001, deadline-time.monotonic())) == 0
        for reader in readers:
            reader.join(timeout=0.5)
        assert all(not reader.is_alive() for reader in readers)
        assert records.empty() and not overflow.is_set() and not stderr_seen.is_set()
        return trace
    finally:
        if child.poll() is None:
            try:
                command('RELEASE')
            except (BrokenPipeError, OSError):
                pass
            child.terminate()
            try:
                child.wait(timeout=1)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=1)
        for stream in (child.stdin, child.stdout, child.stderr):
            stream.close()


@pytest.mark.parametrize('signum', [signal.SIGTERM, signal.SIGINT])
@pytest.mark.parametrize('barrier', ['PRE_LOOP', 'FACTORY_DISPATCHED', 'READY'])
def test_owned_child_signal_stops_at_barrier(tmp_path, signum, barrier):
    trace = run_owned_child(tmp_path, signum, barrier)
    assert trace[-1] == 'CLOSED'
    assert trace.count('STOP_ACCEPTED') == 1
    if barrier != 'READY':
        assert 'READY' not in trace
    else:
        assert trace.count('STOPPING') == 1
    if barrier == 'FACTORY_DISPATCHED':
        assert trace.index('RELEASE') < trace.index('WORKFLOW_CLOSE')
