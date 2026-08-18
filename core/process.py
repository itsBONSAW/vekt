from __future__ import annotations

import subprocess
import threading
from dataclasses import dataclass
from typing import IO


class ProcessSupervisorError(RuntimeError):
    pass


@dataclass
class ProcessResult:
    returncode: int | None
    stdout: str = ""
    stderr: str = ""


class ManagedProcess:
    def __init__(
        self,
        command: list[str],
        *,
        name: str,
        stdout=None,
        stderr=None,
        text: bool = True,
        start_new_session: bool = True,
    ):
        self.command = list(command)
        self.name = name

        self.stdout_pipe = stdout
        self.stderr_pipe = stderr

        self.process: subprocess.Popen | None = None

        self.text = text
        self.start_new_session = start_new_session

        self.lock = threading.RLock()

    @property
    def pid(self) -> int | None:
        with self.lock:
            if self.process is None:
                return None

            return self.process.pid

    @property
    def returncode(self) -> int | None:
        with self.lock:
            if self.process is None:
                return None

            return self.process.poll()

    @property
    def running(self) -> bool:
        with self.lock:
            return bool(self.process is not None and self.process.poll() is None)

    def start(self) -> None:
        with self.lock:
            if self.process is not None:
                raise ProcessSupervisorError(f"{self.name} has already been started")

            try:
                self.process = subprocess.Popen(
                    self.command,
                    stdin=subprocess.DEVNULL,
                    stdout=self.stdout_pipe,
                    stderr=self.stderr_pipe,
                    text=self.text,
                    start_new_session=self.start_new_session,
                )
            except OSError as exc:
                raise ProcessSupervisorError(
                    f"Failed to start {self.name}: {exc}"
                ) from exc

    def poll(self) -> int | None:
        with self.lock:
            if self.process is None:
                return None

            return self.process.poll()

    def wait(
        self,
        timeout: float | None = None,
    ) -> int:
        with self.lock:
            if self.process is None:
                raise ProcessSupervisorError(f"{self.name} has not been started")

            try:
                return self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                raise ProcessSupervisorError(
                    f"{self.name} did not exit within " f"{timeout}s"
                ) from exc

    def terminate(
        self,
        timeout: float = 2.0,
    ) -> ProcessResult:
        with self.lock:
            process = self.process

            if process is None:
                return ProcessResult(returncode=None)

            if process.poll() is None:
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass

            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                return self.kill(timeout=timeout)

            return ProcessResult(returncode=process.returncode)

    def kill(
        self,
        timeout: float = 2.0,
    ) -> ProcessResult:
        with self.lock:
            process = self.process

            if process is None:
                return ProcessResult(returncode=None)

            if process.poll() is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass

            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                raise ProcessSupervisorError(
                    f"{self.name} could not be killed"
                ) from exc

            return ProcessResult(returncode=process.returncode)

    def communicate(
        self,
        timeout: float | None = None,
    ) -> ProcessResult:
        with self.lock:
            process = self.process

            if process is None:
                raise ProcessSupervisorError(f"{self.name} has not been started")

            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                raise ProcessSupervisorError(
                    f"{self.name} communication timed out"
                ) from exc

            return ProcessResult(
                returncode=process.returncode,
                stdout=stdout or "",
                stderr=stderr or "",
            )

    def close_pipes(self) -> None:
        with self.lock:
            process = self.process

            if process is None:
                return

            for stream in (
                process.stdin,
                process.stdout,
                process.stderr,
            ):
                if stream is None:
                    continue

                try:
                    stream.close()
                except Exception:
                    pass

    def cleanup(
        self,
        timeout: float = 2.0,
    ) -> ProcessResult:
        result = self.terminate(timeout=timeout)

        self.close_pipes()

        return result


class ProcessRegistry:
    def __init__(self):
        self._processes: dict[
            str,
            ManagedProcess,
        ] = {}

        self._lock = threading.RLock()

    def register(
        self,
        key: str,
        process: ManagedProcess,
    ) -> ManagedProcess:
        with self._lock:
            if key in self._processes:
                raise ProcessSupervisorError(f"Process key already exists: {key}")

            self._processes[key] = process

        return process

    def get(
        self,
        key: str,
    ) -> ManagedProcess | None:
        with self._lock:
            return self._processes.get(key)

    def remove(
        self,
        key: str,
    ) -> ManagedProcess | None:
        with self._lock:
            return self._processes.pop(
                key,
                None,
            )

    def stop(
        self,
        key: str,
        timeout: float = 2.0,
    ) -> ProcessResult | None:
        process = self.get(key)

        if process is None:
            return None

        try:
            return process.cleanup(timeout=timeout)
        finally:
            self.remove(key)

    def stop_all(
        self,
        timeout: float = 2.0,
    ) -> dict[str, ProcessResult | Exception]:
        with self._lock:
            items = list(self._processes.items())

        results: dict[
            str,
            ProcessResult | Exception,
        ] = {}

        for key, process in items:
            try:
                results[key] = process.cleanup(timeout=timeout)
            except Exception as exc:
                results[key] = exc
            finally:
                self.remove(key)

        return results

    def running(
        self,
    ) -> dict[str, int]:
        with self._lock:
            items = list(self._processes.items())

        result: dict[str, int] = {}

        for key, process in items:
            pid = process.pid

            if process.running and pid is not None:
                result[key] = pid

        return result
