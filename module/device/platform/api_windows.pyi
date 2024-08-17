from typing import Callable, Generator, Tuple, Optional, List, Union

from module.device.platform.emulator_windows import EmulatorInstance
from module.device.platform.winapi import *

def closehandle(*args, fclose=CloseHandle) -> bool:
    """
    Close handles.

    Args:
        *args:
        fclose (callable):

    Returns:
        bool:
    """
    pass

def __yield_entries(entry32: Union[PROCESSENTRY32W, THREADENTRY32], snapshot: int, func: Callable) -> Generator:
    """
    Generates a loop that yields entries from a snapshot until the function fails or finishes.

    Args:
        entry32 (PROCESSENTRY32W or THREADENTRY32): Entry structure to be yielded, either for processes or threads.
        snapshot (int): Handle to the snapshot.
        func (callable): Next entry (e.g., Process32Next or Thread32Next).

    Yields:
        PROCESSENTRY32 or THREADENTRY32: The current entry in the snapshot.

    Raises:
        OSError if any winapi failed.
        IterationFinished if enumeration completed.
    """
    pass

def _enum_processes() -> Generator:
    """
    Enumerates all the processes currently running on the system.

    Yields:
        PROCESSENTRY32 or None: The current process entry or None if enumeration failed.

    Raises:
        OSError if CreateToolhelp32Snapshot or any winapi failed.
        IterationFinished if enumeration completed.
    """
    pass

def _enum_threads() -> Generator:
    """
    Enumerates all the threads currintly running on the system.

    Yields:
        THREADENTRY32 or None: The current thread entry or None if enumeration failed.

    Raises:
        OSError if CreateToolhelp32Snapshot or any winapi failed.
        IterationFinished if enumeration completed.
    """
    pass

def getfocusedwindow() -> Tuple[int, Optional[WINDOWPLACEMENT]]:
    """
    Get focused window.

    Returns:
        hwnd (int): Focused window hwnd
        WINDOWPLACEMENT: The window placement or None if it couldn't be retrieved.
    """
    pass

def setforegroundwindow(focusedwindow: Tuple[int, Optional[WINDOWPLACEMENT]]) -> bool:
    """
    Refocus foreground window.

    Args:
        focusedwindow (tuple(hwnd, WINDOWPLACEMENT) | tuple(hwnd, None)):

    Returns:
        bool:
    """
    pass

def refresh_window(focusedwindow: Tuple[int, Optional[WINDOWPLACEMENT]], max_attempts: int, interval: float) -> None:
    """
    Try to refresh window if previous window was out of focus.

    Args:
        focusedwindow (Tuple[int, Optional[WINDOWPLACEMENT]]): Previous focused window
        max_attempts (int):
        interval (float):

    Returns:

    """
    pass

def execute(command: str, silentstart: bool, start: bool) -> Tuple[PROCESS_INFORMATION, Tuple[int, Optional[WINDOWPLACEMENT]]]:
    """
    Create a new process.

    Args:
        command (str): process's commandline
        silentstart (bool): process's windowplacement
        start (bool): True if start emulator, False if not
        Example:
            '"E:\\Program Files\\Netease\\MuMu Player 12\\shell\\MuMuPlayer.exe" -v 1'

    Returns:
        process: PROCESS_INFORMATION,
        focusedwindow: tuple(hwnd, WINDOWPLACEMENT)

    Raises:
        EmulatorLaunchFailedError if CreateProcessW failed.
    """
    pass

def terminate_process(pid: int) -> bool:
    """
    Terminate emulator process.

    Args:
        pid (int): Emulator's pid

    Raises:
        OSError if OpenProcess failed.
    """
    pass

def get_hwnds(pid: int) -> List[int]:
    """
    Get window hwnds of the process by its ID.

    Args:
        pid (int): Emulator's pid

    Returns:
        hwnds (list): Emulator's possible window hwnds

    Raises:
        HwndNotFoundError if EnumWindows failed.
    """

def get_cmdline(pid: int) -> str:
    """
    Get command line of the process by its ID.

    Args:
        pid (int): Emulator's pid

    Returns:
        cmdline (str): process's command line
        Example:
            '"E:\\Program Files\\Netease\\MuMu Player 12\\shell\\MuMuPlayer.exe" -v 1'
    """
    pass

def kill_process_by_regex(regex: str) -> int:
    """
    Kill processes with cmdline match the given regex.

    Args:
        regex:

    Returns:
        int: Number of processes killed

    Raises:
        OSError if any winapi failed.
        IterationFinished if enumeration completed.
    """
    pass

def __get_creation_time(fopen: Callable, fgettime: Callable, access: int, identification: int) -> Optional[int]:
    """
    Args:
        fopen (callable):
        fgettime (callable):
        access (int):
        identification (int):

    Returns:
        int: creation time
    """
    pass

def _get_process_creation_time(pid: int) -> Optional[int]:
    """
    Get creation time of the process by its ID.

    Args:
        pid (int): Process id

    Returns:
        threadstarttime (int): Thread's start time

    Raises:
        OSError if OpenProcess failed.
    """
    pass

def _get_thread_creation_time(tid: int) -> Optional[int]:
    """
    Get creation time of the thread by its ID.

    Args:
        tid (int): Thread id

    Returns:
        threadstarttime (int): Thread's start time

    Raises:
        OSError if OpenThread failed.
    """
    pass

def get_thread(pid: int) -> int:
    """
    Get the main thread ID of the process by its ID.

    Args:
        pid (int): Emulator's pid

    Returns:
        mainthreadid (int): Emulator's main thread id

    Raises:
        OSError if any winapi failed.
        IterationFinished if enumeration completed.
    """
    pass

def _get_process(pid: int) -> PROCESS_INFORMATION:
    """
    Get emulator's handle.

    Args:
        pid (int): Emulator's pid

    Returns:
        tuple(processhandle, threadhandle, processid, mainthreadid) |
        tuple(None, None, processid, mainthreadid)
    """
    pass

def get_process(instance: EmulatorInstance) -> PROCESS_INFORMATION:
    """
    Get emulator's process.

    Args:
        instance (EmulatorInstance):

    Returns:
        tuple(processhandle, threadhandle, processid, mainthreadid) |
        tuple(None, None, processid, mainthreadid) | (if enum_process() failed)
        None (if enum_process() failed)

    Raises:
        OSError if any winapi failed.
        IterationFinished if enumeration completed.
    """
    pass

def switch_window(hwnds: List[int], arg: int = SW_SHOWNORMAL) -> bool:
    """
    Switch emulator's windowplacement to the given argument.

    Args:
        hwnds (list): Possible emulator's window hwnds
        arg (int): Emulator's windowplacement

    Returns:
        bool:
    """
    pass

def get_parent_pid(pid: int) -> int:
    """
    Get the ID of the parent process.

    Args:
        pid (int): Process ID

    Returns:
        int: ID of the parent process
    """
    pass

def get_exit_code(pid: int) -> int:
    """
    Get the exit code of the process.

    Args:
        pid (int): Process ID

    Returns:
        int: Exit code of the process
    """
    pass

def is_running(ppid: int = 0, pid: int = 0) -> bool:
    """
    Check if a process is still running.

    Args:
        ppid (int): Parent process ID
        pid (int): Process ID

    Returns:
        bool:
    """
    pass