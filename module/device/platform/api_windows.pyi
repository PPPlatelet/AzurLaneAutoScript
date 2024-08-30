from typing import Generator, NewType, List, Tuple

from module.device.platform.emulator_windows import EmulatorInstance
from module.device.platform.winapi import *

LPPROCESSENTRY32W   = NewType('LPPROCESSENTRY32W',  POINTER(PROCESSENTRY32W))
LPTHREADENTRY32     = NewType('LPTHREADENTRY32',    POINTER(THREADENTRY32))
LPFILETIME          = NewType('LPFILETIME',         POINTER(FILETIME))

def close_handle(*args, fclose: Callable[[HANDLE], None] = CloseHandle) -> bool:
    """
    Close handles.

    Args:
        *args (int | c_void_p): Handles to close.
        fclose (Optional[CloseHandle]):

    Returns:
        bool:
    """
    pass

def __yield_entries(
        entry32:    Union[PROCESSENTRY32W, THREADENTRY32],
        snapshot:   HANDLE,
        func:       Callable[[HANDLE, Union[LPPROCESSENTRY32W, LPTHREADENTRY32]], bool]
) -> Generator[Union[PROCESSENTRY32W, THREADENTRY32], None, None]:
    """
    Generates a loop that yields entries from a snapshot until the function fails or finishes.

    Args:
        entry32 (PROCESSENTRY32W | THREADENTRY32): Entry structure to be yielded, either for processes or threads.
        snapshot (HANDLE): Handle to the snapshot.
        func (Process32Next | Thread32Next): Next entry.

    Yields:
        (lppe32 | lpte32) (PROCESSENTRY32W | THREADENTRY32): Current process/thread entry.

    Raises:
        OSError: If any winapi failed.
        IterationFinished: If enumeration completed.
    """
    pass

def _enum_processes() -> Generator[PROCESSENTRY32W, None, None]:
    """
    Enumerates all the processes currently running on the system.

    Yields:
        lppe32 (PROCESSENTRY32): Current process entry.

    Raises:
        OSError: If CreateToolhelp32Snapshot or any winapi failed.
        IterationFinished: If enumeration completed.
    """
    pass

def _enum_threads() -> Generator[THREADENTRY32, None, None]:
    """
    Enumerates all the threads currently running on the system.

    Yields:
        lpte32 (THREADENTRY32): Current thread entry.

    Raises:
        OSError: If CreateToolhelp32Snapshot or any winapi failed.
        IterationFinished: If enumeration completed.
    """
    pass

def get_focused_window() -> Tuple[HWND, Optional[WINDOWPLACEMENT]]:
    """
    Retrieves the handle and placement of the currently focused window.

    Returns:
        (hwnd, wp) (HWND & WINDOWPLACEMENT): Currently window's hwnd and placement.
    """
    pass

def set_focus_to_window(focusedwindow: Tuple[HWND, Optional[WINDOWPLACEMENT]]) -> bool:
    """
    Focus to a window.

    Args:
        focusedwindow (Tuple(HWND, Optional[WINDOWPLACEMENT])): Focused window's hwnd and placement.

    Returns:
        bool:
    """
    pass

def refresh_window(
        focusedwindow: Tuple[HWND, Optional[WINDOWPLACEMENT]],
        max_attempts: int = 10,
        interval: float = 0.5
) -> None:
    """
    Attempts to refocus on the original window if the current focused window changes.\n
    This function is only used in multithreading.

    Args:
        focusedwindow (Tuple[HWND, Optional[WINDOWPLACEMENT]]): Originally focused window's hwnd and placement.
        max_attempts (int): The maximum number of attempts to refocus.
        interval (float): The interval (in seconds) between attempts.

    Returns:
        None:
    """
    pass

def execute(
        command: str,
        silentstart: bool,
        start: bool
) -> Tuple[Optional[PROCESS_INFORMATION], Tuple[HWND, Optional[WINDOWPLACEMENT]]]:
    """
    Create a new process.

    Args:
        command (str): Command-line arguments of the process.
        silentstart (bool): Window placement of the process.
        start (bool): True if start emulator, False if not.

    Examples:
        >>> print(execute('"E:/Program Files/Netease/MuMu Player 12/shell/MuMuPlayer.exe" -v 1', False, True))
        -> 'PROCESS_INFORMATION(1, 2, 3, 4), (114514, WINDOWPLACEMENT(1, 2, 3, POINT(1, 2), POINT(1, 2), RECT(1, 2, 3, 4)))'

    Returns:
        (lpProcessInformation, focusedwindow) (Optional[PROCESS_INFORMATION], Tuple[HWND, Optional[WINDOWPLACEMENT]]):
            PROCESS_INFORMATION structure of the new process,
            Currently focused window's hwnd and placement.

    Raises:
        EmulatorLaunchFailedError: If CreateProcessW failed.
    """
    pass

def terminate_process(pid: int) -> bool:
    """
    Terminate a process.

    Args:
        pid (int): Process ID.

    Raises:
        OSError: If OpenProcess failed.
    """
    pass

def get_hwnds(pid: int) -> List[HWND]:
    """
    Get window hwnds of the process.

    Args:
        pid (int): Process ID.

    Returns:
        hwnds (list): Window hwnds of the process.

    Raises:
        HwndNotFoundError: If EnumWindows failed.
    """

def get_cmdline(pid: int) -> str:
    """
    Get command line of the process.

    Args:
        pid (int): Process ID.

    Returns:
        cmdline (str): Command-line arguments of the process.

    Examples:
        >>> print(get_cmdline(12345))
        '"E:/Program Files/Netease/MuMu Player 12/shell/MuMuPlayer.exe" -v 1'
    """
    pass

def kill_process_by_regex(regex: str) -> int:
    """
    Kill processes with cmdline match the given regex.

    Args:
        regex (str):

    Returns:
        count (int): The number of processes that were killed.

    Raises:
        OSError: If any winapi failed.
        IterationFinished: If enumeration completed.
    """
    pass

def __get_time(
        fopen:          Callable[[int, int, bool, bool], Union[ProcessHandle, ThreadHandle]],
        fgettime:       Callable[[HANDLE, LPFILETIME, LPFILETIME, LPFILETIME, LPFILETIME], bool],
        access:         int,
        identification: int,
        select:         int = 0
) -> Optional[int]:
    """
    Args:
        fopen (callable):
        fgettime (callable):
        access (int):
        identification (int):
        select (int):

    Returns:
        int:
    """
    pass

def _get_process_creation_time(pid: int) -> Optional[int]:
    """
    Get creation time of the process.

    Args:
        pid (int): Process id

    Returns:
        threadstarttime (int): Thread's start time

    Raises:
        OSError: If OpenProcess failed.
    """
    pass

def _get_thread_creation_time(tid: int) -> Optional[int]:
    """
    Get creation time of the thread.

    Args:
        tid (int): Thread id

    Returns:
        threadstarttime (int): Thread's start time

    Raises:
        OSError: If OpenThread failed.
    """
    pass

def get_thread(pid: int) -> int:
    """
    Get the main thread ID of the process.

    Args:
        pid (int): Process ID.

    Returns:
        mainthreadid (int): Main thread ID of the process.

    Raises:
        OSError: If any winapi failed.
        IterationFinished: If enumeration completed.
    """
    pass

def _get_process(pid: int) -> PROCESS_INFORMATION:
    """
    Get PROCESS_INFORMATION of the process.

    Args:
        pid (int): Process ID.

    Returns:
        tuple (int | None, int | None, int, int): PROCESS_INFORMATION of the process.
    """
    pass

def get_process(instance: EmulatorInstance) -> PROCESS_INFORMATION:
    """
    Get PROCESS_INFORMATION Structure of the process.

    Args:
        instance (EmulatorInstance):

    Returns:
        tuple (int | None, int | None, int, int): PROCESS_INFORMATION of the process.

    Raises:
        OSError: If any winapi failed.
        IterationFinished: If enumeration completed.
    """
    pass

def switch_window(hwnds: List[HWND], arg: int = SW_SHOWNORMAL) -> bool:
    """
    Switch window placement to the given argument.

    Args:
        hwnds (List[HWND]): Possible window hwnds of the process.
        arg (int): Target window placement.

    Returns:
        bool: True if switch successed, False if switch failed.
    """
    pass

def get_parent_pid(pid: int) -> int:
    """
    Get the ID of the parent process.

    Args:
        pid (int): Process ID.

    Returns:
        ppid (int): Parent process ID.
    """
    pass

def get_exit_code(pid: int) -> int:
    """
    Get the exit code of the process.

    Args:
        pid (int): Process ID.

    Returns:
        exit_code (int): Exit code of the process
    """
    pass

def is_running(pid: int = 0, ppid: int = 0) -> bool:
    """
    Check if a process is still running.

    Args:
        pid (int): Parent process ID.
        ppid (int): Process ID.

    Returns:
        bool: True if process is still running, False if process has some condition.
    """
    pass