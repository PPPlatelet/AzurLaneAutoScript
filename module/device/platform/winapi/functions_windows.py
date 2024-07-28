from abc import ABCMeta, abstractmethod
import typing as t
import threading
import time
from functools import wraps

from ctypes import POINTER, WINFUNCTYPE, WinDLL, c_size_t
from ctypes.wintypes import \
    HANDLE, DWORD, HWND, BOOL, INT, UINT, \
    LONG, ULONG, LPWSTR, LPCWSTR, \
    LPVOID, LPCVOID, LPARAM, PULONG

from module.device.platform.winapi.structures_windows import \
    SECURITY_ATTRIBUTES, STARTUPINFOW, WINDOWPLACEMENT, \
    PROCESS_INFORMATION, PROCESSENTRY32W, THREADENTRY32, \
    FILETIME

from module.logger import logger

user32      = WinDLL(name='user32',     use_last_error=True)
kernel32    = WinDLL(name='kernel32',   use_last_error=True)
ntdll       = WinDLL(name='ntdll',      use_last_error=True)

CreateProcessW                      = kernel32.CreateProcessW
CreateProcessW.argtypes             = [
    LPCWSTR,                        #lpApplicationName
    LPWSTR,                         #lpCommandLine
    POINTER(SECURITY_ATTRIBUTES),   #lpProcessAttributes
    POINTER(SECURITY_ATTRIBUTES),   #lpThreadAttributes
    BOOL,                           #bInheritHandles
    DWORD,                          #dwCreationFlags
    LPVOID,                         #lpEnvironment
    LPCWSTR,                        #lpCurrentDirectory
    POINTER(STARTUPINFOW),          #lpStartupInfo
    POINTER(PROCESS_INFORMATION)    #lpProcessInformation
]
CreateProcessW.restype              = BOOL

TerminateProcess                    = kernel32.TerminateProcess
TerminateProcess.argtypes           = [HANDLE, UINT]
TerminateProcess.restype            = BOOL

GetForegroundWindow                 = user32.GetForegroundWindow
GetForegroundWindow.argtypes        = []
GetForegroundWindow.restype         = HWND
SetForegroundWindow                 = user32.SetForegroundWindow
SetForegroundWindow.argtypes        = [HWND]
SetForegroundWindow.restype         = BOOL

GetWindowPlacement                  = user32.GetWindowPlacement
GetWindowPlacement.argtypes         = [HWND, POINTER(WINDOWPLACEMENT)]
GetWindowPlacement.restype          = BOOL
SetWindowPlacement                  = user32.SetWindowPlacement
SetWindowPlacement.argtypes         = [HWND, POINTER(WINDOWPLACEMENT)]
SetWindowPlacement.restype          = BOOL

ShowWindow                          = user32.ShowWindow
ShowWindow.argtypes                 = [HWND, INT]
ShowWindow.restype                  = BOOL

GetWindow                           = user32.GetWindow
GetWindow.argtypes                  = [HWND, UINT]
GetWindow.restype                   = HWND

EnumWindowsProc                     = WINFUNCTYPE(BOOL, HWND, LPARAM, use_last_error=True)
EnumWindows                         = user32.EnumWindows
EnumWindows.argtypes                = [EnumWindowsProc, LPARAM]
EnumWindows.restype                 = BOOL
GetWindowThreadProcessId            = user32.GetWindowThreadProcessId
GetWindowThreadProcessId.argtypes   = [HWND, POINTER(DWORD)]
GetWindowThreadProcessId.restype    = DWORD

OpenProcess                         = kernel32.OpenProcess
OpenProcess.argtypes                = [DWORD, BOOL, DWORD]
OpenProcess.restype                 = HANDLE
OpenThread                          = kernel32.OpenThread
OpenThread.argtypes                 = [DWORD, BOOL, DWORD]
OpenThread.restype                  = HANDLE

CreateToolhelp32Snapshot            = kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.argtypes   = [DWORD, DWORD]
CreateToolhelp32Snapshot.restype    = HANDLE

CloseHandle                         = kernel32.CloseHandle
CloseHandle.argtypes                = [HANDLE]
CloseHandle.restype                 = BOOL

Process32First                      = kernel32.Process32First
Process32First.argtypes             = [HANDLE, POINTER(PROCESSENTRY32W)]
Process32First.restype              = BOOL

Process32Next                       = kernel32.Process32Next
Process32Next.argtypes              = [HANDLE, POINTER(PROCESSENTRY32W)]
Process32Next.restype               = BOOL

Thread32First                       = kernel32.Thread32First
Thread32First.argtypes              = [HANDLE, POINTER(THREADENTRY32)]
Thread32First.restype               = BOOL

Thread32Next                        = kernel32.Thread32Next
Thread32Next.argtypes               = [HANDLE, POINTER(THREADENTRY32)]
Thread32Next.restype                = BOOL

GetProcessTimes                     = kernel32.GetProcessTimes
GetProcessTimes.argtypes            = [
    HANDLE,
    POINTER(FILETIME),
    POINTER(FILETIME),
    POINTER(FILETIME),
    POINTER(FILETIME)
]
GetProcessTimes.restype             = BOOL

GetThreadTimes                      = kernel32.GetThreadTimes
GetThreadTimes.argtypes             = [
    HANDLE,
    POINTER(FILETIME),
    POINTER(FILETIME),
    POINTER(FILETIME),
    POINTER(FILETIME)
]
GetThreadTimes.restype              = BOOL

GetLastError                        = kernel32.GetLastError
GetLastError.argtypes               = []
GetLastError.restype                = DWORD

SIZE_T                              = c_size_t
NTSTATUS                            = LONG
ReadProcessMemory                   = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes          = [HANDLE, LPCVOID, LPVOID, SIZE_T, POINTER(SIZE_T)]
ReadProcessMemory.restype           = BOOL
NtQueryInformationProcess           = ntdll.NtQueryInformationProcess
NtQueryInformationProcess.argtypes  = [HANDLE, INT, LPVOID, ULONG, PULONG]
NtQueryInformationProcess.restype   = NTSTATUS

class Handle(metaclass=ABCMeta):
    """
    Abstract base Handle class.
    Please override these functions if needed.
    """
    _handle     = None
    _func       = None
    _exitfunc   = None

    def __init__(self, *args, **kwargs) -> None:
        self._handle = self._func(*self.__get_init_args__(*args, **kwargs))
        if not self:
            report(
                f"{self._func.__name__} failed.",
                uselog=kwargs.get('uselog', True),
                raiseexcept=kwargs.get("raiseexcept", True)
            )

    def __enter__(self) -> int:
        return self._handle

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self:
            self._exitfunc(self._handle)
            self._handle = None

    def __bool__(self) -> bool:
        return not self._is_invalid_handle()

    @abstractmethod
    def __get_init_args__(self, *args, **kwargs) -> tuple: ...
    @abstractmethod
    def _is_invalid_handle(self) -> bool: ...

class ProcessHandle(Handle):
    _func       = OpenProcess
    _exitfunc   = CloseHandle

    def __get_init_args__(self, access, pid, uselog, raiseexcept) -> tuple:
        return access, False, pid

    def _is_invalid_handle(self) -> bool:
        return self._handle is None

class ThreadHandle(Handle):
    _func       = OpenThread
    _exitfunc   = CloseHandle

    def __get_init_args__(self, access, pid, uselog, raiseexcept) -> tuple:
        return access, False, pid

    def _is_invalid_handle(self) -> bool:
        return self._handle is None

class CreateSnapshot(Handle):
    _func       = CreateToolhelp32Snapshot
    _exitfunc   = CloseHandle

    def __get_init_args__(self, access) -> tuple:
        return access, DWORD(0)

    def _is_invalid_handle(self) -> bool:
        from module.device.platform.winapi.const_windows import INVALID_HANDLE_VALUE
        return self._handle == INVALID_HANDLE_VALUE

def report(
        msg: str            = '',
        *args: tuple,
        statuscode: int     = -1,
        uselog: bool        = True,
        level: int          = 40,
        handle: int         = 0,
        raiseexcept: bool   = True,
        exception: type     = OSError,
        **kwargs: dict,
) -> None:
    """
    Report any exception.
    
    Args:
        msg (str):
        args:
        statuscode (int):
        uselog (bool):
        level (int): Logging level
        handle (int): Handle to close
        raiseexcept (bool): Flag indicating whether to raise
        exception (Type[Exception]): Exception class to raise
        kwargs:

    Raises:
        Optional[OSError]:
    """
    from module.logger import logger
    if statuscode == -1:
        statuscode = GetLastError()
    message = f"{msg} Status code: 0x{statuscode:08x} "
    if args:
        message += f"args: {' '.join(map(str, args))} "
    if kwargs:
        message += f"kwargs: {kwargs} "
    if uselog:
        logger.log(level, message)
    if handle:
        CloseHandle(handle)
    if raiseexcept:
        raise exception(message)

def fstr(formatstr: str) -> t.Union[int, str]:
    try:
        return int(formatstr, 16)
    except ValueError:
        return formatstr.replace(r"\\", "/").replace("\\", "/").replace('"', '"')

def open_process(access, pid, uselog=False, raiseexcept=True) -> ProcessHandle:
    return ProcessHandle(access, pid, uselog=uselog, raiseexcept=raiseexcept)

def open_thread(access, tid, uselog=False, raiseexcept=True) -> ThreadHandle:
    return ThreadHandle(access, tid, uselog=uselog, raiseexcept=raiseexcept)

def create_snapshot(arg) -> CreateSnapshot:
    return CreateSnapshot(arg)

def get_func_path(func):
    module = func.__module__
    if hasattr(func, '__qualname__'):
        qualname = func.__qualname__
    else:
        qualname = func.__name__
    return f"{module}::{qualname.replace('.', '::')}"

class LogLevelManager:
    def __init__(self, new_level):
        self.new_level = new_level
        self.original_level = logger.level

    def __enter__(self):
        logger.setLevel(self.new_level)

    def __exit__(self, exc_type, exc_val, exc_tb):
        logger.setLevel(self.original_level)

def Timer(timeout=1):
    import logging

    def decorator(func):
        if not callable(func):
            raise TypeError(f"Expected a callable, but got {type(func).__name__}")

        @wraps(func)
        def wrapper(self, *args, **kwargs):
            func_path = get_func_path(func)
            result = [TimeoutError(f"Function '{func_path}' timed out after {timeout} seconds")]
            stop_event = threading.Event()

            with LogLevelManager(logging.DEBUG):
                logger.debug(f"Entering {func_path}")
                start_time = time.time()

                def target():
                    try:
                        result[0] = func(self, *args, **kwargs)
                    except Exception as e:
                        result[0] = e
                    finally:
                        stop_event.set()

                thread = threading.Thread(target=target, name=f"Thread-{func_path}")
                thread.start()
                if not stop_event.wait(timeout):
                    raise TimeoutError(f"Function '{func_path}' timed out after {timeout} seconds")

                end_time = time.time()
                if isinstance(result[0], Exception):
                    raise result[0]
                logger.debug(f"Exiting {func_path}")
                logger.debug(f"{func_path} executed in {end_time - start_time:.4f} seconds")
            return result[0]
        return wrapper
    return decorator
