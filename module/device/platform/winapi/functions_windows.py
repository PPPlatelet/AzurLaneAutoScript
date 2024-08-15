from abc import ABCMeta, abstractmethod
import typing as t
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
shell32     = WinDLL(name='shell32',    use_last_error=True)
advapi32    = WinDLL(name='advapi32',   use_last_error=True)

IsUserAnAdmin                       = shell32.IsUserAnAdmin
IsUserAnAdmin.argtypes              = []
IsUserAnAdmin.restype               = BOOL

OpenProcessToken                    = advapi32.OpenProcessToken
OpenProcessToken.argtypes           = [HANDLE, DWORD, POINTER(HANDLE)]
OpenProcessToken.restype            = BOOL

DuplicateTokenEx                    = advapi32.DuplicateTokenEx
DuplicateTokenEx.argtypes           = [
    HANDLE,
    DWORD,
    POINTER(SECURITY_ATTRIBUTES),
    ULONG,
    ULONG,
    POINTER(HANDLE)
]
DuplicateTokenEx.restype            = LONG

CreateProcessAsUserW                = advapi32.CreateProcessWithTokenW
CreateProcessAsUserW.argtypes       = [
    HANDLE,                         #hToken
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
CreateProcessAsUserW.restype        = BOOL

GetCurrentProcess                   = kernel32.GetCurrentProcess
GetCurrentProcess.argtypes          = []
GetCurrentProcess.restype           = HANDLE

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

GetExitCodeProcess                  = kernel32.GetExitCodeProcess
GetExitCodeProcess.argtypes         = [HANDLE, POINTER(DWORD)]
GetExitCodeProcess.restype          = BOOL

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

class _Handle(metaclass=ABCMeta):
    """
    Abstract base Handle class.
    Please override these functions if needed.
    """
    _handle     = None
    _func       = None
    _exitfunc   = None

    def __init__(self, *args, **kwargs) -> None:
        self._handle = self._func(*self.__get_init_args__(*args, **kwargs))
        assert self, \
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

class ProcessHandle(_Handle):
    _func       = OpenProcess
    _exitfunc   = CloseHandle

    def __get_init_args__(self, access, pid, uselog, raiseexcept) -> tuple:
        return access, False, pid

    def _is_invalid_handle(self) -> bool:
        return self._handle is None

class ThreadHandle(_Handle):
    _func       = OpenThread
    _exitfunc   = CloseHandle

    def __get_init_args__(self, access, pid, uselog, raiseexcept) -> tuple:
        return access, False, pid

    def _is_invalid_handle(self) -> bool:
        return self._handle is None

class CreateSnapshot(_Handle):
    _func       = CreateToolhelp32Snapshot
    _exitfunc   = CloseHandle

    def __get_init_args__(self, access) -> tuple:
        return access, DWORD(0)

    def _is_invalid_handle(self) -> bool:
        from module.device.platform.winapi.const_windows import INVALID_HANDLE_VALUE
        return self._handle == INVALID_HANDLE_VALUE

class Handle(int, _Handle):
    _func       = int
    closed      = False

    def Close(self, fclose=CloseHandle):
        if not self.closed:
            self.closed = True
            fclose(self)

    def Detach(self):
        if not self.closed:
            self.closed = True
            return int(self)
        raise ValueError("already closed")

    def __repr__(self):
        return f"{self.__class__.__name__}({int(self)})"

    def __get_init_args__(self, *args, **kwargs) -> tuple:
        return ()

    def _is_invalid_handle(self) -> bool:
        return False  # assert the handle is valid

    __del__ = Close
    __str__ = __repr__

def report(
        msg: str            = '',
        *args: tuple,
        reportstatus: bool  = True,
        statuscode: int     = -1,
        uselog: bool        = True,
        level: int          = 40,
        raiseexcept: bool   = True,
        exception: type     = OSError,
        **kwargs: dict,
) -> None:
    """
    Report any exception.
    
    Args:
        msg (str):
        args:
        reportstatus (bool):
        statuscode (int):
        uselog (bool):
        level (int): Logging level
        raiseexcept (bool): Flag indicating whether to raise
        exception (Type[Exception]): Exception class to raise
        kwargs:

    Raises:
        Optional[OSError]:
    """
    message: list = [msg]
    if reportstatus:
        if statuscode == -1:
            statuscode = GetLastError()
        message.append(f"Status code: 0x{statuscode:08x}")
    if args:
        message.append(f"args: {' '.join(map(str, args))}")
    if kwargs:
        message.append(f"kwargs: {kwargs}")
    message: str = '. '.join(message)
    if uselog:
        logger.log(level, message)
    if raiseexcept:
        raise exception(message)

def fstr(formatstr: str) -> t.Union[int, str]:
    try:
        return int(formatstr, 16)
    except ValueError:
        return formatstr.replace(r"\\", "/").replace("\\", "/").replace('"', '"')

def open_process(access, pid, *, uselog=False, raiseexcept=True) -> ProcessHandle:
    return ProcessHandle(access, pid, uselog=uselog, raiseexcept=raiseexcept)

def open_thread(access, tid, *, uselog=False, raiseexcept=True) -> ThreadHandle:
    return ThreadHandle(access, tid, uselog=uselog, raiseexcept=raiseexcept)

def create_snapshot(arg) -> CreateSnapshot:
    return CreateSnapshot(arg)

def get_func_path(func) -> str:
    module = func.__module__
    if hasattr(func, '__qualname__'):
        qualname = func.__qualname__
    else:
        qualname = func.__name__
    return f"{module.replace('.', '::')}::{qualname.replace('.', '::')}"

def Timer(timeout=1):
    import logging
    from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
    executor = ThreadPoolExecutor(max_workers=1)

    def decorator(func):
        if not callable(func):
            raise TypeError(f"Expected a callable, but got {type(func).__name__}")

        @wraps(func)
        def wrapper(*args, **kwargs):
            func_path: str = get_func_path(func)

            original_level = logger.level
            logger.setLevel(logging.DEBUG)

            logger.debug(f"{func_path} | Enter")
            start_time = time.perf_counter()

            try:
                result = executor.submit(func, *args, **kwargs).result(timeout)
            except FuturesTimeoutError:
                logger.error(f"{func_path} timed out after {timeout} seconds")
                raise TimeoutError(f"{func_path} timed out after {timeout} seconds")
            except Exception as e:
                logger.error(f"{func_path} failed: {e}")
                raise e

            execution_time = (time.perf_counter() - start_time) * 1e3
            logger.debug(f"{func_path} | Leave, {execution_time} ms")

            logger.setLevel(original_level)

            return result
        return wrapper
    return decorator
