from abc import ABCMeta, abstractmethod
import time
from functools import wraps
from typing import Any, Callable, Optional, Union

from ctypes import POINTER, WINFUNCTYPE, WinDLL, c_size_t, c_void_p
from ctypes.wintypes import \
    HANDLE, DWORD, HWND, BOOL, INT, UINT, \
    LONG, ULONG, LPWSTR, LPCWSTR, \
    LPVOID, LPCVOID, LPARAM, PULONG, \
    BYTE, PDWORD, PBOOL, PHANDLE

from module.device.platform.winapi import WinapiConstants
from module.device.platform.winapi.structures_windows import \
    SECURITY_ATTRIBUTES, STARTUPINFOW, WINDOWPLACEMENT, \
    PROCESS_INFORMATION, PROCESSENTRY32W, THREADENTRY32, \
    FILETIME, SID_IDENTIFIER_AUTHORITY, SID, LUID, TOKEN_PRIVILEGES
from module.logger import logger

class WinapiFunctions(WinapiConstants):
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
        PHANDLE
    ]
    DuplicateTokenEx.restype            = LONG

    AllocateAndInitializeSid            = advapi32.AllocateAndInitializeSid
    AllocateAndInitializeSid.argtypes   = [
        POINTER(SID_IDENTIFIER_AUTHORITY),
        BYTE,
        DWORD,
        DWORD,
        DWORD,
        DWORD,
        DWORD,
        DWORD,
        DWORD,
        DWORD,
        PBOOL
    ]

    CheckTokenMembership                = advapi32.CheckTokenMembership
    CheckTokenMembership.argtypes       = [HANDLE, POINTER(SID), PBOOL]
    CheckTokenMembership.restype        = BOOL

    FreeSid                             = advapi32.FreeSid
    FreeSid.argtypes                    = [POINTER(SID)]
    FreeSid.restype                     = LPVOID

    AdjustTokenPrivileges               = advapi32.AdjustTokenPrivileges
    AdjustTokenPrivileges.argtypes      = [
        HANDLE,
        BOOL,
        POINTER(TOKEN_PRIVILEGES),
        DWORD,
        POINTER(TOKEN_PRIVILEGES),
        PDWORD
    ]
    AdjustTokenPrivileges.restype       = BOOL

    GetCurrentProcess                   = kernel32.GetCurrentProcess
    GetCurrentProcess.argtypes          = []
    GetCurrentProcess.restype           = HANDLE

    LookupPrivilegeValueW               = advapi32.LookupPrivilegeValueW
    LookupPrivilegeValueW.argtypes      = [LPCWSTR, LPCWSTR, POINTER(LUID)]
    LookupPrivilegeValueW.restype       = BOOL

    CreateProcessWithTokenW             = advapi32.CreateProcessWithTokenW
    CreateProcessWithTokenW.argtypes    = [
        HANDLE,
        DWORD,
        LPCWSTR,
        LPWSTR,
        DWORD,
        LPVOID,
        LPCWSTR,
        POINTER(STARTUPINFOW),
        POINTER(PROCESS_INFORMATION)
    ]
    CreateProcessWithTokenW.restype     = BOOL

    CreateProcessAsUserW                = advapi32.CreateProcessAsUserW
    CreateProcessAsUserW.argtypes       = [
        HANDLE,
        LPCWSTR,
        LPWSTR,
        POINTER(SECURITY_ATTRIBUTES),
        POINTER(SECURITY_ATTRIBUTES),
        BOOL,
        DWORD,
        LPVOID,
        LPCWSTR,
        POINTER(STARTUPINFOW),
        POINTER(PROCESS_INFORMATION)
    ]
    CreateProcessAsUserW.restype        = BOOL

    CreateProcessW                      = kernel32.CreateProcessW
    CreateProcessW.argtypes             = [
        LPCWSTR,
        LPWSTR,
        POINTER(SECURITY_ATTRIBUTES),
        POINTER(SECURITY_ATTRIBUTES),
        BOOL,
        DWORD,
        LPVOID,
        LPCWSTR,
        POINTER(STARTUPINFOW),
        POINTER(PROCESS_INFORMATION)
    ]
    CreateProcessW.restype              = BOOL

    CreateProcessWithLogonW             = advapi32.CreateProcessWithLogonW
    CreateProcessWithLogonW.argtypes    = [
        LPCWSTR,                        # lpUsername
        LPCWSTR,                        # lpDomain
        LPCWSTR,                        # lpPassword
        DWORD,                          # dwLogonFlags
        LPCWSTR,                        # lpApplicationName
        LPWSTR,                         # lpCommandLine
        DWORD,                          # dwCreationFlags
        LPVOID,                         # lpEnvironment
        LPCWSTR,                        # lpCurrentDirectory
        POINTER(STARTUPINFOW),          # lpStartupInfo
        POINTER(PROCESS_INFORMATION)    # lpProcessInformation
    ]
    CreateProcessWithLogonW.restype     = BOOL

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
    GetWindowThreadProcessId.argtypes   = [HWND, PDWORD]
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
    GetExitCodeProcess.argtypes         = [HANDLE, PDWORD]
    GetExitCodeProcess.restype          = BOOL

    GetLastError                        = kernel32.GetLastError
    GetLastError.argtypes               = []
    GetLastError.restype                = DWORD

    SIZE_T                              = c_size_t
    PSIZE_T                             = POINTER(SIZE_T)
    NTSTATUS                            = LONG
    ReadProcessMemory                   = kernel32.ReadProcessMemory
    ReadProcessMemory.argtypes          = [HANDLE, LPCVOID, LPVOID, SIZE_T, PSIZE_T]
    ReadProcessMemory.restype           = BOOL

    NtQueryInformationProcess           = ntdll.NtQueryInformationProcess
    NtQueryInformationProcess.argtypes  = [HANDLE, INT, LPVOID, ULONG, PULONG]
    NtQueryInformationProcess.restype   = NTSTATUS

    def report(
            self,
            msg: str            = '',
            *args: tuple,
            report_status: bool = True,
            status_code: int    = -1,
            use_log: bool       = True,
            log_level: int      = 40,
            raise_exc: bool     = True,
            exc_type: type      = OSError,
            **kwargs: dict
    ) -> None:
        """
        Report any exception.

        Args:
            msg (str): The message to report.
            args (tuple): Additional arguments.
            report_status (bool): Whether to report the status code.
            status_code (int): The status code to report.
            use_log (bool): Whether to log the message.
            log_level (int): Logging level
            raise_exc (bool): Flag indicating whether to raise an exception.
            exc_type (Type[Exception]): Exception class to raise.
            kwargs (dict): Additional keyword arguments.

        Raises:
            Optional[OSError]: The specified exception class if raise_exc is True.
        """
        message: list = [msg]
        if report_status:
            if status_code == -1:
                status_code = self.GetLastError()
            message.append(f"Status code: 0x{status_code:08x}")
        if args:
            message.append(f"args: {' '.join(map(str, args))}")
        if kwargs:
            message.append(f"kwargs: {kwargs}")
        message: str = '. '.join(message)
        if use_log:
            logger.log(log_level, message)
        if raise_exc:
            raise exc_type(message)

class Handle_(metaclass=ABCMeta):
    """
    Abstract base Handle class.
    Please override these functions if needed.
    """
    functions = WinapiFunctions()
    _handle:    Optional[c_void_p]
    _func:      Callable[..., c_void_p]
    _exitfunc:  Callable[[c_void_p], None]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if hasattr(self, '_func'):
            self._handle = HANDLE(self._func(*self.__get_init_args__(*args, **kwargs)))
            assert self, self.functions.report(
                f"{self._func.__name__} failed.",
                use_log=kwargs.get('use_log', True),
                raise_exc=kwargs.get("raise_exc", True)
            )

    def __enter__(self) -> HANDLE:
        return self._handle

    def __exit__(self, exc_type: Optional[type], exc_val: Optional[BaseException], exc_tb: Optional[Any]):
        if self and hasattr(self, '_exitfunc'):
            self._exitfunc(self._handle)
            self._handle = None

    def __bool__(self) -> bool:
        return not self._is_invalid_handle()

    @abstractmethod
    def __get_init_args__(self, *args: Any, **kwargs: Any) -> tuple: ...

    def _is_invalid_handle(self) -> bool:
        return self._handle.value is None

class ProcessHandle(Handle_):
    """
    Process handle class.
    """
    _func       = Handle_.functions.OpenProcess
    _exitfunc   = Handle_.functions.CloseHandle

    def __get_init_args__(self, access: int, pid: int, uselog: bool, raise_: bool) -> tuple:
        return access, False, pid

class ThreadHandle(Handle_):
    """
    Thread handle class.
    """
    _func       = Handle_.functions.OpenThread
    _exitfunc   = Handle_.functions.CloseHandle

    def __get_init_args__(self, access: int, tid: int, uselog: bool, raise_: bool) -> tuple:
        return access, False, tid

class CreateSnapshot(Handle_):
    """
    Snapshot handle class.
    """
    _func       = Handle_.functions.CreateToolhelp32Snapshot
    _exitfunc   = Handle_.functions.CloseHandle

    def __get_init_args__(self, access, uselog: bool, raise_: bool) -> tuple:
        return access, DWORD(0)

    def _is_invalid_handle(self) -> bool:
        return self._handle == self.functions.INVALID_HANDLE_VALUE

def open_process(access: int, pid: int, uselog: bool = False, raise_: bool = True) -> ProcessHandle:
    return ProcessHandle(access, pid, uselog=uselog, raise_=raise_)

def open_thread(access: int, tid: int, uselog: bool = False, raise_: bool = True) -> ThreadHandle:
    return ThreadHandle(access, tid, uselog=uselog, raise_=raise_)

def create_snapshot(access: int, uselog: bool = False, raise_: bool = True) -> CreateSnapshot:
    return CreateSnapshot(access, uselog=uselog, raise_=raise_)

def hex_or_normalize_path(input_str: str) -> Union[int, str]:
    """
    Args:
        input_str (str):

    Returns:
        (int | str):
    """
    try:
        return int(input_str, 16)
    except ValueError:
        return input_str.replace(r"\\", "/").replace("\\", "/").replace('\"', '"')

def get_func_path(func: Callable[..., Any]) -> str:
    """
    Get a function's relative path.

    Args:
        func (Callable[..., Any]):

    Examples:
        >>> print(get_func_path(WinapiFunctions().report))
        -> 'module.device.platform.winapi.functions_windows.report'
        >>> print(get_func_path(FILETIME.__init_subclass__))
        -> 'module.device.platform.winapi.structures_windows.Structure::__init_subclass__'

    Returns:
        str:
    """
    funcpath: list = []
    if hasattr(func, '__module__'):
        funcpath.append(getattr(func, '__module__'))
    else:
        pass
    if hasattr(func, '__qualname__'):
        funcpath.append(getattr(func, '__qualname__').replace('.', '::'))
    else:
        funcpath.append(getattr(func, '__name__').replace('.', '::'))
    funcpath: str = '.'.join(funcpath)
    return funcpath

def timer(timeout: int = 1):
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
