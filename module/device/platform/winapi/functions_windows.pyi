from abc import ABCMeta, abstractmethod
from typing import Any, Callable, Dict, NewType, Optional, Tuple, Type, Union

from ctypes import POINTER, WINFUNCTYPE, WinDLL, c_size_t
from ctypes.wintypes import \
    HANDLE, DWORD, HWND, BOOL, INT, UINT, \
    LONG, ULONG, LPWSTR, LPCWSTR, \
    LPVOID, LPCVOID, LPARAM, PULONG, PHANDLE, PDWORD
from module.device.platform.winapi.structures_windows import \
    SECURITY_ATTRIBUTES, STARTUPINFOW, WINDOWPLACEMENT, \
    PROCESS_INFORMATION, PROCESSENTRY32W, THREADENTRY32, \
    FILETIME, PEB, RTL_USER_PROCESS_PARAMETERS, TOKEN_GROUPS

user32:     WinDLL
kernel32:   WinDLL
ntdll:      WinDLL
shell32:    WinDLL
advapi32:   WinDLL

SIZE_T                          = c_size_t
LPSIZE_T                        = NewType('LPSIZE_T',                       POINTER(SIZE_T))
LPSECURITY_ATTRIBUTES           = NewType('LPSECURITY_ATTRIBUTES',          POINTER(SECURITY_ATTRIBUTES))
LPTOKEN_GROUPS                  = NewType('LPTOKEN_GROUPS',                 POINTER(TOKEN_GROUPS))
LPSTARTUPINFOW                  = NewType('LPSTARTUPINFOW',                 POINTER(STARTUPINFOW))
LPFILETIME                      = NewType('LPFILETIME',                     POINTER(FILETIME))
LPPROCESSENTRY32W               = NewType('LPPROCESSENTRY32W',              POINTER(PROCESSENTRY32W))
LPPROCESS_INFORMATION           = NewType('LPPROCESS_INFORMATION',          POINTER(PROCESS_INFORMATION))
LPWINDOWPLACEMENT               = NewType('LPWINDOWPLACEMENT',              POINTER(WINDOWPLACEMENT))
LPTHREADENTRY32                 = NewType('LPTHREADENTRY32',                POINTER(THREADENTRY32))
PPEB                            = NewType('PPEB',                           POINTER(PEB))
LPRTL_USER_PROCESS_PARAMETERS   = NewType('LPRTL_USER_PROCESS_PARAMETERS',  POINTER(RTL_USER_PROCESS_PARAMETERS))

def IsUserAnAdmin() -> BOOL: ...

def OpenProcessToken(ProcessHandle_: HANDLE, DesiredAccess: DWORD, TokenHandle: PHANDLE) -> BOOL: ...

def DuplicateTokenEx(
    hExistingToken:     HANDLE,
    dwDesiredAccess:    DWORD,
    lpTokenAttributes:  LPSECURITY_ATTRIBUTES,
    ImpersonationLevel: ULONG,
    TokenType:          ULONG,
    phNewToken:         PHANDLE
) -> LONG: ...

def GetCurrentProcess() -> HANDLE: ...

def AdjustTokenGroups(
    TokenHandle:    HANDLE,
    ResetToDefault: BOOL,
    NewState:       LPTOKEN_GROUPS,
    BufferLength:   DWORD,
    PreviousState:  LPTOKEN_GROUPS,
    ReturnLength:   PDWORD
) -> BOOL: ...

def CreateProcessWithTokenW(
    hToken:                 HANDLE,
    dwLogonFlags:           DWORD,
    lpApplicationName:      LPCWSTR,
    lpCommandLine:          LPWSTR,
    dwCreationFlags:        DWORD,
    lpEnvironment:          LPVOID,
    lpCurrentDirectory:     LPCWSTR,
    lpStartupInfo:          LPSTARTUPINFOW,
    lpProcessInformation:   LPPROCESS_INFORMATION
) -> BOOL: ...

def CreateProcessAsUserW(
    hToken:                 HANDLE,
    lpApplicationName:      LPCWSTR,
    lpCommandLine:          LPWSTR,
    lpProcessAttributes:    LPSECURITY_ATTRIBUTES,
    lpThreadAttributes:     LPSECURITY_ATTRIBUTES,
    bInheritHandles:        BOOL,
    dwCreationFlags:        DWORD,
    lpEnvironment:          LPVOID,
    lpCurrentDirectory:     LPCWSTR,
    lpStartupInfo:          LPSTARTUPINFOW,
    lpProcessInformation:   LPPROCESS_INFORMATION
) -> BOOL: ...

def CreateProcessW(
    lpApplicationName:      LPCWSTR,
    lpCommandLine:          LPWSTR,
    lpProcessAttributes:    LPSECURITY_ATTRIBUTES,
    lpThreadAttributes:     LPSECURITY_ATTRIBUTES,
    bInheritHandles:        BOOL,
    dwCreationFlags:        DWORD,
    lpEnvironment:          LPVOID,
    lpCurrentDirectory:     LPCWSTR,
    lpStartupInfo:          LPSTARTUPINFOW,
    lpProcessInformation:   LPPROCESS_INFORMATION
) -> BOOL: ...

def TerminateProcess(hProcess: HANDLE, uExitCode: UINT) -> BOOL: ...

def GetForegroundWindow() -> HWND: ...

def SetForegroundWindow(hWnd: HWND) -> BOOL: ...

def GetWindowPlacement(hWnd: HWND, lpwndpl: LPWINDOWPLACEMENT) -> BOOL: ...

def SetWindowPlacement(hWnd: HWND, lpwndpl: LPWINDOWPLACEMENT) -> BOOL: ...

def ShowWindow(hWnd: HWND, nCmdShow: INT) -> BOOL: ...

def GetWindow(hWnd: HWND, uCmd: UINT) -> HWND: ...

EnumWindowsProc = NewType('EnumWindowsProc', WINFUNCTYPE(BOOL, HWND, LPARAM))
def EnumWindows(lpEnumFunc: EnumWindowsProc, lParam: LPARAM) -> BOOL: ...

def GetWindowThreadProcessId(hWnd: HWND, lpdwProcessId: PDWORD) -> DWORD: ...

def OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwProcessId: DWORD) -> HANDLE: ...

def OpenThread(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwThreadId: DWORD) -> HANDLE: ...

def CreateToolhelp32Snapshot(dwFlags: DWORD, th32ProcessID: DWORD) -> HANDLE: ...

def CloseHandle(hObject: HANDLE) -> BOOL: ...

def Process32First(hSnapshot: HANDLE, lppe: LPPROCESSENTRY32W) -> BOOL: ...

def Process32Next(hSnapshot: HANDLE, lppe: LPPROCESSENTRY32W) -> BOOL: ...

def Thread32First(hSnapshot: HANDLE, lpte: LPTHREADENTRY32) -> BOOL: ...

def Thread32Next(hSnapshot: HANDLE, lpte: LPTHREADENTRY32) -> BOOL: ...

def GetProcessTimes(
    hProcess:       HANDLE,
    lpCreationTime: LPFILETIME,
    lpExitTime:     LPFILETIME,
    lpKernelTime:   LPFILETIME,
    lpUserTime:     LPFILETIME
) -> BOOL: ...

def GetThreadTimes(
    hThread:        HANDLE,
    lpCreationTime: LPFILETIME,
    lpExitTime:     LPFILETIME,
    lpKernelTime:   LPFILETIME,
    lpUserTime:     LPFILETIME
) -> BOOL: ...

def GetExitCodeProcess(hProcess: HANDLE, lpExitCode: PDWORD) -> BOOL: ...

def GetLastError() -> DWORD: ...

def ReadProcessMemory(
    hProcess:               HANDLE,
    lpBaseAddress:          LPCVOID,
    lpBuffer:               POINTER,
    nSize:                  SIZE_T,
    lpNumberOfBytesRead:    LPSIZE_T
) -> BOOL: ...

def NtQueryInformationProcess(
    ProcessHandle_:             HANDLE,
    ProcessInformationClass:    INT,
    ProcessInformation:         POINTER,
    ProcessInformationLength:   ULONG,
    ReturnLength:               PULONG
) -> LONG: ...

class Handle_(metaclass=ABCMeta):
    """
    Abstract base Handle class.
    Please override these functions if needed.
    """
    _handle:    Optional[HANDLE]
    _func:      Callable[..., HANDLE]
    _exitfunc:  Callable[[HANDLE], None]

    def __init__(self, *args: Any, **kwargs: Any) -> None: ...
    def __enter__(self) -> HANDLE: ...
    def __exit__(self, exc_type: Optional[type], exc_val: Optional[BaseException], exc_tb: Optional[Any]) -> None: ...
    def __bool__(self) -> bool: ...
    @abstractmethod
    def __get_init_args__(self, *args: Any, **kwargs: Any) -> Tuple: ...

    def _is_invalid_handle(self) -> bool: ...

class ProcessHandle(Handle_):
    def __get_init_args__(self, access: int, pid: int, uselog: bool, raiseexcept: bool) -> Tuple[int, bool, int]: ...

class ThreadHandle(Handle_):
    def __get_init_args__(self, access: int, pid: int, uselog: bool, raiseexcept: bool) -> Tuple[int, bool, int]: ...

class CreateSnapshot(Handle_):
    def __get_init_args__(self, access: int) -> Tuple[int, DWORD]: ...
    def _is_invalid_handle(self) -> bool: ...

def report(
    msg: str                        = '',
    *args: tuple,
    reportstatus: bool              = True,
    statuscode: int                 = -1,
    uselog: bool                    = True,
    level: int                      = 40,
    raise_: bool                    = True,
    exception: Type[Exception]      = OSError,
    **kwargs: dict
) -> None:
    """
    Report any exception.

    Args:
        msg (str): The message to report.
        args (tuple): Additional arguments.
        reportstatus (bool): Whether to report the status code.
        statuscode (int): The status code to report.
        uselog (bool): Whether to log the message.
        level (int): Logging level
        raise_ (bool): Flag indicating whether to raise an exception.
        exception (Type[Exception]): Exception class to raise.
        kwargs (dict): Additional keyword arguments.

    Raises:
        Optional[OSError]: The specified exception class if raise_ is True.
    """
    pass

def fstr(formatstr: str) -> Union[int, str]: ...

def open_process(access: int, pid: int, uselog: bool = False, raiseexcept: bool = True) -> ProcessHandle: ...

def open_thread(access: int, tid: int, uselog: bool = False, raiseexcept: bool = True) -> ThreadHandle: ...

def create_snapshot(access: int) -> CreateSnapshot: ...

def get_func_path(func: Callable[..., Any]) -> str: ...

def Timer(timeout: int = 1) -> Callable[[Callable[..., Any]], Callable[[Tuple[Any, ...], Dict[str, Any]], Any]]: ...
