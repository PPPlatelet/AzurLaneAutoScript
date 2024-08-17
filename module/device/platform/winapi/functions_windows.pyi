from abc import ABCMeta, abstractmethod
from typing import Callable, Union, Any, Tuple, Dict, Optional

from ctypes import POINTER, WINFUNCTYPE, WinDLL, c_size_t
from ctypes.wintypes import \
    HANDLE, DWORD, HWND, BOOL, INT, UINT, \
    LONG, ULONG, LPWSTR, LPCWSTR, \
    LPVOID, LPCVOID, LPARAM, PULONG
from module.device.platform.winapi.structures_windows import \
    SECURITY_ATTRIBUTES, STARTUPINFOW, WINDOWPLACEMENT, \
    PROCESS_INFORMATION, PROCESSENTRY32W, THREADENTRY32, \
    FILETIME, PEB, RTL_USER_PROCESS_PARAMETERS, TOKEN_GROUPS

user32: WinDLL
kernel32: WinDLL
ntdll: WinDLL
shell32: WinDLL
advapi32: WinDLL

SIZE_T = c_size_t

def IsUserAnAdmin() -> BOOL: ...

def OpenProcessToken(ProcessHandle_: HANDLE, DesiredAccess: DWORD, TokenHandle: POINTER(HANDLE)) -> BOOL: ...

def DuplicateTokenEx(
    hExistingToken: HANDLE,
    dwDesiredAccess: DWORD,
    lpTokenAttributes: POINTER(SECURITY_ATTRIBUTES),
    ImpersonationLevel: ULONG,
    TokenType: ULONG,
    phNewToken: POINTER(HANDLE)
) -> LONG: ...

def GetCurrentProcess() -> HANDLE: ...

def AdjustTokenGroups(
    TokenHandle: HANDLE,
    ResetToDefault: BOOL,
    NewState: POINTER(TOKEN_GROUPS),
    BufferLength: DWORD,
    PreviousState: POINTER(TOKEN_GROUPS),
    ReturnLength: POINTER(DWORD)
) -> BOOL: ...

def CreateProcessWithTokenW(
    hToken: HANDLE,
    dwLogonFlags: DWORD,
    lpApplicationName: LPCWSTR,
    lpCommandLine: LPWSTR,
    dwCreationFlags: DWORD,
    lpEnvironment: LPVOID,
    lpCurrentDirectory: LPCWSTR,
    lpStartupInfo: POINTER(STARTUPINFOW),
    lpProcessInformation: POINTER(PROCESS_INFORMATION)
) -> BOOL: ...

def CreateProcessAsUserW(
    hToken: HANDLE,
    lpApplicationName: LPCWSTR,
    lpCommandLine: LPWSTR,
    lpProcessAttributes: POINTER(SECURITY_ATTRIBUTES),
    lpThreadAttributes: POINTER(SECURITY_ATTRIBUTES),
    bInheritHandles: BOOL,
    dwCreationFlags: DWORD,
    lpEnvironment: LPVOID,
    lpCurrentDirectory: LPCWSTR,
    lpStartupInfo: POINTER(STARTUPINFOW),
    lpProcessInformation: POINTER(PROCESS_INFORMATION)
) -> BOOL: ...

def CreateProcessW(
    lpApplicationName: LPCWSTR,
    lpCommandLine: LPWSTR,
    lpProcessAttributes: POINTER(SECURITY_ATTRIBUTES),
    lpThreadAttributes: POINTER(SECURITY_ATTRIBUTES),
    bInheritHandles: BOOL,
    dwCreationFlags: DWORD,
    lpEnvironment: LPVOID,
    lpCurrentDirectory: LPCWSTR,
    lpStartupInfo: POINTER(STARTUPINFOW),
    lpProcessInformation: POINTER(PROCESS_INFORMATION)
) -> BOOL: ...

def TerminateProcess(hProcess: HANDLE, uExitCode: UINT) -> BOOL: ...

def GetForegroundWindow() -> HWND: ...

def SetForegroundWindow(hWnd: HWND) -> BOOL: ...

def GetWindowPlacement(hWnd: HWND, lpwndpl: POINTER(WINDOWPLACEMENT)) -> BOOL: ...

def SetWindowPlacement(hWnd: HWND, lpwndpl: POINTER(WINDOWPLACEMENT)) -> BOOL: ...

def ShowWindow(hWnd: HWND, nCmdShow: INT) -> BOOL: ...

def GetWindow(hWnd: HWND, uCmd: UINT) -> HWND: ...

EnumWindowsProc: WINFUNCTYPE(BOOL, HWND, LPARAM)
def EnumWindows(lpEnumFunc: WINFUNCTYPE(BOOL, HWND, LPARAM), lParam: LPARAM) -> BOOL: ...

def GetWindowThreadProcessId(hWnd: HWND, lpdwProcessId: POINTER(DWORD)) -> DWORD: ...

def OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwProcessId: DWORD) -> HANDLE: ...

def OpenThread(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwThreadId: DWORD) -> HANDLE: ...

def CreateToolhelp32Snapshot(dwFlags: DWORD, th32ProcessID: DWORD) -> HANDLE: ...

def CloseHandle(hObject: HANDLE) -> BOOL: ...

def Process32First(hSnapshot: HANDLE, lppe: POINTER(PROCESSENTRY32W)) -> BOOL: ...

def Process32Next(hSnapshot: HANDLE, lppe: POINTER(PROCESSENTRY32W)) -> BOOL: ...

def Thread32First(hSnapshot: HANDLE, lpte: POINTER(THREADENTRY32)) -> BOOL: ...

def Thread32Next(hSnapshot: HANDLE, lpte: POINTER(THREADENTRY32)) -> BOOL: ...

def GetProcessTimes(
    hProcess: HANDLE,
    lpCreationTime: POINTER(FILETIME),
    lpExitTime: POINTER(FILETIME),
    lpKernelTime: POINTER(FILETIME),
    lpUserTime: POINTER(FILETIME)
) -> BOOL: ...

def GetThreadTimes(
    hThread: HANDLE,
    lpCreationTime: POINTER(FILETIME),
    lpExitTime: POINTER(FILETIME),
    lpKernelTime: POINTER(FILETIME),
    lpUserTime: POINTER(FILETIME)
) -> BOOL: ...

def GetExitCodeProcess(hProcess: HANDLE, lpExitCode: POINTER(DWORD)) -> BOOL: ...

def GetLastError() -> DWORD: ...

def ReadProcessMemory(
    hProcess: HANDLE,
    lpBaseAddress: LPCVOID,
    lpBuffer: Union[POINTER(PEB), POINTER(RTL_USER_PROCESS_PARAMETERS), ...],
    nSize: SIZE_T,
    lpNumberOfBytesRead: POINTER(SIZE_T)
) -> BOOL: ...

def NtQueryInformationProcess(
    ProcessHandle_: HANDLE,
    ProcessInformationClass: INT,
    ProcessInformation: Optional[POINTER(PROCESS_INFORMATION)],
    ProcessInformationLength: ULONG,
    ReturnLength: PULONG
) -> LONG: ...

class Handle_(metaclass=ABCMeta):
    _handle: int
    _func: Callable
    _exitfunc: Callable

    def __init__(self, *args, **kwargs) -> None: ...
    def __enter__(self) -> int: ...
    def __exit__(self, exc_type, exc_val, exc_tb) -> None: ...
    def __bool__(self) -> bool: ...
    @abstractmethod
    def __get_init_args__(self, *args, **kwargs) -> tuple: ...
    @abstractmethod
    def _is_invalid_handle(self) -> bool: ...

class ProcessHandle(Handle_):
    def __get_init_args__(self, access: int, pid: int, uselog: bool, raiseexcept: bool) -> tuple: ...
    def _is_invalid_handle(self) -> bool: ...

class ThreadHandle(Handle_):
    def __get_init_args__(self, access: int, pid: int, uselog: bool, raiseexcept: bool) -> tuple: ...
    def _is_invalid_handle(self) -> bool: ...

class CreateSnapshot(Handle_):
    def __get_init_args__(self, access: int) -> tuple: ...
    def _is_invalid_handle(self) -> bool: ...

class Handle(int, Handle_):
    closed: bool
    def Close(self, fclose: Callable = CloseHandle) -> None: ...
    def Detach(self) -> int: ...
    def __repr__(self) -> str: ...
    def __get_init_args__(self, *args, **kwargs) -> tuple: ...
    def _is_invalid_handle(self) -> bool: ...
    def __del__(self) -> None: ...
    def __str__(self) -> str: ...

def report(
    msg: str = '',
    *args: tuple,
    reportstatus: bool = True,
    statuscode: int = -1,
    uselog: bool = True,
    level: int = 40,
    raiseexcept: bool = True,
    exception: type = OSError,
    **kwargs: dict
) -> None: ...

def fstr(formatstr: str) -> Union[int, str]: ...
def open_process(access: int, pid: int, *, uselog: bool = False, raiseexcept: bool = True) -> ProcessHandle: ...
def open_thread(access: int, tid: int, *, uselog: bool = False, raiseexcept: bool = True) -> ThreadHandle: ...
def create_snapshot(arg: int) -> CreateSnapshot: ...

def get_func_path(func: Any) -> str: ...

def Timer(timeout: int = 1) -> Callable[[Callable[..., Any]], Callable[[Tuple[Any, ...], Dict[str, Any]], Any]]: ...
