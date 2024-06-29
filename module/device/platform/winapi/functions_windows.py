from ctypes import POINTER, WINFUNCTYPE, WinDLL, c_size_t
from ctypes.wintypes import (
    HANDLE, DWORD, HWND, BOOL, INT, UINT,
    LONG, ULONG, LPWSTR, LPCWSTR, LPRECT,
    LPVOID, LPCVOID, LPARAM, PULONG
)

from module.device.platform.winapi.structures_windows import (
    SECURITY_ATTRIBUTES, STARTUPINFOW, WINDOWPLACEMENT,
    PROCESS_INFORMATION, PROCESSENTRY32, THREADENTRY32,
    FILETIME
)

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

IsWindow                            = user32.IsWindow
IsWindow.argtypes                   = [HWND]
IsWindow.restype                    = BOOL
GetParent                           = user32.GetParent
GetParent.argtypes                  = [HWND]
GetParent.restype                   = HWND
GetWindowRect                       = user32.GetWindowRect
GetWindowRect.argtypes              = [HWND, LPRECT]
GetWindowRect.restype               = BOOL

EnumWindowsProc                     = WINFUNCTYPE(BOOL, HWND, LPARAM)
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
Process32First.argtypes             = [HANDLE, POINTER(PROCESSENTRY32)]
Process32First.restype              = BOOL

Process32Next                       = kernel32.Process32Next
Process32Next.argtypes              = [HANDLE, POINTER(PROCESSENTRY32)]
Process32Next.restype               = BOOL

Thread32First                       = kernel32.Thread32First
Thread32First.argtypes              = [HANDLE, POINTER(THREADENTRY32)]
Thread32First.restype               = BOOL

Thread32Next                        = kernel32.Thread32Next
Thread32Next.argtypes               = [HANDLE, POINTER(THREADENTRY32)]
Thread32Next.restype                = BOOL

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

class Handle:
    handle = None

    def __enter__(self):
        return self.handle

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.handle is not None:
            CloseHandle(self.handle)
            self.handle = None

class ProcessHandle(Handle):
    def __init__(self, access, pid, uselog):
        self.handle = OpenProcess(access, False, pid)
        if self.handle is None:
            report("OpenProcess failed.", uselog=uselog)

class ThreadHandle(Handle):
    def __init__(self, access, tid, uselog):
        self.handle = OpenThread(access, False, tid)
        if self.handle is None:
            report("OpenThread failed.", uselog=uselog)

class CreateSnapshot(Handle):
    def __init__(self, arg):
        self.handle = CreateToolhelp32Snapshot(arg, DWORD(0))
        from module.device.platform.winapi.const_windows import INVALID_HANDLE_VALUE
        if self.handle == INVALID_HANDLE_VALUE:
            report("CreateToolhelp32Snapshot failed.")

def report(
        msg: str            = '',
        statuscode: int     = -1,
        uselog: bool        = True,
        level: int          = 40,
        handle: int         = 0,
        raiseexcept: bool   = True,
        exception: type     = OSError,
):
    """
    Raise exception.

    Args:
        msg (str):
        statuscode (int):
        uselog (bool):
        level (int): Logging level
        handle (int): Handle to close
        raiseexcept (bool): Flag indicating whether to raise
        exception (Type[Exception]): Exception class to raise
    """
    from module.logger import logger
    if statuscode == -1:
        statuscode = GetLastError()
    if uselog:
        logger.log(level, f"{msg} Status code: 0x{statuscode:08x}")
    if handle:
        CloseHandle(handle)
    if raiseexcept:
        raise exception(statuscode)

def open_process(access, pid, uselog=False):
    return ProcessHandle(access, pid, uselog)

def open_thread(access, tid, uselog=False):
    return ThreadHandle(access, tid, uselog)

def create_snapshot(arg):
    return CreateSnapshot(arg)
