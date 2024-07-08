from abc import ABCMeta, abstractmethod

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
wevtapi     = WinDLL(name='wevtapi',    use_last_error=True)
shell32     = WinDLL(name='shell32',    use_last_error=True)

IsUserAnAdmin                       = shell32.IsUserAnAdmin
IsUserAnAdmin.argtypes              = []
IsUserAnAdmin.restype               = BOOL

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

EVT_HANDLE                          = HANDLE
EvtQuery                            = wevtapi.EvtQuery
EvtQuery.argtypes                   = [EVT_HANDLE, LPCWSTR, LPCWSTR, DWORD]
EvtQuery.restype                    = HANDLE

EvtNext                             = wevtapi.EvtNext
EvtNext.argtypes                    = [EVT_HANDLE, DWORD, POINTER(EVT_HANDLE), DWORD, DWORD, POINTER(DWORD)]
EvtNext.restype                     = BOOL

EvtRender                           = wevtapi.EvtRender
EvtRender.argtypes                  = [EVT_HANDLE, EVT_HANDLE, DWORD, DWORD, LPVOID, POINTER(DWORD), POINTER(DWORD)]
EvtRender.restype                   = BOOL

EvtClose                            = wevtapi.EvtClose
EvtClose.argtypes                   = [EVT_HANDLE]
EvtClose.restype                    = BOOL

class Handle(metaclass=ABCMeta):
    """
    Abstract base Handle class.
    Please override these functions if needed.
    """
    _handle     = None
    _func       = None
    _exitfunc   = None

    def __init__(self, *args, **kwargs):
        self._handle = self._func(*self.__getinitargs__(*args, **kwargs))
        if not self:
            report(f"{self._func.__name__} failed.", uselog=kwargs.get('uselog', True))

    def __enter__(self):
        return self._handle

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self:
            self._exitfunc(self._handle)
            self._handle = None

    def __bool__(self):
        return not self._is_invalid_handle()

    @abstractmethod
    def __getinitargs__(self, *args, **kwargs): ...
    @abstractmethod
    def _is_invalid_handle(self): ...

class ProcessHandle(Handle):
    _func       = OpenProcess
    _exitfunc   = CloseHandle

    def __getinitargs__(self, access, pid, uselog):
        return access, False, pid

    def _is_invalid_handle(self):
        return self._handle is None

class ThreadHandle(Handle):
    _func       = OpenThread
    _exitfunc   = CloseHandle

    def __getinitargs__(self, access, pid, uselog):
        return access, False, pid

    def _is_invalid_handle(self):
        return self._handle is None

class CreateSnapshot(Handle):
    _func       = CreateToolhelp32Snapshot
    _exitfunc   = CloseHandle

    def __getinitargs__(self, arg):
        return arg, DWORD(0)

    def _is_invalid_handle(self):
        from module.device.platform.winapi.const_windows import INVALID_HANDLE_VALUE
        return self._handle == INVALID_HANDLE_VALUE

class QueryEvt(Handle):
    _func       = EvtQuery
    _exitfunc   = EvtClose

    def __getinitargs__(self):
        query = "Event/System[EventID=4688]"
        from module.device.platform.winapi.const_windows import EVT_QUERY_REVERSE_DIRECTION, EVT_QUERY_CHANNEL_PATH
        return None, "Security", query, EVT_QUERY_REVERSE_DIRECTION | EVT_QUERY_CHANNEL_PATH

    def _is_invalid_handle(self):
        return self._handle is None

class EventTree:
    class __Node:
        def __init__(self, data=None, parent=None, children: list = None):
            self.data = data
            self.parent = parent
            self.son = [] if children is None else children

    def __init__(self):
        self.root = None

    def add_parent(self, data):
        if self.root is None:
            self.root = self.__Node(data)
            return
        node = self.__Node(data, children=[self.root, ])
        self.root.parent = node
        self.root = node

    def add_son(self, data):
        if self.root is None:
            self.root = self.__Node(data)
            return
        node = self.__Node(data, parent=self.root)
        self.root.son.append(node)


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
    Report any exception.
    
    Args:
        msg (str):
        statuscode (int):
        uselog (bool):
        level (int): Logging level
        handle (int): Handle to close
        raiseexcept (bool): Flag indicating whether to raise
        exception (Type[Exception]): Exception class to raise

    Raises:
        Optional[OSError]:
    """
    from module.logger import logger
    if statuscode == -1:
        statuscode = GetLastError()
    message = f"{msg} Status code: 0x{statuscode:08x}"
    if uselog:
        logger.log(level, message)
    if handle:
        CloseHandle(handle)
    if raiseexcept:
        raise exception(message)

def open_process(access, pid, uselog=False):
    return ProcessHandle(access, pid, uselog=uselog)

def open_thread(access, tid, uselog=False):
    return ThreadHandle(access, tid, uselog=uselog)

def create_snapshot(arg):
    return CreateSnapshot(arg)

def evt_query():
    return QueryEvt()
