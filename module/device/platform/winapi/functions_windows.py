from abc import ABCMeta, abstractmethod
import typing as t
from datetime import datetime
import re
from queue import Queue
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
    FILETIME, RECT

from module.logger import logger

user32      = WinDLL(name='user32',     use_last_error=True)
kernel32    = WinDLL(name='kernel32',   use_last_error=True)
ntdll       = WinDLL(name='ntdll',      use_last_error=True)
wevtapi     = WinDLL(name='wevtapi',    use_last_error=True)
shell32     = WinDLL(name='shell32',    use_last_error=True)
advapi32    = WinDLL(name='advapi32',   use_last_error=True)
userenv     = WinDLL(name='userenv',    use_last_error=True)

OpenProcessToken                    = advapi32.OpenProcessToken
OpenProcessToken.argtypes           = [HANDLE, DWORD, POINTER(HANDLE)]
OpenProcessToken.restype            = LONG

IsUserAnAdmin                       = shell32.IsUserAnAdmin
IsUserAnAdmin.argtypes              = []
IsUserAnAdmin.restype               = BOOL

DuplicateTokenEx                    = advapi32.DuplicateTokenEx
DuplicateTokenEx.argtypes           = [HANDLE, DWORD, POINTER(LPVOID), ULONG, ULONG, POINTER(HANDLE)]
DuplicateTokenEx.restype            = LONG

CreateProcessAsUserW                = advapi32.CreateProcessAsUserW
CreateProcessAsUserW.argtypes       = [
    HANDLE,                         # hToken
    LPCWSTR,                        # lpApplicationName
    LPWSTR,                         # lpCommandLine
    POINTER(SECURITY_ATTRIBUTES),   # lpProcessAttributes
    POINTER(SECURITY_ATTRIBUTES),   # lpThreadAttributes
    BOOL,                           # bInheritHandles
    DWORD,                          # dwCreationFlags
    LPVOID,                         # lpEnvironment
    LPCWSTR,                        # lpCurrentDirectory
    POINTER(STARTUPINFOW),          # lpStartupInfo
    POINTER(PROCESS_INFORMATION)    # lpProcessInformation
]
CreateProcessAsUserW.restype        = BOOL

GetCurrentProcess                   = kernel32.GetCurrentProcess
GetCurrentProcess.argtypes          = []
GetCurrentProcess.restype           = HANDLE

CreateEnvironmentBlock              = userenv.CreateEnvironmentBlock
CreateEnvironmentBlock.argtypes     = [POINTER(LPVOID), HANDLE, BOOL]
CreateEnvironmentBlock.restype      = BOOL

DestroyEnvironmentBlock             = userenv.DestroyEnvironmentBlock
DestroyEnvironmentBlock.argtypes    = [LPVOID]
DestroyEnvironmentBlock.restype     = BOOL

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

GetParent                           = user32.GetParent
GetParent.argtypes                  = [HWND]
GetParent.restype                   = HWND
GetWindowRect                       = user32.GetWindowRect
GetWindowRect.argtypes              = [HWND, POINTER(RECT)]
GetWindowRect.restype               = BOOL

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

class QueryEvt(Handle):
    _func       = EvtQuery
    _exitfunc   = EvtClose

    def __get_init_args__(self):
        query = "Event/System[EventID=4688]"
        from module.device.platform.winapi.const_windows import EVT_QUERY_REVERSE_DIRECTION, EVT_QUERY_CHANNEL_PATH
        return None, "Security", query, EVT_QUERY_REVERSE_DIRECTION | EVT_QUERY_CHANNEL_PATH

    def _is_invalid_handle(self):
        return self._handle is None

class Data:
    def __init__(self, data: dict, dtime: datetime):
        self.system_time: datetime  = dtime
        self.new_process_id: int    = data.get("NewProcessId", 0)
        self.new_process_name: str  = data.get("NewProcessName", '')
        self.process_id: int        = data.get("ProcessId", 0)
        self.process_name: str      = data.get("ParentProcessName", '')

    def __eq__(self, other):
        if isinstance(other, Data):
            return self.new_process_id == other.process_id
        return NotImplemented

    def __str__(self):
        attrs = ', '.join(f"{key}={value}" for key, value in self.__dict__.items())
        return f"Data({attrs})"

    def __repr__(self):
        attrs = ', '.join(f"{key}={value!r}" for key, value in self.__dict__.items())
        return f"Data({attrs})"

class Node:
    def __init__(self, data: Data = None):
        self.data = data
        self.children = []

    def __repr__(self):
        return f"{self.__class__.__name__}(data={self.data!r})"

    def __str__(self) -> str:
        return f"{self.__class__.__name__}(data={self.data})"

    def add_children(self, data):
        self.children.append(Node(data))

class EventTree:
    root = None

    @staticmethod
    def parse_event(event: str):
        import xml.etree.ElementTree as Et
        ns              = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        root            = Et.fromstring(event)
        system_time_str = root.find('.//ns:TimeCreated', ns).attrib['SystemTime']
        match           = re.match(r'(.*\.\d{6})\d?(Z)', system_time_str)
        modifiedtime    = match.group(1) + match.group(2) if match else system_time_str
        system_time     = datetime.strptime(modifiedtime, '%Y-%m-%dT%H:%M:%S.%f%z').astimezone()

        fields          = ["NewProcessId", "NewProcessName", "ProcessId", "ParentProcessName"]
        data            = {field: fstr(root.find(f'.//ns:Data[@Name="{field}"]', ns).text) for field in fields}

        return Data(data, system_time)

    def pre_order_traversal(self, node: Node):
        if node is not None:
            yield node
            for child in node.children:
                yield from self.pre_order_traversal(child)

    def post_order_traversal(self, node: Node):
        if node is not None:
            for child in node.children:
                yield from self.post_order_traversal(child)
            yield node

    @staticmethod
    def level_order_traversal(node: Node):
        q = Queue()
        q.put(node)
        while not q.empty():
            out: Node = q.get()
            yield out
            if not out.children:
                continue
            for child in out.children:
                q.put(child)

    def release_tree(self):
        self.root = None

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

def evt_query() -> QueryEvt:
    return QueryEvt()

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
