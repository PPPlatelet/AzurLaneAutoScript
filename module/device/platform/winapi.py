import ctypes
import ctypes.wintypes
import re

import psutil

from deploy.Windows.utils import DataProcessInfo
from module.device.platform.emulator_windows import Emulator, EmulatorInstance
from module.logger import logger

user32      = ctypes.windll.user32
kernel32    = ctypes.windll.kernel32
psapi       = ctypes.windll.psapi
PyHANDLE    = ctypes.wintypes.HANDLE
DWORD       = ctypes.wintypes.DWORD
WORD        = ctypes.wintypes.WORD
BYTE        = ctypes.wintypes.BYTE
BOOL        = ctypes.wintypes.BOOL
LONG        = ctypes.wintypes.LONG
CHAR        = ctypes.wintypes.CHAR
WCHAR       = ctypes.wintypes.WCHAR
LPWSTR      = ctypes.wintypes.LPWSTR
LPCWSTR     = ctypes.wintypes.LPCWSTR
LPVOID      = ctypes.wintypes.LPVOID
HWND        = ctypes.wintypes.HWND
MAX_PATH    = ctypes.wintypes.MAX_PATH
LPARAM      = ctypes.wintypes.LPARAM
RECT        = ctypes.wintypes.RECT
ULONG_PTR   = ctypes.wintypes.PULONG

class EmulatorLaunchFailedError(Exception): ...
class HwndNotFoundError(Exception): ...
class ProcessNotFoundError(Exception): ...
class WinApiError(Exception): ...
class EmulatorNotFoundError(Exception): ...

PROCESS_ALL_ACCESS          = 0x1F0FFF
THREAD_ALL_ACCESS           = 0x1F03FF
PROCESS_QUERY_INFORMATION   = 0x0400
PROCESS_VM_READ             = 0x0010
ERROR_NO_MORE_FILES         = 0x12
TH32CS_SNAPPROCESS          = DWORD(0x00000002)

# winbase.h
STARTF_USESHOWWINDOW    = 1
STARTF_USESIZE          = 2
STARTF_USEPOSITION      = 4
STARTF_USECOUNTCHARS    = 8
STARTF_USEFILLATTRIBUTE = 16
STARTF_FORCEONFEEDBACK  = 64
STARTF_FORCEOFFFEEDBACK = 128
STARTF_USESTDHANDLES    = 256
STARTF_USEHOTKEY        = 512

# winuser.h
SW_HIDE             = 0
SW_SHOWNORMAL       = 1
SW_NORMAL           = 1
SW_SHOWMINIMIZED    = 2
SW_SHOWMAXIMIZED    = 3
SW_MAXIMIZE         = 3
SW_SHOWNOACTIVATE   = 4
SW_SHOW             = 5
SW_MINIMIZE         = 6
SW_SHOWMINNOACTIVE  = 7
SW_SHOWNA           = 8
SW_RESTORE          = 9
SW_SHOWDEFAULT      = 10
SW_FORCEMINIMIZE    = 11
SW_MAX              = 11

# winuser.h
DEBUG_PROCESS               = 1
DEBUG_ONLY_THIS_PROCESS     = 2
CREATE_SUSPENDED            = 4
DETACHED_PROCESS            = 8
CREATE_NEW_CONSOLE          = 16
NORMAL_PRIORITY_CLASS       = 32
IDLE_PRIORITY_CLASS         = 64
HIGH_PRIORITY_CLASS         = 128
REALTIME_PRIORITY_CLASS     = 256
CREATE_NEW_PROCESS_GROUP    = 512
CREATE_UNICODE_ENVIRONMENT  = 1024
CREATE_SEPARATE_WOW_VDM     = 2048
CREATE_SHARED_WOW_VDM       = 4096
CREATE_DEFAULT_ERROR_MODE   = 67108864
CREATE_NO_WINDOW            = 134217728
PROFILE_USER                = 268435456
PROFILE_KERNEL              = 536870912
PROFILE_SERVER              = 1073741824


class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ('cb',              DWORD),
        ('lpReserved',      LPWSTR),
        ('lpDesktop',       LPWSTR),
        ('lpTitle',         LPWSTR),
        ('dwX',             DWORD),
        ('dwY',             DWORD),
        ('dwXSize',         DWORD),
        ('dwYSize',         DWORD),
        ('dwXCountChars',   DWORD),
        ('dwYCountChars',   DWORD),
        ('dwFillAttribute', DWORD),
        ('dwFlags',         DWORD),
        ('wShowWindow',     WORD),
        ('cbReserved2',     WORD),
        ('lpReserved2',     ctypes.POINTER(BYTE)),
        ('hStdInput',       PyHANDLE),
        ('hStdOutput',      PyHANDLE),
        ('hStdError',       PyHANDLE),
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('hProcess',    PyHANDLE),
        ('hThread',     PyHANDLE),
        ('dwProcessId', DWORD),
        ('dwThreadId',  DWORD),
    ]

class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength",                 DWORD),
        ("lpSecurityDescriptor",    ctypes.c_void_p),
        ("bInheritHandle",          BOOL)
    ]

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",              DWORD),
        ("cntUsage",            DWORD),
        ("th32ProcessID",       DWORD),
        ("th32DefaultHeapID",   ULONG_PTR),
        ("th32ModuleID",        DWORD),
        ("cntThreads",          DWORD),
        ("th32ParentProcessID", DWORD),
        ("pcPriClassBase",      LONG),
        ("dwFlags",             DWORD),
        ("szExeFile",           CHAR * MAX_PATH),
    ]


CreateProcessW = kernel32.CreateProcessW
CreateProcessW.argtypes = [
    LPCWSTR,
    LPWSTR,
    ctypes.POINTER(SECURITY_ATTRIBUTES),
    ctypes.POINTER(SECURITY_ATTRIBUTES),
    BOOL,
    DWORD,
    LPVOID,
    LPCWSTR,
    ctypes.POINTER(STARTUPINFO),
    ctypes.POINTER(PROCESS_INFORMATION)
]
CreateProcessW.restype = BOOL

GetForegroundWindow                 = user32.GetForegroundWindow
SetForegroundWindow                 = user32.SetForegroundWindow
SetForegroundWindow.argtypes        = [HWND]
SetForegroundWindow.restype         = BOOL

ShowWindow                          = user32.ShowWindow
IsWindow                            = user32.IsWindow
GetParent                           = user32.GetParent
GetWindowRect                       = user32.GetWindowRect

EnumWindows                         = user32.EnumWindows
EnumWindowsProc                     = ctypes.WINFUNCTYPE(BOOL, HWND, LPARAM)
GetWindowThreadProcessId            = user32.GetWindowThreadProcessId
GetWindowThreadProcessId.argtypes   = [HWND, ctypes.POINTER(DWORD)]
GetWindowThreadProcessId.restype    = DWORD

OpenProcess                         = kernel32.OpenProcess
OpenProcess.argtypes                = [DWORD, BOOL, DWORD]
OpenProcess.restype                 = PyHANDLE
OpenThread                          = kernel32.OpenThread

CreateToolhelp32Snapshot            = kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.argtypes   = [DWORD, DWORD]
CreateToolhelp32Snapshot.restype    = PyHANDLE

CloseHandle                         = kernel32.CloseHandle
CloseHandle.argtypes                = [PyHANDLE]
CloseHandle.restype                 = BOOL

Process32First                      = kernel32.Process32First
Process32First.argtypes             = [PyHANDLE, ctypes.POINTER(PROCESSENTRY32)]
Process32First.restype              = BOOL

Process32Next                       = kernel32.Process32Next
Process32Next.argtypes              = [PyHANDLE, ctypes.POINTER(PROCESSENTRY32)]
Process32Next.restype               = BOOL

GetLastError                        = kernel32.GetLastError
GetLastError.restype                = BOOL

def getfocusedwindow() -> int:
    return GetForegroundWindow()

def setfocustowindow(hwnd: int) -> bool:
    return SetForegroundWindow(hwnd)

def execute(command: str, arg: bool):
    startupinfo             = STARTUPINFO()
    startupinfo.cb          = ctypes.sizeof(STARTUPINFO)
    startupinfo.dwFlags     = STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = SW_HIDE if arg else SW_MINIMIZE
    
    focusedwindow = getfocusedwindow()

    processinformation = PROCESS_INFORMATION()

    success = CreateProcessW(
        None,
        command,
        None,
        None,
        False,
        DETACHED_PROCESS,
        None,
        None,
        ctypes.byref(startupinfo),
        ctypes.byref(processinformation)
    )

    if not success:
        errorcode = GetLastError()
        raise EmulatorLaunchFailedError(f"Failed to start emulator. Error code: {errorcode}")
    
    process = (
        processinformation.hProcess,
        processinformation.hThread,
        processinformation.dwProcessId,
        processinformation.dwThreadId
    )
    return process, focusedwindow

def gethwnds(pid: int) -> list:
    hwnds = []

    @EnumWindowsProc
    def callback(hwnd: int, lparam):
        processid = DWORD()
        GetWindowThreadProcessId(hwnd, ctypes.byref(processid))
        if processid.value == pid:
            hwnds.append(hwnd)
        return True
    
    EnumWindows(callback, 0)
    if not hwnds:
        logger.critical(
            "Hwnd not found! \n"
            "1.Perhaps emulator was killed. \n"
            "2.Environment has something wrong. Please check the running environment. "
        )
        raise HwndNotFoundError("Hwnd not found")
    return hwnds

def _findemulatorprocess(proc: psutil.Process):
    try:
        processhandle = OpenProcess(PROCESS_ALL_ACCESS, False, proc.pid)
        if not processhandle:
            raise ctypes.WinError(ctypes.get_last_error())

        mainthreadid = proc.threads()[0].id
        threadhandle = OpenThread(THREAD_ALL_ACCESS, False, mainthreadid)
        if not threadhandle:
            raise ctypes.WinError(ctypes.get_last_error())

        return (PyHANDLE(processhandle), PyHANDLE(threadhandle), proc.pid, mainthreadid)
    except Exception as e:
        logger.warning(f"Failed to get process and thread handles: {e}")
        return (None, None, proc.pid, proc.threads()[0].id)

def findemulatorprocess(instance: EmulatorInstance):
    lppe = PROCESSENTRY32()
    lppe.dwSize = ctypes.sizeof(PROCESSENTRY32)
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, DWORD(0))
    Process32First(hSnapshot, ctypes.pointer(lppe))

    process = None
    while Process32Next(hSnapshot, ctypes.pointer(lppe)):
        proc = psutil.Process(lppe.th32ProcessID)
        cmdline = DataProcessInfo(proc=proc, pid=proc.pid).cmdline
        if not instance.path in cmdline:
            continue
        if instance == Emulator.MuMuPlayer12:
            match = re.search(r'\d+$', cmdline)
            if match and int(match.group()) == instance.MuMuPlayer12_id:
                process = proc
                break
        elif instance == Emulator.LDPlayerFamily:
            match = re.search(r'\d+$', cmdline)
            if match and int(match.group()) == instance.LDPlayer_id:
                process = proc
                break
        else:
            matchstr = re.search(fr'\b{instance.name}$', cmdline)
            if matchstr and matchstr.group() == instance.name:
                process = proc
                break
    else:
        CloseHandle(hSnapshot)
        errorcode = GetLastError()
        if errorcode != ERROR_NO_MORE_FILES:
            logger.error(f'Error: {errorcode}')
            raise WinApiError("Process not found")
        
    CloseHandle(hSnapshot)
    return _findemulatorprocess(process)
    
def _switchwindow(hwnd: int, arg: int):
    ShowWindow(hwnd, arg)
    return True

def switchwindow(hwnds: list, arg: int):
    for hwnd in hwnds:
        if not IsWindow(hwnd):
                continue
        if GetParent(hwnd):
            continue
        rect = RECT()
        GetWindowRect(hwnd, ctypes.byref(rect))
        if {rect.left, rect.top, rect.right, rect.bottom} == {0}:
            continue
        _switchwindow(hwnd, arg)
    return True