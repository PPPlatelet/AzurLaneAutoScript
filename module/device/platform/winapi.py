import ctypes
import ctypes.wintypes
from sys import getwindowsversion

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

# winnt.h line 3961
PROCESS_TERMINATE                   = 0x0001
PROCESS_CREATE_THREAD               = 0x0002
PROCESS_SET_SESSIONID               = 0x0004
PROCESS_VM_OPERATION                = 0x0008
PROCESS_VM_READ                     = 0x0010
PROCESS_VM_WRITE                    = 0x0020
PROCESS_DUP_HANDLE                  = 0x0040
PROCESS_CREATE_PROCESS              = 0x0080
PROCESS_SET_QUOTA                   = 0x0100
PROCESS_SET_INFORMATION             = 0x0200
PROCESS_QUERY_INFORMATION           = 0x0400
PROCESS_SUSPEND_RESUME              = 0x0800
PROCESS_QUERY_LIMITED_INFORMATION   = 0x1000

THREAD_TERMINATE                    = 0x0001
THREAD_SUSPEND_RESUME               = 0x0002
THREAD_GET_CONTEXT                  = 0x0008
THREAD_SET_CONTEXT                  = 0x0010
THREAD_SET_INFORMATION              = 0x0020
THREAD_QUERY_INFORMATION            = 0x0040
THREAD_SET_THREAD_TOKEN             = 0x0080
THREAD_IMPERSONATE                  = 0x0100
THREAD_DIRECT_IMPERSONATION         = 0x0200
THREAD_SET_LIMITED_INFORMATION      = 0x0400
THREAD_QUERY_LIMITED_INFORMATION    = 0x0800

# winnt.h line 2809
SYNCHRONIZE                 = 0x00100000
STANDARD_RIGHTS_REQUIRED    = 0x000F0000

VERSIONINFO                 = getwindowsversion()
MAJOR, MINOR, BUILD         = VERSIONINFO.major, VERSIONINFO.minor, VERSIONINFO.build

if (MAJOR > 6) or (MAJOR == 6 and MINOR >= 1):
    PROCESS_ALL_ACCESS      = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xffff
    THREAD_ALL_ACCESS       = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xffff
else:
    PROCESS_ALL_ACCESS      = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xfff
    THREAD_ALL_ACCESS       = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3ff

MAXIMUM_PROC_PER_GROUP      = 64
MAXIMUM_PROCESSORS          = MAXIMUM_PROC_PER_GROUP

# error.h line 23
ERROR_NO_MORE_FILES = 0x12

# tlhelp32.h line 17
TH32CS_SNAPHEAPLIST = 0x00000001
TH32CS_SNAPPROCESS  = 0x00000002
TH32CS_SNAPTHREAD   = 0x00000004
TH32CS_SNAPMODULE   = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
TH32CS_SNAPALL      = TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE
TH32CS_INHERIT      = 0x80000000

# winbase.h line 1463
STARTF_USESHOWWINDOW    = 0x00000001
STARTF_USESIZE          = 0x00000002
STARTF_USEPOSITION      = 0x00000004
STARTF_USECOUNTCHARS    = 0x00000008
STARTF_USEFILLATTRIBUTE = 0x00000010
STARTF_RUNFULLSCREEN    = 0x00000020
STARTF_FORCEONFEEDBACK  = 0x00000040
STARTF_FORCEOFFFEEDBACK = 0x00000080
STARTF_USESTDHANDLES    = 0x00000100

STARTF_USEHOTKEY        = 0x00000200
STARTF_TITLEISLINKNAME  = 0x00000800
STARTF_TITLEISAPPID     = 0x00001000
STARTF_PREVENTPINNING   = 0x00002000

# winuser.h line 200
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

# winbase.h line 377
DEBUG_PROCESS                       = 0x00000001
DEBUG_ONLY_THIS_PROCESS             = 0x00000002
CREATE_SUSPENDED                    = 0x00000004
DETACHED_PROCESS                    = 0x00000008

CREATE_NEW_CONSOLE                  = 0x00000010
NORMAL_PRIORITY_CLASS               = 0x00000020
IDLE_PRIORITY_CLASS                 = 0x00000040
HIGH_PRIORITY_CLASS                 = 0x00000080

REALTIME_PRIORITY_CLASS             = 0x00000100
CREATE_NEW_PROCESS_GROUP            = 0x00000200
CREATE_UNICODE_ENVIRONMENT          = 0x00000400
CREATE_SEPARATE_WOW_VDM             = 0x00000800

CREATE_SHARED_WOW_VDM               = 0x00001000
CREATE_FORCEDOS                     = 0x00002000
BELOW_NORMAL_PRIORITY_CLASS         = 0x00004000
ABOVE_NORMAL_PRIORITY_CLASS         = 0x00008000

INHERIT_PARENT_AFFINITY             = 0x00010000
INHERIT_CALLER_PRIORITY             = 0x00020000
CREATE_PROTECTED_PROCESS            = 0x00040000
EXTENDED_STARTUPINFO_PRESENT        = 0x00080000

PROCESS_MODE_BACKGROUND_BEGIN       = 0x00100000
PROCESS_MODE_BACKGROUND_END         = 0x00200000

CREATE_BREAKAWAY_FROM_JOB           = 0x01000000
CREATE_PRESERVE_CODE_AUTHZ_LEVEL    = 0x02000000
CREATE_DEFAULT_ERROR_MODE           = 0x04000000
CREATE_NO_WINDOW                    = 0x08000000

PROFILE_USER                        = 0x10000000
PROFILE_KERNEL                      = 0x20000000
PROFILE_SERVER                      = 0x40000000
CREATE_IGNORE_SYSTEM_DEFAULT        = 0x80000000


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
SwitchToThisWindow                  = user32.SwitchToThisWindow
SwitchToThisWindow.argtypes         = [HWND, BOOL]
SwitchToThisWindow.restype          = BOOL

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
    SwitchToThisWindow(hwnd, True)
    return True


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


def kill_process_by_regex(regex: str) -> int:
    count = 0

    for proc in psutil.process_iter():
        cmdline = DataProcessInfo(proc=proc, pid=proc.pid).cmdline
        if not re.search(regex, cmdline):
            continue
        logger.info(f'Kill emulator: {cmdline}')
        proc.kill()
        count += 1

    return count


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


def _getprocess(proc: psutil.Process):
    try:
        processhandle = OpenProcess(PROCESS_ALL_ACCESS, False, proc.pid)
        if not processhandle:
            raise ctypes.WinError(GetLastError())

        mainthreadid = proc.threads()[0].id
        threadhandle = OpenThread(THREAD_ALL_ACCESS, False, mainthreadid)
        if not threadhandle:
            raise ctypes.WinError(GetLastError())

        return (PyHANDLE(processhandle), PyHANDLE(threadhandle), proc.pid, mainthreadid)
    except Exception as e:
        logger.warning(f"Failed to get process and thread handles: {e}")
        return (None, None, proc.pid, proc.threads()[0].id)

def getprocess(instance: EmulatorInstance):
    lppe = PROCESSENTRY32()
    lppe.dwSize = ctypes.sizeof(PROCESSENTRY32)
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, DWORD(0))
    Process32First(hSnapshot, ctypes.pointer(lppe))

    while Process32Next(hSnapshot, ctypes.pointer(lppe)):
        try:
            proc = psutil.Process(lppe.th32ProcessID)
            cmdline = DataProcessInfo(proc=proc, pid=proc.pid).cmdline
        except:
            continue
        if not instance.path in cmdline:
            continue
        if instance == Emulator.MuMuPlayer12:
            match = re.search(r'\d+$', cmdline)
            if match and int(match.group()) == instance.MuMuPlayer12_id:
                break
        elif instance == Emulator.LDPlayerFamily:
            match = re.search(r'\d+$', cmdline)
            if match and int(match.group()) == instance.LDPlayer_id:
                break
        else:
            matchstr = re.search(fr'\b{instance.name}$', cmdline)
            if matchstr and matchstr.group() == instance.name:
                break
    else:
        # finished querying
        errorcode = GetLastError()
        CloseHandle(hSnapshot)

        if errorcode != ERROR_NO_MORE_FILES:
            # error code != ERROR_NO_MORE_FILES, means that win api failed
            raise WinApiError(f"Win api failed with error code: {errorcode}")
        # process not found
        raise ProcessNotFoundError("Process not found")
        
    CloseHandle(hSnapshot)
    return _getprocess(proc)
    

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