import re
from sys import getwindowsversion

import psutil
from ctypes import (
    byref, sizeof, WinError, POINTER, WINFUNCTYPE,
    WinDLL, Structure
)
from ctypes.wintypes import (
    HANDLE, DWORD, WORD, BYTE, BOOL, INT, UINT, LONG,
    CHAR, LPWSTR, LPCWSTR, LPVOID, HWND, MAX_PATH,
    LPARAM, RECT, PULONG, POINT
)

from deploy.Windows.utils import DataProcessInfo
from module.device.platform.emulator_windows import Emulator, EmulatorInstance
from module.logger import logger

user32      = WinDLL(name='user32', use_last_error=True)
kernel32    = WinDLL(name='kernel32', use_last_error=True)

class EmulatorLaunchFailedError(Exception): ...
class HwndNotFoundError(Exception): ...

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
TH32CS_SNAPALL      = (
    TH32CS_SNAPHEAPLIST |
    TH32CS_SNAPPROCESS |
    TH32CS_SNAPTHREAD |
    TH32CS_SNAPMODULE
)
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


class STARTUPINFO(Structure):
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
        ('lpReserved2',     POINTER(BYTE)),
        ('hStdInput',       HANDLE),
        ('hStdOutput',      HANDLE),
        ('hStdError',       HANDLE)
    ]

class PROCESSINFORMATION(Structure):
    _fields_ = [
        ('hProcess',    HANDLE),
        ('hThread',     HANDLE),
        ('dwProcessId', DWORD),
        ('dwThreadId',  DWORD)
    ]

class SECURITYATTRIBUTES(Structure):
    _fields_ = [
        ("nLength",                 DWORD),
        ("lpSecurityDescriptor",    LPVOID),
        ("bInheritHandle",          BOOL)
    ]

class PROCESSENTRY32(Structure):
    _fields_ = [
        ("dwSize",              DWORD),
        ("cntUsage",            DWORD),
        ("th32ProcessID",       DWORD),
        ("th32DefaultHeapID",   PULONG),
        ("th32ModuleID",        DWORD),
        ("cntThreads",          DWORD),
        ("th32ParentProcessID", DWORD),
        ("pcPriClassBase",      LONG),
        ("dwFlags",             DWORD),
        ("szExeFile",           CHAR * MAX_PATH)
    ]

class WINDOWPLACEMENT(Structure):
    _fields_ = [
        ("length",              UINT),
        ("flags",               UINT),
        ("showCmd",             UINT),
        ("ptMinPosition",       POINT),
        ("ptMaxPosition",       POINT),
        ("rcNormalPosition",    RECT)
    ]


CreateProcessW                      = kernel32.CreateProcessW
CreateProcessW.argtypes             = [
    LPCWSTR,                        #lpApplicationName
    LPWSTR,                         #lpCommandLine
    POINTER(SECURITYATTRIBUTES),    #lpProcessAttributes
    POINTER(SECURITYATTRIBUTES),    #lpThreadAttributes
    BOOL,                           #bInheritHandles
    DWORD,                          #dwCreationFlags
    LPVOID,                         #lpEnvironment
    LPCWSTR,                        #lpCurrentDirectory
    POINTER(STARTUPINFO),           #lpStartupInfo
    POINTER(PROCESSINFORMATION)     #lpProcessInformation
]
CreateProcessW.restype              = BOOL

GetForegroundWindow                 = user32.GetForegroundWindow
GetForegroundWindow.restype         = HWND
SetForegroundWindow                 = user32.SetForegroundWindow
SetForegroundWindow.argtypes        = [HWND]
SetForegroundWindow.restype         = BOOL

GetWindowPlacement                  = user32.GetWindowPlacement
GetWindowPlacement.argtypes         = [HWND, POINTER(WINDOWPLACEMENT)]
GetWindowPlacement.restype          = BOOL

ShowWindow                          = user32.ShowWindow
ShowWindow.argtypes                 = [HWND, INT]
ShowWindow.restype                  = BOOL

IsWindow                            = user32.IsWindow
GetParent                           = user32.GetParent
GetWindowRect                       = user32.GetWindowRect

EnumWindows                         = user32.EnumWindows
EnumWindowsProc                     = WINFUNCTYPE(BOOL, HWND, LPARAM)
GetWindowThreadProcessId            = user32.GetWindowThreadProcessId
GetWindowThreadProcessId.argtypes   = [HWND, POINTER(DWORD)]
GetWindowThreadProcessId.restype    = DWORD

OpenProcess                         = kernel32.OpenProcess
OpenProcess.argtypes                = [DWORD, BOOL, DWORD]
OpenProcess.restype                 = HANDLE
OpenThread                          = kernel32.OpenThread

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

GetLastError                        = kernel32.GetLastError
GetLastError.restype                = BOOL


def getfocusedwindow():
    hwnd = GetForegroundWindow()
    if not hwnd:
        return None
    wp = WINDOWPLACEMENT()
    wp.length = sizeof(WINDOWPLACEMENT)
    if GetWindowPlacement(hwnd, byref(wp)):
        return hwnd, wp.showCmd
    else:
        return hwnd, SW_SHOWNORMAL

def setforegroundwindow(focusedwindow: tuple = ()) -> bool:
    if not focusedwindow:
        return False
    SetForegroundWindow(focusedwindow[0])
    ShowWindow(focusedwindow[0], focusedwindow[1])
    return True


def execute(command: str, arg: bool = False):
    from shlex import split
    from os.path import dirname
    lpApplicationName           = split(command)[0]
    lpCommandLine               = command
    lpProcessAttributes         = None
    lpThreadAttributes          = None
    bInheritHandles             = False
    dwCreationFlags             = (
        CREATE_NEW_CONSOLE |
        NORMAL_PRIORITY_CLASS |
        CREATE_NEW_PROCESS_GROUP |
        CREATE_DEFAULT_ERROR_MODE |
        CREATE_UNICODE_ENVIRONMENT
    )
    lpEnvironment               = None
    lpCurrentDirectory          = dirname(lpApplicationName)
    lpStartupInfo               = STARTUPINFO()
    lpStartupInfo.cb            = sizeof(STARTUPINFO)
    lpStartupInfo.dwFlags       = STARTF_USESHOWWINDOW
    lpStartupInfo.wShowWindow   = SW_HIDE if arg else SW_MINIMIZE
    lpProcessInformation        = PROCESSINFORMATION()

    focusedwindow               = getfocusedwindow()

    success                     = CreateProcessW(
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        byref(lpStartupInfo),
        byref(lpProcessInformation)
    )

    if not success:
        errorcode = GetLastError()
        raise EmulatorLaunchFailedError(f"Failed to start emulator. Error code: {errorcode}")
    
    process = (
        HANDLE(lpProcessInformation.hProcess),
        HANDLE(lpProcessInformation.hThread),
        lpProcessInformation.dwProcessId,
        lpProcessInformation.dwThreadId
    )
    return process, focusedwindow


def gethwnds(pid: int) -> list:
    hwnds = []

    @EnumWindowsProc
    def callback(hwnd: int, lparam):
        processid = DWORD()
        GetWindowThreadProcessId(hwnd, byref(processid))
        if processid.value == pid:
            hwnds.append(hwnd)
        return True
    
    EnumWindows(callback, 0)
    if not hwnds:
        logger.critical("Hwnd not found!")
        logger.critical("1.Perhaps emulator was killed.")
        logger.critical("2.Environment has something wrong. Please check the running environment.")
        raise HwndNotFoundError("Hwnd not found")
    return hwnds


def enumprocesses():
    lppe32          = PROCESSENTRY32()
    lppe32.dwSize   = sizeof(PROCESSENTRY32)
    snapshot        = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, DWORD(0))
    if snapshot == -1:
        raise RuntimeError(f"Failed to create process snapshot. Errorcode: {GetLastError()}")

    if not Process32First(snapshot, byref(lppe32)):
        CloseHandle(snapshot)
        raise RuntimeError(f"Failed to get first process. Errorcode: {GetLastError()}")

    try:
        while 1:
            yield lppe32
            if Process32Next(snapshot, byref(lppe32)):
                continue
            # finished querying
            errorcode = GetLastError()
            CloseHandle(snapshot)
            if errorcode != ERROR_NO_MORE_FILES:
                # error code != ERROR_NO_MORE_FILES, means that win api failed
                raise RuntimeError(f"Failed to get next process. Errorcode: {errorcode}")
            # process not found
            raise ProcessLookupError(f"Process not found. Errorcode: {errorcode}")
    except GeneratorExit:
        CloseHandle(snapshot)
    finally:
        del lppe32, snapshot
        if 'errorcode' in locals():
            del errorcode
        
def kill_process_by_regex(regex: str) -> int:
    count = 0

    try:
        for lppe32 in enumprocesses():
            proc    = psutil.Process(lppe32.th32ProcessID)
            cmdline = DataProcessInfo(proc=proc, pid=proc.pid).cmdline
            if not re.search(regex, cmdline):
                continue
            logger.info(f'Kill emulator: {cmdline}')
            proc.kill()
            count += 1
    except ProcessLookupError:
        enumprocesses().throw(GeneratorExit)
        return count

def _getprocess(proc: psutil.Process):
    mainthreadid = proc.threads()[0].id
    try:
        processhandle = OpenProcess(PROCESS_ALL_ACCESS, False, proc.pid)
        if not processhandle:
            raise WinError(GetLastError())

        threadhandle = OpenThread(THREAD_ALL_ACCESS, False, mainthreadid)
        if not threadhandle:
            CloseHandle(processhandle)
            raise WinError(GetLastError())

        return HANDLE(processhandle), HANDLE(threadhandle), proc.pid, mainthreadid
    except Exception as e:
        logger.warning(f"Failed to get process and thread handles: {e}")
        return None, None, proc.pid, mainthreadid

def getprocess(instance: EmulatorInstance):
    processes = enumprocesses()
    for lppe32 in processes:
        proc    = psutil.Process(lppe32.th32ProcessID)
        cmdline = DataProcessInfo(proc=proc, pid=proc.pid).cmdline
        if not instance.path in cmdline:
            continue
        if instance == Emulator.MuMuPlayer12:
            match = re.search(r'\d+$', cmdline)
            if match and int(match.group()) == instance.MuMuPlayer12_id:
                processes.close()
                return _getprocess(proc)
        elif instance == Emulator.LDPlayerFamily:
            match = re.search(r'\d+$', cmdline)
            if match and int(match.group()) == instance.LDPlayer_id:
                processes.close()
                return _getprocess(proc)
        else:
            matchstr = re.search(fr'\b{instance.name}$', cmdline)
            if matchstr and matchstr.group() == instance.name:
                processes.close()
                return _getprocess(proc)


def switchwindow(hwnds: list, arg: int = 1):
    for hwnd in hwnds:
        if not IsWindow(hwnd):
            continue
        if GetParent(hwnd):
            continue
        rect = RECT()
        GetWindowRect(hwnd, byref(rect))
        if {rect.left, rect.top, rect.right, rect.bottom} == {0}:
            continue
        ShowWindow(hwnd, arg)
    return True
