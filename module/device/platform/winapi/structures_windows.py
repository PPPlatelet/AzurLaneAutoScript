from ctypes import POINTER, Structure
from ctypes.wintypes import (
    HANDLE, DWORD, WORD, BYTE, BOOL, USHORT,
    UINT, LONG, CHAR, LPWSTR, LPVOID, MAX_PATH,
    RECT, PULONG, POINT, PWCHAR, FILETIME
)

class EmulatorLaunchFailedError(Exception): ...
class HwndNotFoundError(Exception): ...
class IterationFinished(Exception): ...

# processthreadsapi.h line 28
class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ('hProcess',    HANDLE),
        ('hThread',     HANDLE),
        ('dwProcessId', DWORD),
        ('dwThreadId',  DWORD)
    ]

class STARTUPINFOW(Structure):
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

# minwinbase.h line 13
class SECURITY_ATTRIBUTES(Structure):
    _fields_ = [
        ("nLength",                 DWORD),
        ("lpSecurityDescriptor",    LPVOID),
        ("bInheritHandle",          BOOL)
    ]

# tlhelp32.h line 62
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

class THREADENTRY32(Structure):
    _fields_ = [
        ("dwSize",              DWORD),
        ("cntUsage",            DWORD),
        ("th32ThreadID",        DWORD),
        ("th32OwnerProcessID",  DWORD),
        ("tpBasePri",           LONG),
        ("tpDeltaPri",          LONG),
        ("dwFlags",             DWORD)
    ]

# winuser.h line 1801
class WINDOWPLACEMENT(Structure):
    _fields_ = [
        ("length",              UINT),
        ("flags",               UINT),
        ("showCmd",             UINT),
        ("ptMinPosition",       POINT),
        ("ptMaxPosition",       POINT),
        ("rcNormalPosition",    RECT)
    ]


# winternl.h line 25
class UNICODE_STRING(Structure):
    _fields_ = [
        ("Length",          USHORT),
        ("MaximumLength",   USHORT),
        ("Buffer",          PWCHAR)
    ]


# winternl.h line 54
class RTL_USER_PROCESS_PARAMETERS(Structure):
    _fields_ = [
        ("Reserved",        LPVOID * 12),
        ("ImagePathName",   UNICODE_STRING),
        ("CommandLine",     UNICODE_STRING)
    ]

class PEB(Structure):
    _fields_ = [
        ("Reserved",                BYTE * 28),
        ("ProcessParameters",       POINTER(RTL_USER_PROCESS_PARAMETERS)),
    ]

class PROCESS_BASIC_INFORMATION(Structure):
    NTSTATUS    = LONG
    KPRIORITY   = LONG
    KAFFINITY   = PULONG
    _fields_ = [
        ("ExitStatus",                      NTSTATUS),
        ("PebBaseAddress",                  POINTER(PEB)),
        ("AffinityMask",                    KAFFINITY),
        ("BasePriority",                    KPRIORITY),
        ("UniqueProcessId",                 PULONG),
        ("InheritedFromUniqueProcessId",    PULONG),
    ]

def to_int(filetime: FILETIME):
    return (filetime.dwHighDateTime << 32) + filetime.dwLowDateTime
