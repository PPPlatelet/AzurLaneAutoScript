from ctypes import POINTER, Structure
from ctypes.wintypes import (
    HANDLE, DWORD, WORD, LARGE_INTEGER, BYTE, BOOL, BOOLEAN,
    USHORT, UINT, LONG, ULONG, CHAR, LPWSTR, LPVOID, MAX_PATH,
    RECT, PULONG, POINT, PWCHAR
)

class EmulatorLaunchFailedError(Exception): ...
class HwndNotFoundError(Exception): ...
class IterationFinished(Exception): ...

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

class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ('hProcess',    HANDLE),
        ('hThread',     HANDLE),
        ('dwProcessId', DWORD),
        ('dwThreadId',  DWORD)
    ]

class SECURITY_ATTRIBUTES(Structure):
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

class WINDOWPLACEMENT(Structure):
    _fields_ = [
        ("length",              UINT),
        ("flags",               UINT),
        ("showCmd",             UINT),
        ("ptMinPosition",       POINT),
        ("ptMaxPosition",       POINT),
        ("rcNormalPosition",    RECT)
    ]

class LIST_ENTRY(Structure):
    _fields_ = [
        ("Flink", POINTER(LPVOID)),
        ("Blink", POINTER(LPVOID))
    ]

# ntbasic.h line 111
class UNICODE_STRING(Structure):
    _fields_ = [
        ("Length",          USHORT),
        ("MaximumLength",   USHORT),
        ("Buffer",          PWCHAR)
    ]

# ntpsapi.h line 63
class PEB_LDR_DATA(Structure):
    _fields_ = [
        ("Length",                          ULONG),
        ("Initialized",                     BOOLEAN),
        ("SsHandle",                        HANDLE),
        ("InLoadOrderModuleList",           LIST_ENTRY),
        ("InMemoryOrderModuleList",         LIST_ENTRY),
        ("InInitializationOrderModuleList", LIST_ENTRY),
        ("EntryInProgress",                 LPVOID),
        ("ShutdownInProgress",              BOOLEAN),
        ("ShutdownThreadId",                HANDLE)
    ]

# ntpebteb.h line 8
class PEB(Structure):
    _fields_ = [
        ("InheritedAddressSpace",           BOOLEAN),
        ("ReadImageFileExecOptions",        BOOLEAN),
        ("BeingDebugged",                   BOOLEAN),
        ("Spare",                           BOOLEAN),
        ("Mutant",                          HANDLE),
        ("ImageBaseAddress",                LPVOID),
        ("Ldr",                             POINTER(PEB_LDR_DATA)),
        ("ProcessParameters",               LPVOID),
        ("SubSystemData",                   LPVOID),
        ("ProcessHeap",                     LPVOID),
        ("FastPebLock",                     LPVOID),
        ("FastPebLockRoutine",              LPVOID),
        ("FastPebUnlockRoutine",            LPVOID),
        ("EnvironmentUpdateCount",          ULONG),
        ("KernelCallbackTable",             LPVOID),
        ("EventLogSection",                 LPVOID),
        ("EventLog",                        LPVOID),
        ("FreeList",                        LPVOID),
        ("TlsExpansionCounter",             ULONG),
        ("TlsBitmap",                       LPVOID),
        ("TlsBitmapBits",                   ULONG * 2),
        ("ReadOnlySharedMemoryBase",        LPVOID),
        ("ReadOnlySharedMemoryHeap",        LPVOID),
        ("ReadOnlyStaticServerData",        LPVOID),
        ("AnsiCodePageData",                LPVOID),
        ("OemCodePageData",                 LPVOID),
        ("UnicodeCaseTableData",            LPVOID),
        ("NumberOfProcessors",              ULONG),
        ("NtGlobalFlag",                    ULONG),
        ("Spare2",                          BYTE * 4),
        ("CriticalSectionTimeout",          LARGE_INTEGER),
        ("HeapSegmentReserve",              ULONG),
        ("HeapSegmentCommit",               ULONG),
        ("HeapDeCommitTotalFreeThreshold",  ULONG),
        ("HeapDeCommitFreeBlockThreshold",  ULONG),
        ("NumberOfHeaps",                   ULONG),
        ("MaximumNumberOfHeaps",            ULONG),
        ("ProcessHeaps",                    POINTER(LPVOID)),
        ("GdiSharedHandleTable",            LPVOID),
        ("ProcessStarterHelper",            LPVOID),
        ("GdiDCAttributeList",              LPVOID),
        ("LoaderLock",                      LPVOID),
        ("OSMajorVersion",                  ULONG),
        ("OSMinorVersion",                  ULONG),
        ("OSBuildNumber",                   ULONG),
        ("OSPlatformId",                    ULONG),
        ("ImageSubSystem",                  ULONG),
        ("ImageSubSystemMajorVersion",      ULONG),
        ("ImageSubSystemMinorVersion",      ULONG),
        ("GdiHandleBuffer",                 ULONG * 34),
        ("PostProcessInitRoutine",          ULONG),
        ("TlsExpansionBitmap",              ULONG),
        ("TlsExpansionBitmapBits",          BYTE * 32),
        ("SessionId",                       ULONG)
    ]

# ntrtl.h line 2320
class CURDIR(Structure):
    _fields_ = [
        ("DosPath", UNICODE_STRING),
        ("Handle",  HANDLE)
    ]

# ntrtl.h line 2329
class RTL_DRIVE_LETTER_CURDIR(Structure):
    _fields_ = [
        ("Flags",       USHORT),
        ("Length",      USHORT),
        ("TimeStamp",   ULONG),
        ("DosPath",     UNICODE_STRING)
    ]

# ntrtl.h line 2340
class RTL_USER_PROCESS_PARAMETERS(Structure):
    _fields_ = [
        ("MaximumLength",           ULONG),
        ("Length",                  ULONG),

        ("Flags",                   ULONG),
        ("DebugFlags",              ULONG),

        ("ConsoleHandle",           LPVOID),
        ("ConsoleFlags",            ULONG),
        ("StandardInput",           LPVOID),
        ("StandardOutput",          LPVOID),
        ("StandardError",           LPVOID),

        ("CurrentDirectory",        CURDIR),
        ("DllPath",                 UNICODE_STRING),
        ("ImagePathName",           UNICODE_STRING),
        ("CommandLine",             UNICODE_STRING),
        ("Environment",             LPVOID),

        ("StartingX",               ULONG),
        ("StartingY",               ULONG),
        ("CountX",                  ULONG),
        ("CountY",                  ULONG),
        ("CountCharsX",             ULONG),
        ("CountCharsY",             ULONG),
        ("FillAttribute",           ULONG),

        ("WindowFlags",             ULONG),
        ("ShowWindowFlags",         ULONG),
        ("WindowTitle",             UNICODE_STRING),
        ("DesktopInfo",             UNICODE_STRING),
        ("ShellInfo",               UNICODE_STRING),
        ("RuntimeData",             UNICODE_STRING),
        ("CurrentDirectories",      RTL_DRIVE_LETTER_CURDIR * 32),

        ("EnvironmentSize",         ULONG),
        ("EnvironmentVersion",      ULONG),
        ("PackageDependencyData",   LPVOID),
        ("ProcessGroupId",          ULONG),
        ("LoaderThreads",           ULONG)
    ]

class PROCESS_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("Reserved1",       LPVOID),
        ("PebBaseAddress",  POINTER(PEB)),
        ("Reserved2",       LPVOID * 2),
        ("UniqueProcessId", ULONG),
        ("Reserved3",       LPVOID)
    ]

class FILETIME(Structure):
    _fields_ = [
        ("dwLowDateTime",   DWORD),
        ("dwHighDateTime",  DWORD)
    ]

    def to_int(self):
        return (self.dwHighDateTime << 32) + self.dwLowDateTime
