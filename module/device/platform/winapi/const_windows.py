from sys import getwindowsversion
from ctypes.wintypes import LPVOID

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

# subauth.h line 250
STATUS_SUCCESS                  = 0x00000000
STATUS_INVALID_INFO_CLASS       = 0xC0000003
STATUS_NO_SUCH_USER             = 0xC0000064
STATUS_WRONG_PASSWORD           = 0xC000006A
STATUS_PASSWORD_RESTRICTION     = 0xC000006C
STATUS_LOGON_FAILURE            = 0xC000006D
STATUS_ACCOUNT_RESTRICTION      = 0xC000006E
STATUS_INVALID_LOGON_HOURS      = 0xC000006F
STATUS_INVALID_WORKSTATION      = 0xC0000070
STATUS_PASSWORD_EXPIRED         = 0xC0000071
STATUS_ACCOUNT_DISABLED         = 0xC0000072
STATUS_INSUFFICIENT_RESOURCES   = 0xC000009A
STATUS_ACCOUNT_EXPIRED          = 0xC0000193
STATUS_PASSWORD_MUST_CHANGE     = 0xC0000224
STATUS_ACCOUNT_LOCKED_OUT       = 0xC0000234

# error.h line 23
ERROR_NO_MORE_FILES = 0x12

# winerror.h
ERROR_SUCCESS               = 0     # line 227
ERROR_INSUFFICIENT_BUFFER   = 122   # line 1041

# winbase.h line 822
INFINITE = 0xFFFFFFFF

# winevt.h line 156
EVT_QUERY_CHANNEL_PATH          = 0x1
EVT_QUERY_FILE_PATH             = 0x2
EVT_QUERY_FORWARD_DIRECTION     = 0x100
EVT_QUERY_REVERSE_DIRECTION     = 0x200
EVT_QUERY_TOLERATE_QUERY_ERRORS = 0x1000
# line 176
EVT_RENDER_EVENT_VALUES = 0
EVT_RENDER_EVENT_XML    = 1
EVT_RENDER_BOOK_MARK    = 2
# line 242
EVT_VAR_TYPE_NULL               = 0
EVT_VAR_TYPE_STRING             = 1
EVT_VAR_TYPE_ANSISTRING         = 2
EVT_VAR_TYPE_SBYTE              = 3
EVT_VAR_TYPE_BYTE               = 4
EVT_VAR_TYPE_INT16              = 5
EVT_VAR_TYPE_UINT16             = 6
EVT_VAR_TYPE_INT32              = 7
EVT_VAR_TYPE_UINT32             = 8
EVT_VAR_TYPE_INT64              = 9
EVT_VAR_TYPE_UINT64             = 10
EVT_VAR_TYPE_SINGLE             = 11
EVT_VAR_TYPE_DOUBLE             = 12
EVT_VAR_TYPE_BOOLEAN            = 13
EVT_VAR_TYPE_BINARY             = 14
EVT_VAR_TYPE_GUID               = 15
EVT_VAR_TYPE_SIZET              = 16
EVT_VAR_TYPE_FILETIME           = 17
EVT_VAR_TYPE_SYSTIME            = 18
EVT_VAR_TYPE_SID                = 19
EVT_VAR_TYPE_HEXINT32           = 20
EVT_VAR_TYPE_HEXINT64           = 21
EVT_VAR_TYPE_EVTHANDLE          = 32
EVT_VAR_TYPE_EVTXML             = 35

MAXULONGLONG            = LPVOID(-1).value
INVALID_HANDLE_VALUE    = -1
