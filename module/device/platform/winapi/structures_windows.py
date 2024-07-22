from ctypes import POINTER, sizeof, Structure as _Structure
from ctypes.wintypes import (
    HANDLE, DWORD, WORD, BYTE, BOOL, USHORT,
    UINT, LONG, WCHAR, LPWSTR, LPVOID, MAX_PATH,
    RECT, PULONG, POINT, PWCHAR, FILETIME as _FILETIME
)

class EmulatorLaunchFailedError(Exception): ...
class HwndNotFoundError(Exception): ...
class IterationFinished(Exception): ...

class Structure(_Structure):
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        cls.field_name = tuple(name for name, _ in cls._fields_)
        cls.field_type = tuple(_type for _, _type in cls._fields_)

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        for name in self.field_name:
            if getattr(self, name) != getattr(other, name):
                return False
        return True

    def __repr__(self):
        field_values = ', '.join(f"{name}={getattr(self, name)!r}" for name in self.field_name)
        return f"{self.__class__.__name__}({field_values})"

    def __str__(self):
        field_values = ', '.join(f"{name}={getattr(self, name)}" for name in self.field_name)
        return f"{self.__class__.__name__}({field_values})"

    def __hash__(self):
        field_values = tuple(getattr(self, name) for name in self.field_name)
        return hash((self.__class__, field_values))

    def __sizeof__(self):
        return sizeof(self)

    def __iter__(self):
        for name in self.field_name:
            yield name, getattr(self, name)

    def __setitem__(self, key, value):
        if isinstance(key, slice):
            indices = range(*key.indices(len(self)))
            if len(indices) != len(value):
                raise ValueError("Value list length does not match slice length")
            for i, val in zip(indices, value):
                setattr(self, self.field_name[i], val)
        elif isinstance(key, int):
            if key < 0 or key >= len(self):
                raise IndexError("Index out of range")
            setattr(self, self.field_name[key], value)
        elif isinstance(key, str):
            if key not in self.field_name:
                raise KeyError(f"'{self.__class__.__name__}' object has no key '{key}'")
            setattr(self, key, value)
        else:
            raise TypeError("Invalid argument type")

    def __getitem__(self, item):
        if isinstance(item, slice):
            indices = range(*item.indices(len(self)))
            return [getattr(self, self.field_name[i]) for i in indices]
        elif isinstance(item, int):
            if item < 0 or item >= len(self):
                raise IndexError("Index out of range")
            return getattr(self, self.field_name[item])
        elif isinstance(item, str):
            if item not in self.field_name:
                raise KeyError(f"'{self.__class__.__name__}' object has no item '{item}'")
            return getattr(self, item)
        else:
            raise TypeError("Invalid argument type")

    def __contains__(self, item):
        return item in self.field_name

    def __copy__(self):
        cls = self.__class__
        result = cls.__new__(cls)
        result.__dict__.update(self.__dict__)
        return result

    def __deepcopy__(self, memodict=None):
        import copy as cp
        if memodict is None:
            memodict = {}
        cls = self.__class__
        result = cls.__new__(cls)
        memodict[id(self)] = result
        for name in self.field_name:
            setattr(result, name, cp.deepcopy(getattr(self, name), memodict))
        return result

    def __len__(self):
        return len(self.field_name)

    def __dir__(self):
        return super().__dir__()

    def __format__(self, format_spec):
        if format_spec == '':
            return str(self)
        elif format_spec == 'b':
            field_values = ', '.join(
                f"{name}=0b{getattr(self, name):b}"
                if isinstance(getattr(self, name), int)
                else f"{name}={getattr(self, name)}"
                for name in self.field_name
            )
            return f"{self.__class__.__name__}({field_values})"
        elif format_spec == 'x':
            field_values = ', '.join(
                f"{name}=0x{getattr(self, name):x}"
                if isinstance(getattr(self, name), int)
                else f"{name}={getattr(self, name)}"
                for name in self.field_name
            )
            return f"{self.__class__.__name__}({field_values})"
        else:
            raise ValueError(f"Unsupported format specifier: {format_spec}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb): ...

    def __bytes__(self):
        return bytes(str(self), 'utf-8')

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
class PROCESSENTRY32W(Structure):
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
        ("szExeFile",           WCHAR * MAX_PATH)
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
        ("Reserved",            BYTE * 28),
        ("ProcessParameters",   POINTER(RTL_USER_PROCESS_PARAMETERS)),
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

class FILETIME(Structure, _FILETIME):
    def to_int(self):
        return (self.dwHighDateTime << 32) + self.dwLowDateTime
