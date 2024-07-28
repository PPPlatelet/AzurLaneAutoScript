from ctypes import \
    POINTER, sizeof, Structure as _Structure, \
    c_int32, c_uint32, c_uint64, c_uint16, \
    c_wchar, c_void_p, c_ubyte, c_byte, c_long, c_ulong
from ctypes.wintypes import MAX_PATH, FILETIME as _FILETIME

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
        return all(getattr(self, name) == getattr(other, name) for name in self.field_name)

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

    def __bool__(self):
        return any(getattr(self, name) for name in self.field_name)

# processthreadsapi.h line 28
class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ('hProcess',    c_void_p),
        ('hThread',     c_void_p),
        ('dwProcessId', c_uint32),
        ('dwThreadId',  c_uint32)
    ]

class STARTUPINFOW(Structure):
    _fields_ = [
        ("cb",              c_uint32),
        ("lpReserved",      POINTER(c_wchar)),
        ("lpDesktop",       POINTER(c_wchar)),
        ("lpTitle",         POINTER(c_wchar)),
        ("dwX",             c_uint32),
        ("dwY",             c_uint32),
        ("dwXSize",         c_uint32),
        ("dwYSize",         c_uint32),
        ("dwXCountChars",   c_uint32),
        ("dwYCountChars",   c_uint32),
        ("dwFillAttribute", c_uint32),
        ("dwFlags",         c_uint32),
        ("wShowWindow",     c_uint16),
        ("cbReserved2",     c_uint16),
        ("lpReserved2",     POINTER(c_ubyte)),
        ("hStdInput",       c_void_p),
        ("hStdOutput",      c_void_p),
        ("hStdError",       c_void_p)
    ]

# minwinbase.h line 13
class SECURITY_ATTRIBUTES(Structure):
    _fields_ = [
        ("nLength",                 c_uint32),
        ("lpSecurityDescriptor",    c_void_p),
        ("bInheritHandle",          c_int32)
    ]

# tlhelp32.h line 62
class PROCESSENTRY32W(Structure):
    _fields_ = [
        ("dwSize",              c_ulong),
        ("cntUsage",            c_ulong),
        ("th32ProcessID",       c_ulong),
        ("th32DefaultHeapID",   c_uint64),
        ("th32ModuleID",        c_ulong),
        ("cntThreads",          c_ulong),
        ("th32ParentProcessID", c_ulong),
        ("pcPriClassBase",      c_long),
        ("dwFlags",             c_ulong),
        ("szExeFile",           c_wchar * MAX_PATH)
    ]

class THREADENTRY32(Structure):
    _fields_ = [
        ("dwSize",              c_ulong),
        ("cntUsage",            c_ulong),
        ("th32ThreadID",        c_ulong),
        ("th32OwnerProcessID",  c_ulong),
        ("tpBasePri",           c_long),
        ("tpDeltaPri",          c_long),
        ("dwFlags",             c_ulong)
    ]

class POINT(Structure):
    _fields_ = [
        ("x", c_long),
        ("y", c_long)
    ]

class RECT(Structure):
    _fields_ = [
        ("left",    c_long),
        ("top",     c_long),
        ("right",   c_long),
        ("bottom",  c_long)
    ]

# winuser.h line 1801
class WINDOWPLACEMENT(Structure):
    _fields_ = [
        ("length",              c_uint32),
        ("flags",               c_uint32),
        ("showCmd",             c_uint32),
        ("ptMinPosition",       POINT),
        ("ptMaxPosition",       POINT),
        ("rcNormalPosition",    RECT)
    ]

# winternl.h line 25
class UNICODE_STRING(Structure):
    _fields_ = [
        ("Length",          c_uint16),
        ("MaximumLength",   c_uint16),
        ("Buffer",          POINTER(c_wchar))
    ]

# winternl.h line 54
class RTL_USER_PROCESS_PARAMETERS(Structure):
    _fields_ = [
        ("Reserved",        c_byte * 96),
        ("ImagePathName",   UNICODE_STRING),
        ("CommandLine",     UNICODE_STRING)
    ]

class PEB(Structure):
    _fields_ = [
        ("Reserved1",           c_byte * 32),
        ("ProcessParameters",   POINTER(RTL_USER_PROCESS_PARAMETERS)),
    ]

class PROCESS_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("ExitStatus",                      c_int32),
        ("PebBaseAddress",                  POINTER(PEB)),
        ("AffinityMask",                    c_uint64),
        ("BasePriority",                    c_int32),
        ("UniqueProcessId",                 c_uint64),
        ("InheritedFromUniqueProcessId",    c_uint64),
    ]

class FILETIME(Structure, _FILETIME):
    def to_int(self):
        return (self.dwHighDateTime << 32) + self.dwLowDateTime
