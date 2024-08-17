import threading
import re
from typing import Callable, Generator, Optional, Tuple, List

from ctypes import byref, create_unicode_buffer, wstring_at, addressof
from ctypes.wintypes import HANDLE, HWND, LPARAM, DWORD, ULONG, LPCWSTR, LPWSTR, BOOL, LPVOID, UINT, INT

from module.device.platform.emulator_windows import Emulator, EmulatorInstance
from module.device.platform.winapi import *
from module.logger import logger


def closehandle(*args, fclose=CloseHandle) -> bool:
    for handle in args:
        fclose(handle)
    return True


def __yield_entries(entry32, snapshot, func: Callable) -> Generator:
    while 1:
        yield entry32
        if func(snapshot, byref(entry32)):
            continue
        # Finished querying
        errorcode = GetLastError()
        assert errorcode == ERROR_NO_MORE_FILES, report(f"{func.__name__} failed", statuscode=errorcode)
        report("Finished querying.", statuscode=errorcode, uselog=False, exception=IterationFinished)


def _enum_processes() -> Generator:
    lppe32          = PROCESSENTRY32W()
    lppe32.dwSize   = sizeof(PROCESSENTRY32W)
    with create_snapshot(TH32CS_SNAPPROCESS) as snapshot:
        assert Process32First(HANDLE(snapshot), byref(lppe32)), report("Process32First failed")
        yield from __yield_entries(lppe32, snapshot, Process32Next)


def _enum_threads() -> Generator:
    lpte32          = THREADENTRY32()
    lpte32.dwSize   = sizeof(THREADENTRY32)
    with create_snapshot(TH32CS_SNAPTHREAD) as snapshot:
        assert Thread32First(HANDLE(snapshot), byref(lpte32)), report("Thread32First failed")
        yield from __yield_entries(lpte32, snapshot, Thread32Next)


def getfocusedwindow() -> Tuple[int, Optional[WINDOWPLACEMENT]]:
    hwnd = GetForegroundWindow()
    wp = WINDOWPLACEMENT()
    wp.length = sizeof(WINDOWPLACEMENT)
    if GetWindowPlacement(hwnd, byref(wp)):
        return hwnd, wp
    else:
        report("Failed to get windowplacement", level=30, raiseexcept=False)
        return hwnd, None


def setforegroundwindow(focusedwindow: Tuple[int, Optional[WINDOWPLACEMENT]]) -> bool:
    SetForegroundWindow(HANDLE(focusedwindow[0]))
    if focusedwindow[1] is None:
        ShowWindow(HANDLE(focusedwindow[0]), SW_SHOWNORMAL)
    else:
        ShowWindow(HANDLE(focusedwindow[0]), focusedwindow[1].showCmd)
        SetWindowPlacement(HANDLE(focusedwindow[0]), focusedwindow[1])
    return True


def refresh_window(focusedwindow, max_attempts=10, interval=0.5) -> None:
    from time import sleep
    from itertools import combinations

    attempts = 0
    prevwindow = ()

    def unique(*args):
        return all(x[0] != y[0] for x, y in combinations(args, 2))

    while attempts < max_attempts:
        currentwindow = getfocusedwindow()
        if prevwindow:
            if unique(currentwindow, prevwindow, focusedwindow):
                break

        if unique(focusedwindow, currentwindow):
            logger.info(f"Current window is {currentwindow[0]}, flash back to {focusedwindow[0]}")
            setforegroundwindow(focusedwindow)
            attempts += 1
            sleep(interval)

        attempts += 1
        sleep(interval)

        prevwindow = currentwindow


def execute(command: str, silentstart: bool, start: bool) -> Tuple[Optional[PROCESS_INFORMATION], Tuple[int, Optional[WINDOWPLACEMENT]]]:
    # TODO:Create Process with non-administrator privileges
    from shlex import split
    from os.path import dirname
    focusedwindow               = getfocusedwindow()
    if start:
        threading.Thread(target=refresh_window, args=(focusedwindow,)).start()

    chandle = HANDLE()
    OpenProcessToken(GetCurrentProcess(), DWORD(TOKEN_DUPLICATE), byref(chandle))
    hToken = HANDLE()
    DuplicateTokenEx(
        chandle,
        DWORD(TOKEN_DUPLICATE | TOKEN_QUERY, TOKEN_ADJUST_SESSIONID),
        None,
        ULONG(SECURITY_DELEGATION),
        ULONG(TOKEN_PRIMARY),
        byref(hToken)
    )
    token_groups = TOKEN_GROUPS()
    token_groups.GroupCount = 1
    token_groups.Groups[0].Attributes = SE_GROUP_USE_FOR_DENY_ONLY
    AdjustTokenGroups(
        hToken,
        BOOL(True),
        byref(token_groups),
        DWORD(0),
        None,
        None
    )

    dwLogonFlags = 0
    lpApplicationName           = split(command)[0]
    lpCommandLine               = command
    # lpProcessAttributes         = None
    # lpThreadAttributes          = None
    # bInheritHandles             = False
    dwCreationFlags             = (
        DETACHED_PROCESS |
        CREATE_UNICODE_ENVIRONMENT
    )
    lpEnvironment               = None
    lpCurrentDirectory          = dirname(lpApplicationName)
    lpStartupInfo               = STARTUPINFOW()
    lpStartupInfo.cb            = sizeof(STARTUPINFOW)
    lpStartupInfo.dwFlags       = STARTF_USESHOWWINDOW
    if start:
        lpStartupInfo.wShowWindow   = SW_FORCEMINIMIZE if silentstart else SW_MINIMIZE
    else:
        lpStartupInfo.wShowWindow   = SW_FORCEMINIMIZE
    lpProcessInformation        = PROCESS_INFORMATION()

    assert CreateProcessWithTokenW(
        hToken,
        DWORD(dwLogonFlags),
        LPCWSTR(lpApplicationName),
        LPWSTR(lpCommandLine),
        DWORD(dwCreationFlags),
        LPVOID(lpEnvironment),
        LPCWSTR(lpCurrentDirectory),
        byref(lpStartupInfo),
        byref(lpProcessInformation)
    ),  report("Failed to start emulator", exception=EmulatorLaunchFailedError)

    if start:
        return lpProcessInformation, focusedwindow
    else:
        closehandle(*lpProcessInformation[:2])
        return None, focusedwindow


def terminate_process(pid: int) -> bool:
    with open_process(PROCESS_TERMINATE, pid) as hProcess:
        assert TerminateProcess(HANDLE(hProcess), UINT(0)), report("Failed to kill process")
    return True


def get_hwnds(pid: int) -> List[int]:
    hwnds = []

    @EnumWindowsProc
    def callback(hwnd: HWND, lparam: LPARAM):  # DO NOT DELETE THIS PARAMETER!!!
        processid = DWORD()
        GetWindowThreadProcessId(hwnd, byref(processid))
        if processid.value == pid:
            hwnds.append(hwnd)
        return True
    
    assert EnumWindows(callback, LPARAM(0)), report("Failed to get hwnds")

    if not hwnds:
        logger.error("Hwnd not found!")
        logger.error("1.Perhaps emulator has been killed.")
        logger.error("2.Environment has something wrong. Please check the running environment.")
        report("Hwnd not found", exception=HwndNotFoundError)
    return hwnds


def get_cmdline(pid: int) -> str:
    try:
        with open_process(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, pid) as hProcess:
            # Query process infomation
            pbi = PROCESS_BASIC_INFORMATION()
            returnlength = ULONG(sizeof(pbi))
            status = NtQueryInformationProcess(HANDLE(hProcess), INT(0), byref(pbi), ULONG(sizeof(pbi)), byref(returnlength))
            assert status == STATUS_SUCCESS, \
                report(f"NtQueryInformationProcess failed. Status: 0x{status:x}.", level=30)

            # Read PEB
            peb = PEB()
            assert ReadProcessMemory(HANDLE(hProcess), pbi.PebBaseAddress, byref(peb), SIZE_T(sizeof(peb)), None), \
                report("Failed to read PEB", level=30)

            # Read process parameters
            upp = RTL_USER_PROCESS_PARAMETERS()
            assert ReadProcessMemory(HANDLE(hProcess), peb.ProcessParameters, byref(upp), SIZE_T(sizeof(upp)), None), \
                report("Failed to read process parameters", level=30)

            # Read command line
            commandLine = create_unicode_buffer(upp.CommandLine.Length // 2)
            assert ReadProcessMemory(HANDLE(hProcess), upp.CommandLine.Buffer, commandLine, upp.CommandLine.Length, None), \
                report("Failed to read command line", level=30)

            cmdline = wstring_at(addressof(commandLine), len(commandLine))
    except OSError:
        return ''
    return fstr(cmdline)


def kill_process_by_regex(regex: str) -> int:
    count = 0

    try:
        for lppe32 in _enum_processes():
            pid     = lppe32.th32ProcessID
            cmdline = get_cmdline(lppe32.th32ProcessID)
            if not re.search(regex, cmdline):
                continue
            logger.info(f'Kill emulator: {cmdline}')
            terminate_process(pid)
            count += 1
    except IterationFinished:
        return count


def __get_creation_time(fopen: Callable, fgettime: Callable, access: int, identification: int) -> Optional[int]:
    with fopen(access, identification, uselog=False, raiseexcept=False) as handle:
        creationtime    = FILETIME()
        exittime        = FILETIME()
        kerneltime      = FILETIME()
        usertime        = FILETIME()
        if not fgettime(
            handle,
            byref(creationtime),
            byref(exittime),
            byref(kerneltime),
            byref(usertime)
        ):
            return None
        return creationtime.to_int()

def _get_process_creation_time(pid: int) -> Optional[int]:
    return __get_creation_time(open_process, GetProcessTimes, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, pid)

def _get_thread_creation_time(tid: int) -> Optional[int]:
    return __get_creation_time(open_thread, GetThreadTimes, THREAD_QUERY_INFORMATION, tid)


def get_thread(pid: int) -> int:
    mainthreadid    = 0
    minstarttime    = MAXULONGLONG
    try:
        for lpte32 in _enum_threads():
            if lpte32.th32OwnerProcessID != pid:
                continue

            # In general, the first tid obtained by traversing is always the main tid, so these code can be commented.
            threadstarttime = _get_thread_creation_time(lpte32.th32ThreadID)
            if threadstarttime is None or threadstarttime >= minstarttime:
                continue

            minstarttime = threadstarttime
            mainthreadid = lpte32.th32ThreadID
    except IterationFinished:
        return mainthreadid


def _get_process(pid: int) -> PROCESS_INFORMATION:
    tid = get_thread(pid)
    pi = PROCESS_INFORMATION(None, None, pid, tid)
    try:
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, BOOL(False), ULONG(pid))
        assert hProcess is not None, \
            report("OpenProcess failed", level=30)

        hThread = OpenThread(THREAD_ALL_ACCESS, BOOL(False), ULONG(tid))
        if hThread is None:
            CloseHandle(hProcess)
            report("OpenThread failed", level=30)

        pi.hProcess, pi.hThread = hProcess, hThread
    except Exception as e:
        logger.warning(f"Failed to get process and thread handles: {e}")
    finally:
        logger.info(f"Emulator Process: {pi}")
        return pi

def get_process(instance: EmulatorInstance) -> PROCESS_INFORMATION:
    for lppe32 in _enum_processes():
        pid = lppe32.th32ProcessID
        cmdline = get_cmdline(pid)
        if not instance.path in cmdline:
            continue
        if instance == Emulator.MuMuPlayer12:
            match = re.search(r'-v\s*(\d+)', cmdline)
            if match and int(match.group(1)) == instance.MuMuPlayer12_id:
                return _get_process(pid)
        elif instance == Emulator.LDPlayerFamily:
            match = re.search(r'index=\s*(\d+)', cmdline)
            if match and int(match.group(1)) == instance.LDPlayer_id:
                return _get_process(pid)
        else:
            matchname = re.search(fr'{instance.name}(\s+|$)', cmdline)
            if matchname and matchname.group(0).strip() == instance.name:
                return _get_process(pid)


def switch_window(hwnds: List[int], arg: int = SW_SHOWNORMAL) -> bool:
    for hwnd in hwnds:
        if not GetWindow(HANDLE(hwnd), GW_CHILD):
            continue
        ShowWindow(HANDLE(hwnd), INT(arg))
    return True

def get_parent_pid(pid: int) -> int:
    try:
        with open_process(PROCESS_QUERY_INFORMATION, pid) as hProcess:
            # Query process infomation
            pbi = PROCESS_BASIC_INFORMATION()
            returnlength = ULONG(sizeof(pbi))
            status = NtQueryInformationProcess(HANDLE(hProcess), INT(0), byref(pbi), returnlength, byref(returnlength))
            assert status == STATUS_SUCCESS, \
                report(f"NtQueryInformationProcess failed. Status: 0x{status:x}.", level=30)
    except OSError:
        return -1
    return pbi.InheritedFromUniqueProcessId

def get_exit_code(pid: int) -> int:
    try:
        with open_process(PROCESS_QUERY_INFORMATION, pid) as hProcess:
            exit_code = ULONG()
            assert GetExitCodeProcess(HANDLE(hProcess), byref(exit_code)), \
                report("Failed to get Exit code", level=30)
    except OSError:
        return -1
    return exit_code.value

def is_running(ppid: int = 0, pid: int = 0) -> bool:
    if pid and get_exit_code(pid) != STILL_ACTIVE:
        return False
    if ppid and ppid != get_parent_pid(pid):
        return False
    return True

if __name__ == '__main__':
    c = fstr('"E:\\Program Files\\Netease\\MuMu Player 12\\shell\\MuMuPlayer.exe" -v 2')
    p, fw = execute(c, False, True)
    logger.info(p)
    logger.info(fw)
