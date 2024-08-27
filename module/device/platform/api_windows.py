import threading
import re
from typing import Generator

from ctypes import addressof, create_unicode_buffer, wstring_at

from module.device.platform.emulator_windows import Emulator
from module.device.platform.winapi import *
from module.logger import logger


def close_handle(*args, fclose=CloseHandle):
    count = 0
    for handle in args:
        if isinstance(handle, int):
            handle = HANDLE(handle)
        if isinstance(handle, c_void_p):
            fclose(handle)
            count += 1
            logger.info(f"Closed handle: {handle}")
        else:
            report(
                f"Expected a int or c_void_p, but got {type(handle).__name__}",
                reportstatus=False,
                level=30,
                raise_=False,
            )
    if not count:
        report(
            f"All handles are unavailable, please check the running environment",
            reportstatus=False,
            raise_=False
        )
        return False
    return True


def __yield_entries(entry32, snapshot, func):
    while 1:
        yield entry32
        if func(snapshot, byref(entry32)):
            continue
        # Finished querying
        errorcode = GetLastError()
        assert errorcode == ERROR_NO_MORE_FILES, report(f"{func.__name__} failed", statuscode=errorcode)
        report("Finished querying.", statuscode=errorcode, uselog=False, exception=IterationFinished)


def _enum_processes() -> Generator[PROCESSENTRY32W, None, None]:
    lppe32          = PROCESSENTRY32W()
    lppe32.dwSize   = sizeof(PROCESSENTRY32W)
    with create_snapshot(TH32CS_SNAPPROCESS) as snapshot:
        assert Process32First(snapshot, byref(lppe32)), report("Process32First failed")
        yield from __yield_entries(lppe32, snapshot, Process32Next)


def _enum_threads() -> Generator[THREADENTRY32, None, None]:
    lpte32          = THREADENTRY32()
    lpte32.dwSize   = sizeof(THREADENTRY32)
    with create_snapshot(TH32CS_SNAPTHREAD) as snapshot:
        assert Thread32First(snapshot, byref(lpte32)), report("Thread32First failed")
        yield from __yield_entries(lpte32, snapshot, Thread32Next)


def get_focused_window():
    hwnd = HWND(GetForegroundWindow())
    wp = WINDOWPLACEMENT()
    wp.length = sizeof(WINDOWPLACEMENT)
    if GetWindowPlacement(hwnd, byref(wp)):
        return hwnd, wp
    else:
        report("Failed to get windowplacement", level=30, raise_=False)
        return hwnd, None


def set_focus_to_window(focusedwindow):
    SetForegroundWindow(focusedwindow[0])
    if focusedwindow[1] is None:
        ShowWindow(focusedwindow[0], SW_SHOWNORMAL)
    else:
        ShowWindow(focusedwindow[0], focusedwindow[1].showCmd)
        SetWindowPlacement(focusedwindow[0], focusedwindow[1])
    return True


def refresh_window(focusedwindow, max_attempts=10, interval=0.5):
    from time import sleep
    from itertools import combinations

    attempts = 0
    prevwindow = None

    unique = lambda *args: all(x[0].value != y[0].value for x, y in combinations(args, 2))

    while attempts < max_attempts:
        currentwindow = get_focused_window()
        if prevwindow:
            if unique(currentwindow, prevwindow, focusedwindow):
                break

        if unique(focusedwindow, currentwindow):
            logger.info(f"Current window is {currentwindow[0]}, flash back to {focusedwindow[0]}")
            set_focus_to_window(focusedwindow)
            attempts += 1
            sleep(interval)

        attempts += 1
        sleep(interval)

        prevwindow = currentwindow


def execute(command, silentstart, start):
    # TODO:Create Process with non-administrator privileges
    from shlex import split
    from os.path import dirname
    focusedwindow               = get_focused_window()
    if start:
        threading.Thread(target=refresh_window, name='Refresh_Thread', args=(focusedwindow,)).start()

    chandle = HANDLE()
    OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE, byref(chandle))
    hToken = HANDLE()
    DuplicateTokenEx(
        chandle,
        TOKEN_DUPLICATE | TOKEN_QUERY, TOKEN_ADJUST_SESSIONID,
        None,
        SECURITY_DELEGATION,
        TOKEN_PRIMARY,
        byref(hToken)
    )
    token_groups = TOKEN_GROUPS()
    token_groups.GroupCount = 1
    token_groups.Groups[0].Attributes = SE_GROUP_USE_FOR_DENY_ONLY
    AdjustTokenGroups(
        hToken,
        True,
        byref(token_groups),
        0,
        None,
        None
    )

    dwLogonFlags = DWORD(0)
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
        dwLogonFlags,
        lpApplicationName,
        lpCommandLine,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        byref(lpStartupInfo),
        byref(lpProcessInformation)
    ),  report("Failed to start emulator", exception=EmulatorLaunchFailedError)

    if start:
        return lpProcessInformation, focusedwindow
    else:
        close_handle(*lpProcessInformation[:2])
        return None, focusedwindow


def terminate_process(pid):
    with open_process(PROCESS_TERMINATE, pid) as hProcess:
        assert TerminateProcess(hProcess, 0), report("Failed to kill process")
    return True


def get_hwnds(pid):
    hwnds = []

    @EnumWindowsProc
    def callback(hwnd: HWND, lparam: LPARAM):  # DO NOT DELETE THIS PARAMETER!!!
        processid = DWORD()
        GetWindowThreadProcessId(hwnd, byref(processid))
        if processid.value == pid:
            hwnds.append(HWND(hwnd))
        return True
    
    assert EnumWindows(callback, LPARAM(0)), report("Failed to get hwnds")

    if not hwnds:
        logger.error("Hwnd not found!")
        logger.error("1.Perhaps emulator has been killed.")
        logger.error("2.Environment has something wrong. Please check the running environment.")
        report("Hwnd not found", exception=HwndNotFoundError)
    return hwnds


def get_cmdline(pid):
    try:
        with open_process(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, pid) as hProcess:
            # Query process infomation
            pbi = PROCESS_BASIC_INFORMATION()
            returnlength = ULONG(sizeof(pbi))
            status = NtQueryInformationProcess(hProcess, 0, byref(pbi), sizeof(pbi), byref(returnlength))
            assert status == STATUS_SUCCESS, \
                report(f"NtQueryInformationProcess failed. Status: 0x{status:08x}", uselog=False)

            # Read PEB
            peb = PEB()
            assert ReadProcessMemory(hProcess, pbi.PebBaseAddress, byref(peb), sizeof(peb), None), \
                report("Failed to read PEB", level=30)

            # Read process parameters
            upp = RTL_USER_PROCESS_PARAMETERS()
            assert ReadProcessMemory(hProcess, peb.ProcessParameters, byref(upp), sizeof(upp), None), \
                report("Failed to read process parameters", level=30)

            # Read command line
            commandLine = create_unicode_buffer(upp.CommandLine.Length // 2)
            assert ReadProcessMemory(hProcess, upp.CommandLine.Buffer, commandLine, upp.CommandLine.Length, None), \
                report("Failed to read command line", level=30)

            cmdline = wstring_at(addressof(commandLine), len(commandLine))
    except OSError:
        return ''
    return fstr(cmdline)


def kill_process_by_regex(regex):
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


def __get_time(fopen, fgettime, access, identification, select=0):
    with fopen(access, identification, False, False) as handle:
        Time = TIMEINFO()
        if not fgettime(
            handle,
            byref(Time.CreationTime),
            byref(Time.ExitTime),
            byref(Time.KernelTime),
            byref(Time.UserTime)
        ):
            return None
        return Time[select].to_int()

def _get_process_creation_time(pid):
    return __get_time(open_process, GetProcessTimes, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, pid, 0)

def _get_thread_creation_time(tid):
    return __get_time(open_thread, GetThreadTimes, THREAD_QUERY_INFORMATION, tid, 0)


def get_thread(pid):
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


def _get_process(pid):
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
    except OSError as e:
        logger.warning(f"Failed to get process and thread handles: {e}")
    finally:
        logger.info(f"Emulator Process: {pi}")
        return pi

def get_process(instance):
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


def switch_window(hwnds, arg=SW_SHOWNORMAL):
    count = 0
    for hwnd in hwnds:
        if not GetWindow(hwnd, GW_CHILD):
            continue
        count += 1
        ShowWindow(hwnd, arg)
    if not count:
        report(
            "All hwnds are unavailable, please check the running environment",
            reportstatus=False,
            raise_=False
        )
        return False
    return True

def get_parent_pid(pid):
    try:
        with open_process(PROCESS_QUERY_INFORMATION, pid) as hProcess:
            # Query process infomation
            pbi = PROCESS_BASIC_INFORMATION()
            returnlength = ULONG(sizeof(pbi))
            status = NtQueryInformationProcess(hProcess, 0, byref(pbi), returnlength, byref(returnlength))
            assert status == STATUS_SUCCESS, \
                report(f"NtQueryInformationProcess failed. Status: 0x{status:x}", level=30)
    except OSError:
        return -1
    return pbi.InheritedFromUniqueProcessId

def get_exit_code(pid):
    try:
        with open_process(PROCESS_QUERY_INFORMATION, pid) as hProcess:
            exit_code = ULONG()
            assert GetExitCodeProcess(hProcess, byref(exit_code)), \
                report("Failed to get Exit code", level=30)
    except OSError:
        return -1
    return exit_code.value

def is_running(pid=0, ppid=0):
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
