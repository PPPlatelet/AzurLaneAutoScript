import re

import psutil
from ctypes import byref, sizeof, WinError, cast, create_unicode_buffer, wstring_at, addressof
from ctypes.wintypes import SIZE

from deploy.Windows.utils import DataProcessInfo
from module.device.platform.emulator_windows import Emulator, EmulatorInstance
from module.device.platform.api_windows.const_windows import *
from module.device.platform.api_windows.functions_windows import *
from module.device.platform.api_windows.structures_windows import *
from module.logger import logger

def get_focused_window():
    hwnd = GetForegroundWindow()
    if not hwnd:
        return None
    wp = WINDOWPLACEMENT()
    wp.length = sizeof(WINDOWPLACEMENT)
    if GetWindowPlacement(hwnd, byref(wp)):
        return hwnd, wp
    else:
        errorcode = GetLastError()
        logger.warning(f"GetWindowPlacement failed. GetLastError = {errorcode}")
        return hwnd, None

def set_foreground_window(focusedwindow: tuple = ()) -> bool:
    if not focusedwindow:
        return False
    SetForegroundWindow(focusedwindow[0])
    if focusedwindow[2] is None:
        ShowWindow(focusedwindow[0], SW_SHOWNORMAL)
    else:
        SetWindowPlacement(focusedwindow[0], focusedwindow[1])
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
    lpProcessInformation        = PROCESS_INFORMATION()

    focusedwindow               = get_focused_window()

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
        lpProcessInformation.hProcess,
        lpProcessInformation.hThread,
        lpProcessInformation.dwProcessId,
        lpProcessInformation.dwThreadId
    )
    return process, focusedwindow


def get_hwnds(pid: int) -> list:
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


def get_cmdline(pid: int) -> str:
    hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not hProcess:
        raise WinError(GetLastError())

    # Query process infomation
    pbi = PROCESS_BASIC_INFORMATION()
    returnlength = SIZE()
    status = NtQueryInformationProcess(
        hProcess,
        0,
        byref(pbi),
        sizeof(pbi),
        byref(returnlength)
    )
    if status != STATUS_SUCCESS:
        logger.warning(f"NtQueryInformationProcess failed. Status = 0x{status}")
        CloseHandle(hProcess)
        raise WinError(GetLastError())

    # Read PEB
    peb = PEB()
    if not ReadProcessMemory(hProcess, pbi.PebBaseAddress, byref(peb), sizeof(peb), None):
        errorcode = GetLastError()
        logger.warning(f"ReadProcessMemory failed. GetLastError = {errorcode}")
        CloseHandle(hProcess)
        raise WinError(errorcode)

    # Read process parameters
    upp = RTL_USER_PROCESS_PARAMETERS()
    uppAddress = cast(peb.ProcessParameters, POINTER(RTL_USER_PROCESS_PARAMETERS))
    if not ReadProcessMemory(hProcess, uppAddress, byref(upp), sizeof(upp), None):
        errorcode = GetLastError()
        logger.warning(f"ReadProcessMemory failed. GetLastError = {errorcode}")
        CloseHandle(hProcess)
        raise WinError(errorcode)

    # Read command line
    commandLine = create_unicode_buffer(upp.CommandLine.Length // 2)
    if not ReadProcessMemory(hProcess, upp.CommandLine.Buffer, commandLine, upp.CommandLine.Length, None):
        errorcode = GetLastError()
        logger.warning(f"ReadProcessMemory failed. GetLastError = {errorcode}")
        CloseHandle(hProcess)
        raise WinError(errorcode)

    cmdline = wstring_at(addressof(commandLine), len(commandLine))

    CloseHandle(hProcess)

    return cmdline


def enum_processes():
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
        pass
    finally:
        CloseHandle(snapshot)
        del lppe32, snapshot
        
def kill_process_by_regex(regex: str) -> int:
    count = 0

    try:
        for lppe32 in enum_processes():
            proc    = psutil.Process(lppe32.th32ProcessID)
            cmdline = DataProcessInfo(proc=proc, pid=proc.pid).cmdline
            if not re.search(regex, cmdline):
                continue
            logger.info(f'Kill emulator: {cmdline}')
            proc.kill()
            count += 1
    except ProcessLookupError:
        enum_processes().throw(GeneratorExit)
        return count

def _get_process(pid: int):
    proc = psutil.Process(pid)
    mainthreadid = proc.threads()[0].id
    try:
        processhandle = OpenProcess(PROCESS_ALL_ACCESS, False, proc.pid)
        if not processhandle:
            raise WinError(GetLastError())

        threadhandle = OpenThread(THREAD_ALL_ACCESS, False, mainthreadid)
        if not threadhandle:
            CloseHandle(processhandle)
            raise WinError(GetLastError())

        return processhandle, threadhandle, proc.pid, mainthreadid
    except Exception as e:
        logger.warning(f"Failed to get process and thread handles: {e}")
        return None, None, proc.pid, mainthreadid

def get_process(instance: EmulatorInstance):
    processes = enum_processes()
    for lppe32 in processes:
        pid = lppe32.th32ProcessID
        cmdline = getcmdline(pid)
        if not instance.path in cmdline:
            continue
        if instance == Emulator.MuMuPlayer12:
            match = re.search(r'\d+$', cmdline)
            if match and int(match.group()) == instance.MuMuPlayer12_id:
                processes.close()
                return _get_process(pid)
        elif instance == Emulator.LDPlayerFamily:
            match = re.search(r'\d+$', cmdline)
            if match and int(match.group()) == instance.LDPlayer_id:
                processes.close()
                return _get_process(pid)
        else:
            matchstr = re.search(fr'\b{instance.name}$', cmdline)
            if matchstr and matchstr.group() == instance.name:
                processes.close()
                return _get_process(pid)


def switch_window(hwnds: list, arg: int = 1):
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
