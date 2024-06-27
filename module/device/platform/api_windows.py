import re

import psutil
from ctypes import byref, sizeof, cast, create_unicode_buffer, wstring_at, addressof
from ctypes.wintypes import SIZE

from module.device.platform.emulator_windows import Emulator, EmulatorInstance
from module.device.platform.winapi.const_windows import *
from module.device.platform.winapi.functions_windows import *
from module.device.platform.winapi.structures_windows import *
from module.logger import logger


def _error(errstr: str = '', handle: int = 0, exception: type = OSError, raiseexcept: bool = True):
    """
    Raise exception.

    Args:
        errstr (str): Error message
        handle (int): Handle to close
        exception (Type[Exception]): Exception class to raise
        raiseexcept (bool): Flag indicating whether to raise the exception
    """
    errorcode = GetLastError()
    logger.warning(f"{errstr}Errorcode: {errorcode}")
    if not handle:
        CloseHandle(handle)
    if raiseexcept:
        raise exception(errorcode)


def getfocusedwindow():
    """
    Get focused window.

    Returns:
        hwnd (int): Focused window hwnd
        WINDOWPLACEMENT:
    """
    hwnd = GetForegroundWindow()
    if not hwnd:
        return 0, None
    wp = WINDOWPLACEMENT()
    wp.length = sizeof(WINDOWPLACEMENT)
    if GetWindowPlacement(hwnd, byref(wp)):
        return hwnd, wp
    else:
        _error(errstr="Failed to get windowplacement. ", raiseexcept=False)
        return hwnd, None

def setforegroundwindow(focusedwindow: tuple = ()) -> bool:
    """
    Refocus foreground window.

    Args:
        focusedwindow: tuple(hwnd, WINDOWPLACEMENT) | tuple(hwnd, None)

    Returns:
        bool:
    """
    if not focusedwindow:
        return False
    SetForegroundWindow(focusedwindow[0])
    if focusedwindow[1] is None:
        ShowWindow(focusedwindow[0], SW_SHOWNORMAL)
    else:
        SetWindowPlacement(focusedwindow[0], focusedwindow[1])
    return True


def execute(command: str, arg: bool = False):
    """
    Create a new process.

    Args:
        command (str): process's commandline
        arg (bool): process's windowplacement
        Example:
            '"E:\\Program Files\\Netease\\MuMu Player 12\\shell\\MuMuPlayer.exe" -v 1'

    Returns:
        process: tuple(processhandle, threadhandle, processid, mainthreadid),
        focusedwindow: tuple(hwnd, WINDOWPLACEMENT)
    """
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
        _error(errstr="Failed to start emulator. ", exception=EmulatorLaunchFailedError)
    
    process = (
        lpProcessInformation.hProcess,
        lpProcessInformation.hThread,
        lpProcessInformation.dwProcessId,
        lpProcessInformation.dwThreadId
    )
    return process, focusedwindow


def terminate_process(pid: int):
    """
    Terminate emulator process.

    Args:
        pid (int): Emulator's pid
    """
    hProcess = OpenProcess(PROCESS_TERMINATE, False, pid)
    if TerminateProcess(hProcess, 0) == 0:
        _error("Failed to kill process. ", hProcess)
    CloseHandle(hProcess)
    return True


def get_hwnds(pid: int) -> list:
    """
    Get process's window hwnds from this processid.

    Args:
        pid (int): Emulator's pid

    Returns:
        hwnds (list): Emulator's possible window hwnds
    """
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
        logger.error("Hwnd not found!")
        logger.error("1.Perhaps emulator was killed.")
        logger.error("2.Environment has something wrong. Please check the running environment.")
        _error(errstr="Hwnd not found. ", exception=HwndNotFoundError)
    return hwnds


def get_cmdline(pid: int) -> str:
    """
    Get a process's command line from this processid.

    Args:
        pid (int): Emulator's pid

    Returns:
        command line (str): process's command line
        Example:
            '"E:\\Program Files\\Netease\\MuMu Player 12\\shell\\MuMuPlayer.exe" -v 1'
    """
    hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not hProcess:
        _error("OpenProcess failed. ")

    # Query process infomation
    pbi = PROCESS_BASIC_INFORMATION()
    returnlength = SIZE()
    status = NtQueryInformationProcess(hProcess, 0, byref(pbi), sizeof(pbi), byref(returnlength))
    if status != STATUS_SUCCESS:
        _error(f"NtQueryInformationProcess failed. Status: 0x{status}. ", hProcess)

    # Read PEB
    peb = PEB()
    if not ReadProcessMemory(hProcess, pbi.PebBaseAddress, byref(peb), sizeof(peb), None):
        _error("ReadProcessMemory failed. ", hProcess)

    # Read process parameters
    upp = RTL_USER_PROCESS_PARAMETERS()
    uppAddress = cast(peb.ProcessParameters, POINTER(RTL_USER_PROCESS_PARAMETERS))
    if not ReadProcessMemory(hProcess, uppAddress, byref(upp), sizeof(upp), None):
        _error("ReadProcessMemory failed. ", hProcess)

    # Read command line
    commandLine = create_unicode_buffer(upp.CommandLine.Length // 2)
    if not ReadProcessMemory(hProcess, upp.CommandLine.Buffer, commandLine, upp.CommandLine.Length, None):
        _error("ReadProcessMemory failed. ", hProcess)

    CloseHandle(hProcess)
    cmdline = wstring_at(addressof(commandLine), len(commandLine))

    return cmdline


def _enum_processes():
    """
    Enumerates all the processes currently running on the system.

    Yields:
        lppe32 (PROCESSENTRY32) |
        None (if enum failed)
    """
    lppe32          = PROCESSENTRY32()
    lppe32.dwSize   = sizeof(PROCESSENTRY32)
    snapshot        = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, DWORD(0))
    if snapshot == -1:
        _error()

    if not Process32First(snapshot, byref(lppe32)):
        _error("Process32First failed. ", snapshot)

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
                raise OSError(errorcode)
            raise ProcessLookupError(f"Finished querying. Errorcode: {errorcode}")
    except GeneratorExit:
        pass
    finally:
        CloseHandle(snapshot)
        del lppe32, snapshot
        
def kill_process_by_regex(regex: str) -> int:
    """
        Kill processes with cmdline match the given regex.

        Args:
            regex:

        Returns:
            int: Number of processes killed
    """
    count = 0

    processes = _enum_processes()
    try:
        for lppe32 in processes:
            pid = lppe32.th32ProcessID
            cmdline    = get_cmdline(lppe32.th32ProcessID)
            if not re.search(regex, cmdline):
                continue
            logger.info(f'Kill emulator: {cmdline}')
            terminate_process(pid)
            count += 1
    except ProcessLookupError:
        processes.close()
        return count

def _get_process(pid: int):
    """
    Get emulator's handle.

    Args:
        pid (int): Emulator's pid

    Returns:
        tuple(processhandle, threadhandle, processid, mainthreadid) |
        tuple(None, None, processid, mainthreadid) | (if enum_process() failed)
    """
    proc = psutil.Process(pid)
    mainthreadid = proc.threads()[0].id
    try:
        processhandle = OpenProcess(PROCESS_ALL_ACCESS, False, proc.pid)
        if not processhandle:
            _error("OpenProcess failed. ", processhandle)

        threadhandle = OpenThread(THREAD_ALL_ACCESS, False, mainthreadid)
        if not threadhandle:
            _error("OpenThread failed. ", threadhandle)

        return processhandle, threadhandle, proc.pid, mainthreadid
    except Exception as e:
        logger.warning(f"Failed to get process and thread handles: {e}")
        return None, None, proc.pid, mainthreadid

def get_process(instance: EmulatorInstance):
    """
    Get emulator's process.

    Args:
        instance (EmulatorInstance):

    Returns:
        tuple(processhandle, threadhandle, processid, mainthreadid) |
        tuple(None, None, processid, mainthreadid) | (if enum_process() failed)
        None (if enum_process() failed)
    """
    processes = _enum_processes()
    for lppe32 in processes:
        pid = lppe32.th32ProcessID
        cmdline = get_cmdline(pid)
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


def switch_window(hwnds: list, arg: int = SW_SHOWNORMAL):
    """
    Switch emulator's windowplacement to the given arg

    Args:
        hwnds (list): Possible emulator's window hwnds
        arg (int): Emulator's windowplacement

    Returns:
        bool:
    """
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
