import re

from ctypes import byref, sizeof, cast, create_unicode_buffer, wstring_at, addressof
from ctypes.wintypes import SIZE

from module.device.platform.emulator_windows import Emulator, EmulatorInstance
from module.device.platform.winapi import *
from module.logger import logger


def __yieldloop(entry32, snapshot, func: callable):
    while 1:
        yield entry32
        if func(snapshot, byref(entry32)):
            continue
        # Finished querying
        errorcode = GetLastError()
        if errorcode != ERROR_NO_MORE_FILES:
            report(f"{func.__name__} failed.", statuscode=errorcode)
        report("Finished querying.", statuscode=errorcode, uselog=False, exception=IterationFinished)


def _enum_processes():
    """
    Enumerates all the processes currently running on the system.

    Yields:
        lppe32 (PROCESSENTRY32) |
        None (if enum failed)
    """
    lppe32          = PROCESSENTRY32()
    lppe32.dwSize   = sizeof(PROCESSENTRY32)
    with create_snapshot(TH32CS_SNAPPROCESS) as snapshot:
        if not Process32First(snapshot, byref(lppe32)):
            report("Process32First failed.")
        yield from __yieldloop(lppe32, snapshot, Process32Next)


def _enum_threads():
    """
    Enumerates all the threads currintly running on the system.

    Yields:
        lpte32 (THREADENTRY32) |
        None (if enum failed)
    """
    lpte32          = THREADENTRY32()
    lpte32.dwSize   = sizeof(THREADENTRY32)
    with create_snapshot(TH32CS_SNAPTHREAD) as snapshot:
        if not Thread32First(snapshot, byref(lpte32)):
            report("Thread32First failed.")
        yield from __yieldloop(lpte32, snapshot, Thread32Next)


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
        report("Failed to get windowplacement.", level=30, raiseexcept=False)
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


def execute(command: str, sstart: bool = False):
    """
    Create a new process.

    Args:
        command (str): process's commandline
        sstart (bool): process's windowplacement
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
    lpStartupInfo               = STARTUPINFOW()
    lpStartupInfo.cb            = sizeof(STARTUPINFOW)
    lpStartupInfo.dwFlags       = STARTF_USESHOWWINDOW
    lpStartupInfo.wShowWindow   = SW_HIDE if sstart else SW_MINIMIZE
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
        report("Failed to start emulator.", exception=EmulatorLaunchFailedError)
    
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
    with open_process(PROCESS_TERMINATE, pid) as hProcess:
        if TerminateProcess(hProcess, 0) == 0:
            report("Failed to kill process.")
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
        report("Hwnd not found.", exception=HwndNotFoundError)
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
    try:
        with open_process(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, pid) as hProcess:
            # Query process infomation
            pbi = PROCESS_BASIC_INFORMATION()
            returnlength = SIZE()
            status = NtQueryInformationProcess(hProcess, 0, byref(pbi), sizeof(pbi), byref(returnlength))
            if status != STATUS_SUCCESS:
                report(f"NtQueryInformationProcess failed. Status: 0x{status}.", level=30)

            # Read PEB
            peb = PEB()
            if not ReadProcessMemory(hProcess, pbi.PebBaseAddress, byref(peb), sizeof(peb), None):
                report("Failed to read PEB.", level=30)

            # Read process parameters
            upp = RTL_USER_PROCESS_PARAMETERS()
            uppAddress = cast(peb.ProcessParameters, POINTER(RTL_USER_PROCESS_PARAMETERS))
            if not ReadProcessMemory(hProcess, uppAddress, byref(upp), sizeof(upp), None):
                report("Failed to read process parameters.", level=30)

            # Read command line
            commandLine = create_unicode_buffer(upp.CommandLine.Length // 2)
            if not ReadProcessMemory(hProcess, upp.CommandLine.Buffer, commandLine, upp.CommandLine.Length, None):
                report("Failed to read command line.", level=30)

            cmdline = wstring_at(addressof(commandLine), len(commandLine))
    except OSError:
        return ''
    return cmdline


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
            pid     = lppe32.th32ProcessID
            cmdline = get_cmdline(lppe32.th32ProcessID)
            if not re.search(regex, cmdline):
                continue
            logger.info(f'Kill emulator: {cmdline}')
            terminate_process(pid)
            count += 1
    except IterationFinished:
        processes.close()
        return count


def _get_thread_creation_time(tid):
    """
    Get thread's creation time.

    Args:
        tid (int): Thread id

    Returns:
        threadstarttime (int): Thread's start time
    """
    with open_thread(THREAD_QUERY_INFORMATION, tid) as hThread:
        creationtime    = FILETIME()
        exittime        = FILETIME()
        kerneltime      = FILETIME()
        usertime        = FILETIME()
        if not GetThreadTimes(
            hThread,
            byref(creationtime),
            byref(exittime),
            byref(kerneltime),
            byref(usertime)
        ):
            return None
        return creationtime.to_int()

def get_thread(pid: int):
    """
    Get process's main thread id.

    Args:
        pid (int): Emulator's pid

    Returns
        mainthreadid (int): Emulator's main thread id
    """
    mainthreadid    = 0
    minstarttime    = MAXULONGLONG
    threads         = _enum_threads()
    try:
        for lpte32 in threads:
            if lpte32.th32OwnerProcessID != pid:
                continue

            threadstarttime = _get_thread_creation_time(lpte32.th32ThreadID)
            if threadstarttime is None or threadstarttime >= minstarttime:
                continue

            minstarttime = threadstarttime
            mainthreadid = lpte32.th32ThreadID
    except IterationFinished:
        threads.close()
        return mainthreadid


def _get_process(pid: int):
    """
    Get emulator's handle.

    Args:
        pid (int): Emulator's pid

    Returns:
        tuple(processhandle, threadhandle, processid, mainthreadid) |
        tuple(None, None, processid, mainthreadid) | (if enum_process() failed)
    """
    tid = get_thread(pid)
    try:
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not hProcess:
            report("OpenProcess failed.", level=30)

        hThread = OpenThread(THREAD_ALL_ACCESS, False, tid)
        if not hThread:
            CloseHandle(hProcess)
            report("OpenThread failed.", level=30)

        return hProcess, hThread, pid, tid
    except Exception as e:
        logger.warning(f"Failed to get process and thread handles: {e}")
        return None, None, pid, tid

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
