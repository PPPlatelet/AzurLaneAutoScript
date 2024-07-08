import re
import xml.etree.ElementTree as Et

from ctypes import byref, sizeof, create_unicode_buffer, wstring_at, addressof

from module.device.platform.emulator_windows import Emulator, EmulatorInstance
from module.device.platform.winapi import *
from module.logger import logger


def is_admin():
    try:
        return IsUserAnAdmin()
    except:
        return False


def __yieldloop(entry32, snapshot, func: callable):
    """
    Generates a loop that yields entries from a snapshot until the function fails or finishes.

    Args:
        entry32 (PROCESSENTRY32 or THREADENTRY32): Entry structure to be yielded, either for processes or threads.
        snapshot (int): Handle to the snapshot.
        func (callable): Next entry (e.g., Process32Next or Thread32Next).

    Yields:
        PROCESSENTRY32 or THREADENTRY32: The current entry in the snapshot.

    Raises:
        OSError if any winapi failed.
        IterationFinished if enumeration completed.
    """
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
        PROCESSENTRY32 or None: The current process entry or None if enumeration failed.

    Raises:
        OSError if CreateToolhelp32Snapshot or any winapi failed.
        IterationFinished if enumeration completed.
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
        THREADENTRY32 or None: The current thread entry or None if enumeration failed.

    Raises:
        OSError if CreateToolhelp32Snapshot or any winapi failed.
        IterationFinished if enumeration completed.
    """
    lpte32          = THREADENTRY32()
    lpte32.dwSize   = sizeof(THREADENTRY32)
    with create_snapshot(TH32CS_SNAPTHREAD) as snapshot:
        if not Thread32First(snapshot, byref(lpte32)):
            report("Thread32First failed.")
        yield from __yieldloop(lpte32, snapshot, Thread32Next)


def _enum_events(hevent):
    event = EVT_HANDLE()
    returned = DWORD(0)
    while EvtNext(hevent, 1, byref(event), INFINITE, 0, byref(returned)):
        if event == INVALID_HANDLE_VALUE:
            report(f"Invalid handle: 0x{event}", raiseexcept=False)
            continue

        buffer_size = DWORD(0)
        buffer_used = DWORD(0)
        property_count = DWORD(0)
        rendered_content = None

        EvtRender(
            None,
            event,
            EVT_RENDER_EVENT_XML,
            buffer_size,
            rendered_content,
            byref(buffer_used),
            byref(property_count)
        )
        if GetLastError() == ERROR_SUCCESS:
            yield rendered_content
            continue

        buffer_size = buffer_used.value
        rendered_content = create_unicode_buffer(buffer_size)
        if not rendered_content:
            report("malloc failed.", raiseexcept=False)
            continue

        if not EvtRender(
            None,
            event,
            EVT_RENDER_EVENT_XML,
            buffer_size,
            rendered_content,
            byref(buffer_used),
            byref(property_count)
        ):
            report(f"EvtRender failed with {GetLastError()}", raiseexcept=False)
            continue

        if GetLastError() == ERROR_SUCCESS:
            yield rendered_content.value

        EvtClose(event)


def getfocusedwindow():
    """
    Get focused window.

    Returns:
        hwnd (int): Focused window hwnd
        WINDOWPLACEMENT: The window placement or None if it couldn't be retrieved.
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


def flash_window(focusedwindow: tuple, max_attempts: int = 5, interval: int = 1):
    from time import sleep
    attempts = 0
    failed = 0

    while attempts < max_attempts:
        currentwindow = getfocusedwindow()
        if not (focusedwindow[0] and currentwindow[0]):
            failed += 1
            if failed >= max_attempts:
                report("Flash window failed.")
            sleep(interval)
            continue
        if focusedwindow[0] != currentwindow[0]:
            logger.info(f"Current window is {currentwindow[0]}, flash back to {focusedwindow[0]}")
            setforegroundwindow(focusedwindow)
            attempts += 1
            sleep(interval)
        else:
            attempts += 1
            sleep(interval)


def execute(command: str, silentstart: bool, start: bool):
    """
    Create a new process.

    Args:
        command (str): process's commandline
        silentstart (bool): process's windowplacement
        start (bool): True if start emulator, False if not
        Example:
            '"E:\\Program Files\\Netease\\MuMu Player 12\\shell\\MuMuPlayer.exe" -v 1'

    Returns:
        process: tuple(processhandle, threadhandle, processid, mainthreadid),
        focusedwindow: tuple(hwnd, WINDOWPLACEMENT)

    Raises:
        EmulatorLaunchFailedError if CreateProcessW failed.
    """
    from shlex import split
    from os.path import dirname
    import threading
    focusedwindow               = getfocusedwindow()
    if start:
        focus_thread = threading.Thread(target=flash_window, args=(focusedwindow, ))
        focus_thread.start()

    lpApplicationName           = split(command)[0]
    lpCommandLine               = command
    lpProcessAttributes         = None
    lpThreadAttributes          = None
    bInheritHandles             = False
    dwCreationFlags             = (
        CREATE_NO_WINDOW |
        IDLE_PRIORITY_CLASS |
        CREATE_NEW_PROCESS_GROUP |
        CREATE_DEFAULT_ERROR_MODE |
        CREATE_UNICODE_ENVIRONMENT
    )
    lpEnvironment               = None
    lpCurrentDirectory          = dirname(lpApplicationName)
    lpStartupInfo               = STARTUPINFOW()
    lpStartupInfo.cb            = sizeof(STARTUPINFOW)
    lpStartupInfo.dwFlags       = STARTF_USESHOWWINDOW
    if start:
        lpStartupInfo.wShowWindow   = SW_HIDE if silentstart else SW_MINIMIZE
    else:
        lpStartupInfo.wShowWindow   = SW_HIDE
    lpProcessInformation        = PROCESS_INFORMATION()

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

    Raises:
        OSError if OpenProcess failed.
    """
    with open_process(PROCESS_TERMINATE, pid) as hProcess:
        if TerminateProcess(hProcess, 0) == 0:
            report("Failed to kill process.")
    return True


def parse_event(event: str):
    ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
    tree = Et.ElementTree(Et.fromstring(event))
    time_created = tree.find('.//ns:TimeCreated', ns).attrib['SystemTime']
    new_process_id = tree.find('.//ns:Data[@Name="NewProcessId"]', ns).text
    new_process_name = tree.find('.//ns:Data[@Name="NewProcessName"]', ns).text
    process_id = tree.find('.//ns:Data[@Name="ProcessId"]', ns).text
    parent_process_name = tree.find('.//ns:Data[@Name="ParentProcessName"]', ns).text
    return {
        'TimeCreated': time_created,
        'NewProcessId': new_process_id,
        'NewProcessName': new_process_name,
        'ProcessId': process_id,
        'ParentProcessName': parent_process_name,
    }


def pids_manager(pid: int):
    try:
        if IsUserAnAdmin():
            pass
        else:
            return
    except:
        return
    with evt_query() as hevent:
        events = _enum_events(hevent)
        for content in events:
            logger.info(parse_event(content))


def get_hwnds(pid: int) -> list:
    """
    Get process's window hwnds from this processid.

    Args:
        pid (int): Emulator's pid

    Returns:
        hwnds (list): Emulator's possible window hwnds

    Raises:
        HwndNotFoundError if EnumWindows failed.
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
        cmdline (str): process's command line
        Example:
            '"E:\\Program Files\\Netease\\MuMu Player 12\\shell\\MuMuPlayer.exe" -v 1'
    """
    try:
        with open_process(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, pid) as hProcess:
            # Query process infomation
            pbi = PROCESS_BASIC_INFORMATION()
            returnlength = ULONG()
            status = NtQueryInformationProcess(hProcess, 0, byref(pbi), sizeof(pbi), byref(returnlength))
            if status != STATUS_SUCCESS:
                report(f"NtQueryInformationProcess failed. Status: 0x{status}.", level=30)

            # Read PEB
            peb = PEB()
            if not ReadProcessMemory(hProcess, pbi.PebBaseAddress, byref(peb), sizeof(peb), None):
                report("Failed to read PEB.", level=30)

            # Read process parameters
            upp = RTL_USER_PROCESS_PARAMETERS()
            if not ReadProcessMemory(hProcess, peb.ProcessParameters, byref(upp), sizeof(upp), None):
                report("Failed to read process parameters.", level=30)

            # Read command line
            commandLine = create_unicode_buffer(upp.CommandLine.Length // 2)
            if not ReadProcessMemory(hProcess, upp.CommandLine.Buffer, commandLine, upp.CommandLine.Length, None):
                report("Failed to read command line.", level=30)

            cmdline = wstring_at(addressof(commandLine), len(commandLine))
    except OSError:
        return ''
    return cmdline.replace(r"\\", "/").replace("\\", "/").replace('"', '"')


def kill_process_by_regex(regex: str) -> int:
    """
    Kill processes with cmdline match the given regex.

    Args:
        regex:

    Returns:
        int: Number of processes killed

    Raises:
        OSError if any winapi failed.
        IterationFinished if enumeration completed.
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


def _get_thread_creation_time(tid: int):
    """
    Get thread's creation time.

    Args:
        tid (int): Thread id

    Returns:
        threadstarttime (int): Thread's start time

    Raises:
        OSError if OpenThread failed.
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
        return to_int(creationtime)

def get_thread(pid: int):
    """
    Get process's main thread id.

    Args:
        pid (int): Emulator's pid

    Returns:
        mainthreadid (int): Emulator's main thread id

    Raises:
        OSError if any winapi failed.
        IterationFinished if enumeration completed.
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
        tuple(None, None, processid, mainthreadid)
    """
    tid = get_thread(pid)
    try:
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if hProcess is None:
            report("OpenProcess failed.", level=30)

        hThread = OpenThread(THREAD_ALL_ACCESS, False, tid)
        if hThread is None:
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

    Raises:
        OSError if any winapi failed.
        IterationFinished if enumeration completed.
    """
    processes = _enum_processes()
    for lppe32 in processes:
        pid = lppe32.th32ProcessID
        cmdline = get_cmdline(pid)
        if not instance.path in cmdline:
            continue
        if instance == Emulator.MuMuPlayer12:
            match = re.search(r'\d+$', cmdline)
            if not match:
                continue
            if int(match.group()) != instance.MuMuPlayer12_id:
                continue
            processes.close()
            return _get_process(pid)
        elif instance == Emulator.LDPlayerFamily:
            match = re.search(r'\d+$', cmdline)
            if not match:
                continue
            if int(match.group()) != instance.LDPlayer_id:
                continue
            processes.close()
            return _get_process(pid)
        else:
            matchstr = re.search(fr'\b{instance.name}$', cmdline)
            if not matchstr:
                continue
            if matchstr.group() != instance.name:
                continue
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

if __name__ == '__main__':
    p = 1234
    pids_manager(1234)
