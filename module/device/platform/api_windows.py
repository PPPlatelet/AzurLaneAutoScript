from module.device.env import IS_WINDOWS
if not IS_WINDOWS:
    raise OSError("Current environment isn't Windows")

import re
from typing import Generator

from ctypes import addressof, create_unicode_buffer, wstring_at

from module.device.platform.emulator_windows import Emulator, EmulatorManager
from module.device.platform.platform_base import PlatformBase
from module.device.platform.winapi import *
from module.base.timer import Timer
from module.logger import logger

class Winapi(PlatformBase, WinapiFunctions, EmulatorManager):
    process = None

    def __new__(cls, *args, **kwargs):
        instance = super(WinapiConstants, cls).__new__(cls)
        return instance

    def close_handle(self, *args, fclose=None):
        if fclose is None:
            fclose = self.CloseHandle
        count = 0
        for handle in args:
            if isinstance(handle, int):
                handle = HANDLE(handle)
            if isinstance(handle, c_void_p):
                fclose(handle)
                count += 1
                logger.info(f"Closed handle: {handle}")
                continue
            self.report(
                f"Expected a int or c_void_p, but got {type(handle).__name__}",
                reportstatus=False,
                level=30,
                raise_=False,
            )
        if not count:
            self.report(
                f"All handles are unavailable, please check the running environment",
                reportstatus=False,
                raise_=False
            )
            return False
        return True

    def __yield_entries(self, entry32, snapshot, func):
        while 1:
            yield entry32
            if func(snapshot, byref(entry32)):
                continue
            # Finished querying
            errorcode = self.GetLastError()
            assert errorcode == self.ERROR_NO_MORE_FILES, self.report(f"{func.__name__} failed", statuscode=errorcode)
            self.report("Finished querying.", statuscode=errorcode, uselog=False, exception=IterationFinished)

    def _enum_processes(self) -> Generator[PROCESSENTRY32W, None, None]:
        lppe32 = PROCESSENTRY32W(sizeof(PROCESSENTRY32W))
        with create_snapshot(self.TH32CS_SNAPPROCESS) as snapshot:
            assert self.Process32First(snapshot, byref(lppe32)), self.report("Process32First failed")
            yield from self.__yield_entries(lppe32, snapshot, self.Process32Next)

    def _enum_threads(self) -> Generator[THREADENTRY32, None, None]:
        lpte32 = THREADENTRY32(sizeof(THREADENTRY32))
        with create_snapshot(self.TH32CS_SNAPTHREAD) as snapshot:
            assert self.Thread32First(snapshot, byref(lpte32)), self.report("Thread32First failed")
            yield from self.__yield_entries(lpte32, snapshot, self.Thread32Next)

    def get_focused_window(self):
        hwnd = HWND(self.GetForegroundWindow())
        wp = WINDOWPLACEMENT(sizeof(WINDOWPLACEMENT))
        if not self.GetWindowPlacement(hwnd, byref(wp)):
            self.report("Failed to get windowplacement", level=30, raise_=False)
            wp = None
        return hwnd, wp

    def set_focus_to_window(self, focusedwindow):
        self.SetForegroundWindow(focusedwindow[0])
        if focusedwindow[1] is None:
            self.ShowWindow(focusedwindow[0], self.SW_SHOWNORMAL)
        else:
            self.ShowWindow(focusedwindow[0], focusedwindow[1].showCmd)
            self.SetWindowPlacement(focusedwindow[0], focusedwindow[1])
        return True

    def refresh_window(self, focusedwindow, max_attempts=10, interval=0.5):
        from itertools import combinations

        attempts = 0
        prevwindow = None

        unique = lambda *args: all(x[0].value != y[0].value for x, y in combinations(args, 2))
        interval = Timer(interval).start()

        while attempts < max_attempts:
            currentwindow = self.get_focused_window()
            if prevwindow and unique(currentwindow, prevwindow, focusedwindow):
                break

            if unique(focusedwindow, currentwindow):
                logger.info(f"Current window is {currentwindow[0]}, flash back to {focusedwindow[0]}")
                self.set_focus_to_window(focusedwindow)
                attempts += 1
                interval.wait()
                interval.reset()

            attempts += 1
            interval.wait()
            interval.reset()

            prevwindow = currentwindow

    def execute(self, command, silentstart, start):
        # TODO:Create Process with non-administrator privileges
        from shlex import split
        from os.path import dirname
        focusedwindow               = self.get_focused_window()
        if start:
            refresh_thread = threading.Thread(target=self.refresh_window, name='Refresh-Thread', args=(focusedwindow,))
            refresh_thread.start()

        """
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
        """

        # dwLogonFlags = DWORD(0)
        lpApplicationName           = split(command)[0]
        lpCommandLine               = command
        lpProcessAttributes         = None
        lpThreadAttributes          = None
        bInheritHandles             = False
        dwCreationFlags             = (
            self.DETACHED_PROCESS |
            self.CREATE_UNICODE_ENVIRONMENT
        )
        lpEnvironment               = None
        lpCurrentDirectory          = dirname(lpApplicationName)
        lpStartupInfo               = STARTUPINFOW(
            cb                      = sizeof(STARTUPINFOW),
            dwFlags                 = self.STARTF_USESHOWWINDOW,
            wShowWindow             = self.SW_FORCEMINIMIZE if silentstart else self.SW_MINIMIZE
        )
        lpProcessInformation        = PROCESS_INFORMATION()

        assert self.CreateProcessW(
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
        ),  self.report("Failed to start emulator", exception=EmulatorLaunchFailedError)

        if not start:
            self.close_handle(*lpProcessInformation[:2])
            lpProcessInformation = None

        return lpProcessInformation, focusedwindow

    def terminate_process(self, pid):
        with open_process(self.PROCESS_TERMINATE, pid) as hProcess:
            assert self.TerminateProcess(hProcess, 0), self.report("Failed to kill process")
        return True

    def get_hwnds(self, pid):
        hwnds = []

        @self.EnumWindowsProc
        def callback(hwnd: HWND, lparam: LPARAM):  # DO NOT DELETE THIS PARAMETER!!!
            processid = DWORD()
            self.GetWindowThreadProcessId(hwnd, byref(processid))
            if processid.value == pid:
                hwnds.append(HWND(hwnd))
            return True

        assert self.EnumWindows(callback, LPARAM(0)), self.report("Failed to get hwnds")

        if not hwnds:
            logger.error("Hwnd not found!")
            logger.error("1.Perhaps emulator has been killed.")
            logger.error("2.Environment has something wrong. Please check the running environment.")
            self.report("Hwnd not found", exception=HwndNotFoundError)
        return hwnds

    def get_cmdline(self, pid):
        try:
            with open_process(self.PROCESS_VM_READ | self.PROCESS_QUERY_INFORMATION, pid) as hProcess:
                # Query process infomation
                pbi = PROCESS_BASIC_INFORMATION()
                returnlength = ULONG(sizeof(pbi))
                status = self.NtQueryInformationProcess(hProcess, 0, byref(pbi), sizeof(pbi), byref(returnlength))
                assert status == self.STATUS_SUCCESS, \
                    self.report(f"NtQueryInformationProcess failed. Status: 0x{status:08x}", level=30)

                # Read PEB
                peb = PEB()
                assert self.ReadProcessMemory(hProcess, pbi.PebBaseAddress, byref(peb), sizeof(peb), None), \
                    self.report("Failed to read PEB", level=30)

                # Read process parameters
                upp = RTL_USER_PROCESS_PARAMETERS()
                assert self.ReadProcessMemory(hProcess, peb.ProcessParameters, byref(upp), sizeof(upp), None), \
                    self.report("Failed to read process parameters", level=30)

                # Read command line
                commandLine = create_unicode_buffer(upp.CommandLine.Length // 2)
                assert self.ReadProcessMemory(hProcess, upp.CommandLine.Buffer, commandLine, upp.CommandLine.Length, None), \
                    self.report("Failed to read command line", level=30)

                cmdline = wstring_at(addressof(commandLine), len(commandLine))
        except OSError:
            return ''
        return hex_or_normalize_path(cmdline)

    def kill_process_by_regex(self, regex):
        count = 0

        try:
            for lppe32 in self._enum_processes():
                pid     = lppe32.th32ProcessID
                cmdline = self.get_cmdline(lppe32.th32ProcessID)
                if not re.search(regex, cmdline):
                    continue
                logger.info(f'Kill emulator: {cmdline}')
                self.terminate_process(pid)
                count += 1
        except IterationFinished:
            return count

    @staticmethod
    def __get_time(fopen, fgettime, access, identification, select=0):
        with fopen(access, identification, False, False) as handle:
            ti = TIMEINFO()
            if not fgettime(
                handle,
                byref(ti.CreationTime),
                byref(ti.ExitTime),
                byref(ti.KernelTime),
                byref(ti.UserTime)
            ):
                return None
            return ti[select].to_int()

    def _get_process_creation_time(self, pid):
        return self.__get_time(
            open_process,
            self.GetProcessTimes,
            self.PROCESS_QUERY_INFORMATION |
            self.PROCESS_VM_READ,
            pid,
            0
        )

    def _get_thread_creation_time(self, tid):
        return self.__get_time(
            open_thread,
            self.GetThreadTimes,
            self.THREAD_QUERY_INFORMATION,
            tid,
            0
        )

    def get_thread(self, pid):
        mainthreadid    = 0
        minstarttime    = self.MAXULONGLONG
        try:
            for lpte32 in self._enum_threads():
                if lpte32.th32OwnerProcessID != pid:
                    continue

                # In general, the first tid obtained by traversing is always the main tid, so these code can be commented.
                threadstarttime = self._get_thread_creation_time(lpte32.th32ThreadID)
                if threadstarttime is None or threadstarttime >= minstarttime:
                    continue

                minstarttime = threadstarttime
                mainthreadid = lpte32.th32ThreadID
        except IterationFinished:
            return mainthreadid

    def _get_process(self, pid):
        tid = self.get_thread(pid)
        pi = PROCESS_INFORMATION(None, None, pid, tid)
        try:
            hProcess = self.OpenProcess(self.PROCESS_ALL_ACCESS, False, pid)
            assert hProcess is not None, \
                self.report("OpenProcess failed", level=30)

            hThread = self.OpenThread(self.THREAD_ALL_ACCESS, False, tid)
            if hThread is None:
                self.CloseHandle(hProcess)
                self.report("OpenThread failed", level=30)

            pi.hProcess, pi.hThread = hProcess, hThread
        except OSError as e:
            logger.warning(f"Failed to get process and thread handles: {e}")
        finally:
            logger.info(f"Emulator Process: {pi}")
            return pi

    def get_process(self, instance):
        for lppe32 in self._enum_processes():
            pid = lppe32.th32ProcessID
            cmdline = self.get_cmdline(pid)
            if not cmdline:
                continue
            if not instance.path.lower() in cmdline.lower():
                continue
            if instance == Emulator.MuMuPlayer12:
                match = re.search(r'-v\s*(\d+)', cmdline)
                if match is None:
                    return self._get_process(pid)
                if match and int(match.group(1)) == instance.MuMuPlayer12_id:
                    return self._get_process(pid)
            elif instance == Emulator.LDPlayerFamily:
                match = re.search(r'index=\s*(\d+)', cmdline)
                if match and int(match.group(1)) == instance.LDPlayer_id:
                    return self._get_process(pid)
            else:
                match = re.search(fr'{instance.name}(\s+|$)', cmdline)
                if match and match.group(0).strip() == instance.name:
                    return self._get_process(pid)

    def switch_window(self, hwnds, arg=None):
        if arg is None:
            arg = self.SW_SHOWNORMAL
        count = 0
        for hwnd in hwnds:
            if not self.GetWindow(hwnd, self.GW_CHILD):
                continue
            count += 1
            self.ShowWindow(hwnd, arg)
        if not count:
            self.report(
                "All hwnds are unavailable, please check the running environment",
                reportstatus=False,
                raise_=False
            )
            return False
        return True

    def get_parent_pid(self, pid):
        try:
            with open_process(self.PROCESS_QUERY_INFORMATION, pid) as hProcess:
                # Query process infomation
                pbi = PROCESS_BASIC_INFORMATION()
                returnlength = ULONG(sizeof(pbi))
                status = self.NtQueryInformationProcess(hProcess, 0, byref(pbi), returnlength, byref(returnlength))
                assert status == self.STATUS_SUCCESS, \
                    self.report(f"NtQueryInformationProcess failed. Status: 0x{status:x}", level=30)
        except OSError:
            return -1
        return pbi.InheritedFromUniqueProcessId

    def get_exit_code(self, pid):
        try:
            with open_process(self.PROCESS_QUERY_INFORMATION, pid) as hProcess:
                exit_code = ULONG()
                assert self.GetExitCodeProcess(hProcess, byref(exit_code)), \
                    self.report("Failed to get Exit code", level=30)
        except OSError:
            return -1
        return exit_code.value

    def is_running(self, pid=0, ppid=0):
        if pid and self.get_exit_code(pid) != self.STILL_ACTIVE:
            return False
        if ppid and ppid != self.get_parent_pid(pid):
            return False
        return True

    def emulator_check(self) -> bool:
        try:
            if not isinstance(self.process, PROCESS_INFORMATION):
                self.process = self.get_process(self.emulator_instance)
                return True
            cmdline = self.get_cmdline(self.process[2])
            if self.emulator_instance.path.lower() in cmdline.lower():
                return True
            if not all(handle is not None for handle in self.process[:2]):
                self.close_handle(*self.process[:2])
                self.process = None
            raise ProcessLookupError
        except (IterationFinished, IndexError):
            return False
        except ProcessLookupError:
            return self.emulator_check
        except OSError as e:
            logger.error(e)
            raise e
        except Exception as e:
            logger.exception(e)
            raise e

if __name__ == '__main__':
    c = hex_or_normalize_path('"E:\\Program Files\\Netease\\MuMu Player 12\\shell\\MuMuPlayer.exe" -v 2')
    p, fw = Winapi().execute(c, False, True)
    logger.info(p)
    logger.info(fw)
