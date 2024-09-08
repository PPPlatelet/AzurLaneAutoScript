from module.device.env import IS_WINDOWS
if not IS_WINDOWS:
    raise OSError("Current environment isn't Windows")

import re
from typing import Generator, Iterable
from shlex import split as split_
from os.path import dirname

from ctypes import addressof, create_unicode_buffer, wstring_at

from module.device.platform.emulator_windows import Emulator
from module.device.platform.winapi import *
from module.base.timer import Timer
from module.logger import logger

class Winapi(WinapiFunctions):
    # TODO:Send MessageBox
    # TODO:Send Notify

    def close_handle(self, handles: Iterable[Any], *args, fclose=None):
        from itertools import chain

        if fclose is None:
            fclose = self.CloseHandle

        count = 0
        for handle in iter(chain(handles, args)):
            if not isinstance(handle, (int, c_void_p)):
                self.report(
                    f"Expected a int or c_void_p, but got {type(handle).__name__}",
                    report_status=False,
                    log_level=30,
                    raise_exc=False
                )
                continue
            fclose(handle)
            count += 1
            logger.info(f"Closed handle: {handle}")

        if not count:
            self.report(
            f"All handles are unavailable, please check the running environment",
            report_status=False,
            raise_exc=False,
        )
            return False

        return True

    def __yield_entries(self, entry32, snapshot, func):
        while 1:
            yield entry32
            if func(snapshot, byref(entry32)):
                continue
            # Finished querying
            errcode = self.GetLastError()
            assert errcode == self.ERROR_NO_MORE_FILES, self.report(f"{func.__name__} failed", status_code=errcode)
            self.report("Finished querying.", use_log=False, exc_type=IterationFinished)

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
            self.report("Failed to get windowplacement", log_level=30, raise_exc=False)
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
        focusedwindow               = self.get_focused_window()
        if start and silentstart:
            refresh_thread = threading.Thread(target=self.refresh_window, name='Refresh-Thread', args=(focusedwindow,))
            refresh_thread.start()

        lpApplicationName           = split_(command)[0]
        lpCommandLine               = command
        lpProcessAttributes         = None
        lpThreadAttributes          = None
        bInheritHandles             = False
        dwCreationFlags             = (
            self.CREATE_NEW_CONSOLE |
            self.NORMAL_PRIORITY_CLASS |
            self.CREATE_NEW_PROCESS_GROUP |
            self.CREATE_DEFAULT_ERROR_MODE |
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
        """
        TokenHandle = HANDLE()
        assert self.OpenProcessToken(
            self.GetCurrentProcess(),
            self.TOKEN_DUPLICATE | self.TOKEN_QUERY,
            byref(TokenHandle)
        ), self.report("Failed to open process token", exc_type=EmulatorLaunchFailedError)

        DuplicateTokenHandle = HANDLE()
        assert self.DuplicateTokenEx(
            TokenHandle,
            self.MAXIMUM_ALLOWED,
            None,
            self.SECURITY_IMPERSONATION,
            self.TOKEN_PRIMARY,
            byref(DuplicateTokenHandle)
        ), self.report("Failed to duplicate token", exc_type=EmulatorLaunchFailedError)
        """
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
        ),  self.report("Failed to start emulator", exc_type=EmulatorLaunchFailedError)

        if not start:
            self.close_handle(lpProcessInformation[:2])
            lpProcessInformation = None

        # self.close_handle((), TokenHandle, DuplicateTokenHandle)

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
            self.report("Hwnd not found", exc_type=HwndNotFoundError)
        return hwnds

    def get_cmdline(self, pid):
        try:
            with open_process(self.PROCESS_VM_READ | self.PROCESS_QUERY_INFORMATION, pid) as hProcess:
                # Query process infomation
                pbi = PROCESS_BASIC_INFORMATION()
                returnlength = ULONG(sizeof(pbi))
                status = self.NtQueryInformationProcess(hProcess, 0, byref(pbi), sizeof(pbi), byref(returnlength))
                assert status == self.STATUS_SUCCESS, \
                    self.report(f"NtQueryInformationProcess failed. Status: 0x{status:08x}", log_level=30)

                # Read PEB
                peb = PEB()
                assert self.ReadProcessMemory(hProcess, pbi.PebBaseAddress, byref(peb), sizeof(peb), None), \
                    self.report("Failed to read PEB", log_level=30)

                # Read process parameters
                upp = RTL_USER_PROCESS_PARAMETERS()
                assert self.ReadProcessMemory(hProcess, peb.ProcessParameters, byref(upp), sizeof(upp), None), \
                    self.report("Failed to read process parameters", log_level=30)

                # Read command line
                commandLine = create_unicode_buffer(upp.CommandLine.Length // 2)
                assert self.ReadProcessMemory(hProcess, upp.CommandLine.Buffer, commandLine, upp.CommandLine.Length, None), \
                    self.report("Failed to read command line", log_level=30)

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
                self.report("OpenProcess failed", log_level=30)

            hThread = self.OpenThread(self.THREAD_ALL_ACCESS, False, tid)
            if hThread is None:
                self.CloseHandle(hProcess)
                self.report("OpenThread failed", log_level=30)

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
                report_status=False,
                raise_exc=False
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
                    self.report(f"NtQueryInformationProcess failed. Status: 0x{status:x}", log_level=30)
        except OSError:
            return -1
        return pbi.InheritedFromUniqueProcessId

    def get_exit_code(self, pid):
        try:
            with open_process(self.PROCESS_QUERY_INFORMATION, pid) as hProcess:
                exit_code = ULONG()
                assert self.GetExitCodeProcess(hProcess, byref(exit_code)), \
                    self.report("Failed to get Exit code", log_level=30)
        except OSError:
            return -1
        return exit_code.value

    def is_running(self, pid=0, ppid=0):
        if pid and self.get_exit_code(pid) != self.STILL_ACTIVE:
            return False
        if ppid and ppid != self.get_parent_pid(pid):
            return False
        return True

    def is_user_admin(self):
        nt_authority    = (c_byte * 6)
        nt_authority[:] = 0,0,0,0,0,self.SECURITY_NT_AUTHORITY.value
        admins_group    = c_void_p()

        assert self.AllocateAndInitializeSid(
            byref(nt_authority),
            2,
            self.SECURITY_BUILTIN_DOMAIN_RID,
            self.DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            byref(admins_group)
        ), self.report("Failed to allocate and initialize SID")

        is_admin = BOOL()
        if not self.CheckTokenMembership(None, admins_group, byref(is_admin)):
            self.report("Failed to check token membership", log_level=30, raise_exc=False)
            return False

        self.FreeSid(admins_group)

        return is_admin.value == 1

    def set_privilege(self, hToken, lpszPrivilege, bEnablePrivilege):
        tp = TOKEN_PRIVILEGES()
        luid = LUID()

        if not self.LookupPrivilegeValueW(None, lpszPrivilege, byref(luid)):
            self.report("Failed to lookup privilege value", log_level=30, raise_exc=False)
            return

        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid

        tp.Privileges[0].Attributes = (self.SE_PRIVILEGE_ENABLED if bEnablePrivilege else 0)

        assert self.AdjustTokenPrivileges(hToken, False, byref(tp), sizeof(tp), None, None), \
            self.report("Failed to adjust token privileges")

    def create_process_with_token(
            self,
            hToken,
            dwLogonFlags            = 1,
            lpApplicationName       = None,
            lpCommandLine           = 'notepad.exe',
            dwCreationFlags         = 0,
            lpEnvironment           = None,
            lpCurrentDirectory      = None,
            lpStartupInfo           = STARTUPINFOW(),
            lpProcessInformation    = PROCESS_INFORMATION()
    ):
        assert self.CreateProcessWithTokenW(
            hToken,
            dwLogonFlags,
            lpApplicationName,
            lpCommandLine,
            dwCreationFlags,
            lpEnvironment,
            lpCurrentDirectory,
            byref(lpStartupInfo),
            byref(lpProcessInformation)
        ), self.report("Failed to create process with token", exc_type=EmulatorLaunchFailedError)
        return lpProcessInformation

    def create_process(self, **kwargs):
        lpStartupInfo           = kwargs.get('lpStartupInfo',           STARTUPINFOW())
        lpProcessInformation    = kwargs.get('lpProcessInformation',    PROCESS_INFORMATION())
        assert self.CreateProcessW(
            kwargs.get('lpApplicationName',     None),
            kwargs.get('lpCommandLine',         'notepad.exe'),
            kwargs.get('lpProcessAttributes',   None),
            kwargs.get('lpThreadAttributes',    None),
            kwargs.get('bInheritHandles',       False),
            kwargs.get('dwCreationFlags',       0),
            kwargs.get('lpEnvironment',         None),
            kwargs.get('lpCurrentDirectory',    None),
            byref(lpStartupInfo),
            byref(lpProcessInformation)
        ), self.report("Failed to create process", exc_type=EmulatorLaunchFailedError)
        return lpProcessInformation

if __name__ == '__main__':
    c = hex_or_normalize_path(r'"D:\Program Files\NetEase\MuMu Player 12\shell\MuMuPlayer.exe" -v 2')
    p, fw = Winapi('alas').execute(c, False, True)
    logger.info(p)
    logger.info(fw)
