from typing import Callable

from module.base.decorator import run_once
from module.base.timer import Timer
from module.device.connection import AdbDeviceWithStatus
from module.device.platform.platform_base import PlatformBase
from module.device.platform.emulator_windows import Emulator, EmulatorInstance
from module.device.platform.api_windows import Winapi
from module.device.platform.winapi.functions_windows import hex_or_normalize_path
from module.device.platform.winapi.structures_windows import \
    EmulatorLaunchFailedError, PROCESS_INFORMATION
from module.logger import logger

class EmulatorUnknown(Exception):
    pass


class PlatformWindows(Winapi, PlatformBase):
    # Quadruple, contains the kernel process object, kernel thread object, process ID and thread ID.
    # If the kernel process object and kernel thread object are no longer used, PLEASE USE CloseHandle.
    # Otherwise, it'll crash the system in some cases.
    process: PROCESS_INFORMATION = None
    # Window handles of the target process.
    hwnds: list = []
    # Pair, contains the hwnd of the focused window and a WINDOWPLACEMENT object.
    focusedwindow: tuple = ()

    def __execute(self, command: str, start: bool) -> bool:
        command = hex_or_normalize_path(command)
        logger.info(f'Execute: {command}')

        silentstart = False if self.config.Emulator_SilentStart == 'normal' else True

        if self.process is not None and not all(handle is not None for handle in self.process[:2]):
            self.close_handle(*self.process[:2])
            self.process = None

        self.hwnds = []

        self.process, self.focusedwindow = self.execute(command, silentstart, start)
        return True

    def _start(self, command: str) -> bool:
        return self.__execute(command, start=True)

    def _stop(self, command: str) -> bool:
        return self.__execute(command, start=False)

    def switch_window(self, hwnds=None, arg=None) -> bool:
        if not self.process:
            self.process = self.get_process(self.emulator_instance)
        if not self.hwnds:
            self.hwnds = self.get_hwnds(self.process[2])
        if hwnds is None:
            hwnds = self.hwnds
        method = self.config.Emulator_SilentStart
        if method == 'normal' and arg is None:
            arg = self.SW_SHOW
        elif method == 'minimize' and arg is None:
            arg = self.SW_MINIMIZE
        elif method == 'silent' and arg is None:
            arg = self.SW_HIDE
        else:
            from module.exception import ScriptError
            raise ScriptError("Wrong setting")
        return super().switch_window(hwnds, arg)

    def _emulator_start(self, instance: EmulatorInstance):
        """
        Start an emulator without error handling
        """
        exe: str = instance.emulator.path
        if instance == Emulator.MuMuPlayer:
            # NemuPlayer.exe
            self._start(exe)
        elif instance == Emulator.MuMuPlayerX:
            # NemuPlayer.exe -m nemu-12.0-x64-default
            self._start(f'"{exe}" -m {instance.name}')
        elif instance == Emulator.MuMuPlayer12:
            # MuMuPlayer.exe -v 0
            if instance.MuMuPlayer12_id is None:
                logger.warning(f'Cannot get MuMu instance index from name {instance.name}')
            self._start(f'"{exe}" -v {instance.MuMuPlayer12_id}')
        elif instance == Emulator.LDPlayerFamily:
            # ldconsole.exe launch --index 0
            self._start(f'"{Emulator.single_to_console(exe)}" launch --index {instance.LDPlayer_id}')
        elif instance == Emulator.NoxPlayerFamily:
            # Nox.exe -clone:Nox_1
            self._start(f'"{exe}" -clone:{instance.name}')
        elif instance == Emulator.BlueStacks5:
            # HD-Player.exe --instance Pie64
            self._start(f'"{exe}" --instance {instance.name}')
        elif instance == Emulator.BlueStacks4:
            # Bluestacks.exe -vmname Android_1
            self._start(f'"{exe}" -vmname {instance.name}')
        elif instance == Emulator.MEmuPlayer:
            # MEmu.exe MEmu_0
            self._start(f'"{exe}" {instance.name}')
        else:
            raise EmulatorUnknown(f'Cannot start an unknown emulator instance: {instance}')

    def _emulator_stop(self, instance: EmulatorInstance):
        """
        Stop an emulator without error handling
        """
        exe: str = instance.emulator.path
        if instance == Emulator.MuMuPlayer:
            # MuMu6 does not have multi instance, kill one means kill all
            # Has 4 processes
            # "C:\Program Files\NemuVbox\Hypervisor\NemuHeadless.exe" --comment nemu-6.0-x64-default --startvm
            # "E:\ProgramFiles\MuMu\emulator\nemu\EmulatorShell\NemuPlayer.exe"
            # E:\ProgramFiles\MuMu\emulator\nemu\EmulatorShell\NemuService.exe
            # "C:\Program Files\NemuVbox\Hypervisor\NemuSVC.exe" -Embedding
            self.kill_process_by_regex(
                rf'('
                rf'NemuHeadless.exe'
                rf'|NemuPlayer.exe\"'
                rf'|NemuPlayer.exe$'
                rf'|NemuService.exe'
                rf'|NemuSVC.exe'
                rf')'
            )
        elif instance == Emulator.MuMuPlayerX:
            # MuMu X has 3 processes
            # "E:\ProgramFiles\MuMu9\emulator\nemu9\EmulatorShell\NemuPlayer.exe" -m nemu-12.0-x64-default -s 0 -l
            # "C:\Program Files\Muvm6Vbox\Hypervisor\Muvm6Headless.exe" --comment nemu-12.0-x64-default --startvm xxx
            # "C:\Program Files\Muvm6Vbox\Hypervisor\Muvm6SVC.exe" --Embedding
            self.kill_process_by_regex(
                rf'('
                rf'NemuPlayer.exe.*-m {instance.name}'
                rf'|Muvm6Headless.exe'
                rf'|Muvm6SVC.exe'
                rf')'
            )
        elif instance == Emulator.MuMuPlayer12:
            # MuMuManager.exe control -v 1 shutdown
            if instance.MuMuPlayer12_id is None:
                logger.warning(f'Cannot get MuMu instance index from name {instance.name}')
            self._stop(f'"{Emulator.single_to_console(exe)}" control -v {instance.MuMuPlayer12_id} shutdown')
        elif instance == Emulator.LDPlayerFamily:
            # ldconsole.exe quit --index 0
            self._stop(f'"{Emulator.single_to_console(exe)}" quit --index {instance.LDPlayer_id}')
        elif instance == Emulator.NoxPlayerFamily:
            # Nox.exe -clone:Nox_1 -quit
            self._stop(f'"{exe}" -clone:{instance.name} -quit')
        elif instance == Emulator.BlueStacks5:
            # BlueStack has 2 processes
            # C:\Program Files\BlueStacks_nxt_cn\HD-Player.exe --instance Pie64
            # C:\Program Files\BlueStacks_nxt_cn\BstkSVC.exe -Embedding
            self.kill_process_by_regex(
                rf'('
                rf'HD-Player.exe.*"--instance" "{instance.name}"'
                rf')'
            )
        elif instance == Emulator.BlueStacks4:
            # bsconsole.exe quit --name Android
            self._stop(f'"{Emulator.single_to_console(exe)}" quit --name {instance.name}')
        elif instance == Emulator.MEmuPlayer:
            # memuc.exe stop -n MEmu_0
            self._stop(f'"{Emulator.single_to_console(exe)}" stop -n {instance.name}')
        else:
            raise EmulatorUnknown(f'Cannot stop an unknown emulator instance: {instance}')

    def _emulator_function_wrapper(self, func: Callable):
        """
        Args:
            func (callable): _emulator_start or _emulator_stop

        Returns:
            bool: If success
        """
        try:
            func(self.emulator_instance)
            return True
        except OSError as e:
            msg = str(e)
            # OSError: [WinError 740] 请求的操作需要提升。
            if 'WinError 740' in msg:
                logger.error('To start/stop MumuAppPlayer, ALAS needs to be run as administrator')
        except EmulatorUnknown as e:
            logger.error(e)
        except EmulatorLaunchFailedError as e:
            logger.exception(e)
        except Exception as e:
            logger.exception(e)

        logger.error(f'Emulator function {func.__name__}() failed')
        return False

    def emulator_start_watch(self):
        """
        Returns:
            bool: True if startup completed
                False if timeout
        """
        logger.info("Emulator starting...")
        logger.info(f"Current window: {self.focusedwindow[0]}")
        serial = self.emulator_instance.serial

        def adb_connect():
            m = self.adb_client.connect(self.serial)
            if 'connected' in m:
                # Connected to 127.0.0.1:59865
                # Already connected to 127.0.0.1:59865
                return False
            elif '(10061)' in m:
                # cannot connect to 127.0.0.1:55555:
                # No connection could be made because the target machine actively refused it. (10061)
                return False
            else:
                return True

        @run_once
        def show_online(m):
            logger.info(f'Emulator online: {m}')

        @run_once
        def show_ping(m):
            logger.info(f'Command ping: {m}')

        @run_once
        def show_package(m):
            logger.info(f'Found azurlane packages: {m}')

        interval = Timer(0.5).start()
        timeout = Timer(180).start()
        while 1:
            interval.wait()
            interval.reset()
            if timeout.reached():
                logger.warning(f'Emulator start timeout')
                return False

            # Check device connection
            devices = self.list_device().select(serial=serial)
            # logger.info(devices)
            if devices:
                device: AdbDeviceWithStatus = devices.first_or_none()
                if device.status == 'device':
                    # Emulator online
                    pass
                if device.status == 'offline':
                    self.adb_client.disconnect(serial)
                    adb_connect()
                    continue
            else:
                # Try to connect
                adb_connect()
                continue
            show_online(devices.first_or_none())

            # Check command availability
            try:
                pong = self.adb_shell(['echo', 'pong'])
            except Exception as e:
                logger.info(e)
                continue
            show_ping(pong)

            # Check azuelane package
            packages = self.list_known_packages(show_log=False)
            if not len(packages):
                continue
            show_package(packages)

            # All check passed
            break

        # Check emulator process and hwnds
        self.hwnds = self.get_hwnds(self.process[2])

        logger.info(f'Emulator start completed')
        logger.info(f'Emulator Process: {self.process}')
        logger.info(f'Emulator hwnds: {self.hwnds}')
        return True

    def emulator_start(self):
        logger.hr('Emulator start', level=1)
        for _ in range(3):
            # Start
            if self._emulator_function_wrapper(self._emulator_start):
                # Success
                self.emulator_start_watch()
                return True
            # Failed to start, stop and start again
            if self._emulator_function_wrapper(self._emulator_stop):
                continue
            return False

        logger.error('Failed to start emulator 3 times, stopped')
        return False

    def emulator_stop(self):
        logger.hr('Emulator stop', level=1)
        for _ in range(3):
            # Stop
            if self._emulator_function_wrapper(self._emulator_stop):
                # Success
                return True
            # Failed to stop, start and stop again
            if self._emulator_function_wrapper(self._emulator_start):
                continue
            return False

        logger.error('Failed to stop emulator 3 times, stopped')
        return False

if __name__ == '__main__':
    self = PlatformWindows('alas')
    d = self.emulator_instance
    print(d)
