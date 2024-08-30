from datetime import datetime
import re
from queue import Queue
import asyncio
import threading

from ctypes import WinDLL, POINTER, byref, create_unicode_buffer
from ctypes.wintypes import HANDLE, LPCWSTR, DWORD, BOOL, LPVOID

from module.device.platform.winapi.functions_windows import Handle_, fstr, GetLastError, report, IsUserAnAdmin
from module.device.platform.winapi.const_windows import INFINITE, INVALID_HANDLE_VALUE, ERROR_SUCCESS
from module.device.platform.api_windows import is_running, get_cmdline, terminate_process
from module.logger import logger

# winevt.h line 156
EVT_QUERY_CHANNEL_PATH          = 0x1
EVT_QUERY_FILE_PATH             = 0x2
EVT_QUERY_FORWARD_DIRECTION     = 0x100
EVT_QUERY_REVERSE_DIRECTION     = 0x200
EVT_QUERY_TOLERATE_QUERY_ERRORS = 0x1000
# line 176
EVT_RENDER_EVENT_VALUES = 0
EVT_RENDER_EVENT_XML    = 1
EVT_RENDER_BOOK_MARK    = 2

wevtapi     = WinDLL(name='wevtapi',    use_last_error=True)

EVT_HANDLE                          = HANDLE
EvtQuery                            = wevtapi.EvtQuery
EvtQuery.argtypes                   = [EVT_HANDLE, LPCWSTR, LPCWSTR, DWORD]
EvtQuery.restype                    = HANDLE

EvtNext                             = wevtapi.EvtNext
EvtNext.argtypes                    = [EVT_HANDLE, DWORD, POINTER(EVT_HANDLE), DWORD, DWORD, POINTER(DWORD)]
EvtNext.restype                     = BOOL

EvtRender                           = wevtapi.EvtRender
EvtRender.argtypes                  = [EVT_HANDLE, EVT_HANDLE, DWORD, DWORD, LPVOID, POINTER(DWORD), POINTER(DWORD)]
EvtRender.restype                   = BOOL

EvtClose                            = wevtapi.EvtClose
EvtClose.argtypes                   = [EVT_HANDLE]
EvtClose.restype                    = BOOL

class QueryEvt(Handle_):
    _func       = EvtQuery
    _exitfunc   = EvtClose

    def __enter__(self) -> EVT_HANDLE:
        return self._handle

    @staticmethod
    def __get_init_args__():
        query = "Event/System[EventID=4688]"
        return None, "Security", query, EVT_QUERY_REVERSE_DIRECTION | EVT_QUERY_CHANNEL_PATH

class EvtData:
    def __init__(self, data: dict, dtime: datetime):
        self.system_time: datetime  = dtime
        self.new_process_id: int    = data.get("NewProcessId", 0)
        self.new_process_name: str  = data.get("NewProcessName", '')
        self.process_id: int        = data.get("ProcessId", 0)
        self.process_name: str      = data.get("ParentProcessName", '')

    def __eq__(self, other):
        if isinstance(other, EvtData):
            return self.new_process_id == other.process_id
        return NotImplemented

    def __str__(self):
        attrs = ', '.join(f"{key}={value}" for key, value in self.__dict__.items())
        return f"{self.__class__.__name__}({attrs})"

    def __repr__(self):
        attrs = ', '.join(f"{key}={value!r}" for key, value in self.__dict__.items())
        return f"{self.__class__.__name__}({attrs})"

class Node:
    def __init__(self, data: EvtData = None):
        self.data = data
        self.children = []

    def __repr__(self):
        return f"{self.__class__.__name__}(data={self.data!r})"

    def __str__(self) -> str:
        return f"{self.__class__.__name__}(data={self.data})"

    def add_children(self, data):
        self.children.append(Node(data))

class EventTree:
    root = None

    @staticmethod
    def parse_event(event: str):
        import xml.etree.ElementTree as Et
        ns              = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        root            = Et.fromstring(event)
        system_time_str = root.find('.//ns:TimeCreated', ns).attrib['SystemTime']
        match           = re.match(r'(.*\.\d{6})\d?(Z)', system_time_str)
        modifiedtime    = match.group(1) + match.group(2) if match else system_time_str
        system_time     = datetime.strptime(modifiedtime, '%Y-%m-%dT%H:%M:%S.%f%z').astimezone()

        fields          = ["NewProcessId", "NewProcessName", "ProcessId", "ParentProcessName"]
        data            = {field: fstr(root.find(f'.//ns:Data[@Name="{field}"]', ns).text) for field in fields}

        return EvtData(data, system_time)

    def pre_order_traversal(self, node: Node):
        if node is not None:
            yield node
            for child in node.children:
                yield from self.pre_order_traversal(child)

    def post_order_traversal(self, node: Node):
        if node is not None:
            for child in node.children:
                yield from self.post_order_traversal(child)
            yield node

    @staticmethod
    def level_order_traversal(node: Node):
        q = Queue()
        q.put(node)
        while not q.empty():
            out: Node = q.get()
            yield out
            if not out.children:
                continue
            for child in out.children:
                q.put(child)

    def release_tree(self):
        self.root = None

    def init_tree(self, data: EvtData):
        self.root = Node(data)
        return True

def evt_query() -> QueryEvt:
    return QueryEvt()

def _enum_events(hevent):
    event = EVT_HANDLE()
    returned = DWORD(0)
    while EvtNext(hevent, 1, byref(event), INFINITE, 0, byref(returned)):
        if event == INVALID_HANDLE_VALUE:
            report(f"Invalid handle: 0x{event}", raise_=False)
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
            report("malloc failed.", raise_=False)
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
            report(f"EvtRender failed with {GetLastError()}", raise_=False)
            continue

        if GetLastError() == ERROR_SUCCESS:
            yield rendered_content.value

        EvtClose(event)

class ProcessManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(ProcessManager, cls).__new__(cls)
        return cls._instance

    def __init__(self, pid: int):
        if hasattr(self, '_initialized') and self._initialized:
            return
        self.mainpid        = pid
        self.datas          = []
        self.evttree        = EventTree()
        self.lock           = threading.Lock()
        self.loop           = asyncio.new_event_loop()
        self.change_event   = asyncio.Event()
        self.kill_event     = asyncio.Event()
        self.exit_event     = asyncio.Event()
        self._initialized   = True
        threading.Thread(target=self.run_loop, daemon=True).start()
        self.loop.call_soon_threadsafe(self.grab_pids)

    def run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def schedule_task(self):
        self.loop.call_later(60, self.scheduled_grab)

    def scheduled_grab(self):
        if not self.kill_event.is_set():
            asyncio.run_coroutine_threadsafe(self.grab_pids(), self.loop)
            self.schedule_task()

    async def grab_pids(self):
        try:
            if not IsUserAnAdmin():
                report("Currently not running in administrator mode", statuscode=GetLastError())
            with evt_query() as hevent:
                for content in _enum_events(hevent):
                    data = self.evttree.parse_event(content)
                    with self.lock:
                        self.datas.append(data)
                    if data.new_process_id == self.mainpid:
                        break
                with self.lock:
                    self.datas = self.datas[::-1]
                    self.build_tree()
        except OSError:
            self.exit_event.set()
            exit(1)

    def build_tree(self):
        if not self.datas:
            return
        self.evttree.init_tree(self.datas[0])
        for data in self.datas[1:]:
            evtiter = self.evttree.pre_order_traversal(self.evttree.root)
            for node in evtiter:
                if node.data != data:
                    continue
                if is_running(node.data.process_id, data.process_id):
                    break
                cmdline = get_cmdline(data.process_id)
                if data.process_name not in cmdline:
                    continue
                node.add_children(data)
        # self.logtree()

    def logtree(self):
        evtiter = self.evttree.level_order_traversal(self.evttree.root)
        for node in evtiter:
            if node is None:
                continue
            logger.info(node.data)

    async def kill_pids(self):
        with self.lock:
            evtiter = self.evttree.post_order_traversal(self.evttree.root)
            for node in evtiter:
                terminate_process(node.data.process_id)
            self.datas = []
            self.evttree = EventTree()

    async def handle_event(self, event_type, pid=None):
        if event_type == "kill":
            await self.kill_pids()
        elif event_type == "change" and pid is not None:
            with self.lock:
                self.datas = []
                self.evttree.release_tree()
                self.mainpid = pid
                await self.grab_pids()

    def start(self):
        self.schedule_task()

    def stop(self):
        self.loop.call_soon_threadsafe(self.loop.stop)

    def send_change_event(self, pid: int):
        self.kill_event.clear()
        self.change_event.set()
        asyncio.run_coroutine_threadsafe(self.handle_event('change', pid), self.loop)

    def send_kill_event(self):
        self.kill_event.set()
        self.change_event.clear()
        asyncio.run_coroutine_threadsafe(self.handle_event('kill'), self.loop)
