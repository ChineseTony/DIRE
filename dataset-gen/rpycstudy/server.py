# -*- coding: utf-8 -*-
# 在ida 开启server脚本
# reference https://github.com/zardus/idalink
import idc
import threading

from rpyc.core import SlaveService
from rpyc.utils.server import OneShotServer, ThreadedServer


def main_thread(port):
    srv = ThreadedServer(SlaveService, port=port)
    srv.start()

def main():
    port = int(idc.ARGV[1]) if idc.ARGV[1:] else 18861
    thread_mode = idc.ARGV[2] == 'threaded' if idc.ARGV[2:] else False
    print('Received arguments: port=%s, thread_mode=%s' % (port, thread_mode))
    if thread_mode:
        thread = threading.Thread(target=main_thread, args=(port, ))
        thread.daemon = True
        thread.start()
    else:
        srv = OneShotServer(SlaveService, port=port,
                            protocol_config={'import_custom_exceptions': True})
        srv._listen()
        srv._register()
        srv.accept()
        idc.Exit(0)
        # idc.exit_process()

if __name__ == '__main__':
    main()
