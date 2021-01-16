# -*- coding: utf-8 -*-

import threading
from rpyc.core import SlaveService
from rpyc.utils.server import OneShotServer, ThreadedServer


def main_thread(port):
    srv = ThreadedServer(SlaveService, port=port)
    srv.start()

def main():
    port = 18861
    thread_mode = False
    print('Received arguments: port=%s, thread_mode=%s' % (port, thread_mode))
    if thread_mode:
        thread = threading.Thread(target=main_thread, args=(port, thread_mode))
        thread.daemon = True
        thread.start()
    else:
        while True:
            srv = OneShotServer(SlaveService, port=port)
            srv._listen()
            srv._register()
            srv.accept()

if __name__ == '__main__':
    main()
