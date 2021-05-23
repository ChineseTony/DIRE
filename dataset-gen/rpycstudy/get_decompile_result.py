# -*- coding: utf-8 -*-

# reference https://github.com/zardus/idalink


import random
import socket
import time
from rpyc import classic as rpyc_classic
import logging
import os
import subprocess
import sys
import rpyc
import argparse
import tempfile
from errors import IDALinkError

LOG = logging.getLogger('idalink')
MODULE_DIR = os.path.dirname(os.path.realpath(__file__))
IDA_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'support')
LOGFILE = os.path.join(tempfile.gettempdir(), 'idatlink-{port}.log')



IDA_MODULES = ['ida_allins',
               'ida_auto',
               'ida_bytes',
               'ida_dbg',
               'ida_diskio',
               'ida_entry',
               'ida_enum',
               'ida_expr',
               'ida_fixup',
               'ida_fpro',
               'ida_frame',
               'ida_funcs',
               'ida_gdl',
               'ida_graph',
               'ida_hexrays',
               'ida_ida',
               'ida_idaapi',
               'ida_idc',
               'ida_idd',
               'ida_idp',
               'ida_kernwin',
               'ida_lines',
               'ida_loader',
               'ida_moves',
               'ida_nalt',
               'ida_name',
               'ida_netnode',
               'ida_offset',
               'ida_pro',
               'ida_problems',
               'ida_range',
               'ida_registry',
               'ida_search',
               'ida_segment',
               'ida_segregs',
               'ida_strlist',
               'ida_struct',
               'ida_tryblks',
               'ida_typeinf',
               'ida_ua',
               'ida_xref',
               'idaapi',
               'idautils',
               'idc']


def ida_connect(host='localhost', port=18861, retry=10):
    for i in range(retry):
        try:
            LOG.debug('Connectint to %s:%d, try %d...', host, port, i + 1)
            link = rpyc_classic.connect(host, port)
            link.eval('2 + 2')
        except socket.error:
            time.sleep(1)
            continue
        else:
            LOG.debug('Connected to %s:%d', host, port)
            return link

    raise IDALinkError("Could not connect to "
                       "%s:%d after %d tries" % (host, port, retry))


def _which(filename):
    if os.path.pathsep in filename:
        if os.path.exists(filename) and os.access(filename, os.X_OK):
            return filename
        return None
    path_entries = os.getenv('PATH').split(os.path.pathsep)
    for entry in path_entries:
        filepath = os.path.join(entry, filename)
        if os.path.exists(filepath) and os.access(filepath, os.X_OK):
            return filepath
    return None


class RemoteIDALink(object):
    def __init__(self, filename=None):
        self.filename = filename
        for m in IDA_MODULES:
            try:
                setattr(self, m, __import__(m))
            except ImportError:
                pass


def ida_spawn(ida_binary, filename, port=18861, mode='oneshot',
              processor_type=None, logfile=None):
    ida_progname = _which(ida_binary)
    if ida_progname is None:
        raise IDALinkError('Could not find executable %s' % ida_binary)
    if mode not in ('oneshot', 'threaded'):
        raise ValueError("Bad mode %s" % mode)

    if logfile is None:
        logfile = LOGFILE.format(port=port)

    ida_realpath = os.path.expanduser(ida_progname)
    file_realpath = os.path.realpath(os.path.expanduser(filename))
    server_script = os.path.join(MODULE_DIR, 'server.py')

    LOG.info('Launching IDA (%s) on %s, listening on port %d, logging to %s',
             ida_realpath, file_realpath, port, logfile)

    env = dict(os.environ)
    if mode == 'oneshot':
        env['TVHEADLESS'] = '1'

    if sys.platform == "darwin":
        if "VIRTUAL_ENV" in os.environ:
            env['DYLD_INSERT_LIBRARIES'] = os.environ['VIRTUAL_ENV'] + '/.Python'

    # The parameters are:
    # -A     Automatic mode
    # -S     Run a script (our server script)
    # -L     Log all output to our logfile
    # -p     Set the processor type

    command = [
        ida_realpath,
        # 关闭自动模式，需要打开窗口页面
        # '-A',
        '-S%s %d %s' % (server_script, port, mode),
        '-L%s' % logfile,
    ]
    if processor_type is not None:
        command.append('-p%s' % processor_type)
    command.append(file_realpath)

    LOG.debug('IDA command is %s', ' '.join("%s" % s for s in command))
    return subprocess.Popen(command, env=env)



class IDALink(object):
    def __init__(self,
                 ida_binary=None,
                 filename=None,
                 host=None,
                 port=None,
                 retry=10,
                 processor_type=None,
                 logfile=None):

        if port is None:
            if host is not None:
                raise ValueError("Provided host but not port")
            port = random.randint(40000, 49999)

        if ida_binary is None and host is None:
            raise ValueError("Must provide ida_binary or host")
        if ida_binary is not None and host is not None:
            raise ValueError("Must provide exactly one of ida_binary and host")

        if ida_binary is not None:
            if filename is None:
                raise ValueError("Must provide filename if spawning a local process")

            self._proc = ida_spawn(ida_binary, filename, port, processor_type=processor_type, logfile=logfile)
            host = 'localhost'
        else:
            self._proc = None

        self._link = ida_connect(host, port, retry=retry)

        for m in IDA_MODULES:
            try:
                setattr(self, m, self._link.root.getmodule(m))
            except ImportError:
                pass
        self.filename = filename

    def close(self):
        self._link.close()
        if self._proc is not None:
            self._proc.wait()

def get_type(ida_binary,filename,structs:dict):
    ida = IDALink(ida_binary, filename)
    # 设置异常
    rpyc.core.vinegar._generic_exceptions_cache["ida_hexrays.DecompilationFailure"] \
        = ida.ida_hexrays.DecompilationFailure
    type_dict = dict()
    struct_names = set()
    for ea in ida.idautils.Functions():
        print(ida.idaapi.get_func_name(ea))
        f = ida.idaapi.get_func(ea)
        if f is None:
            print('Please position the cursor within a function')
            continue
        cfunc = None
        ida.idaapi.open_pseudocode(ea, 0)
        vu = ida.idaapi.get_widget_vdui(ida.idaapi.find_widget("Pseudocode-A"))
        print(vu)
        if vu is not None:
            # 获取pseudocode函数
            print("before-->"+vu.cfunc)
            lvars = vu.cfunc.get_lvars()
            for lvar in lvars:
                tmp = 0
                if lvar.name in structs.keys():
                    struct_name = structs[lvar.name]
                    struct_names.add(struct_name)
                    tif = ida.ida_typeinf.tinfo_t()
                    tid_t = ida.ida_struct.add_struc(tmp, struct_name)
                    struct_id = ida.ida_struct.get_struc_id(struct_name)
                    ida.ida_typeinf.parse_decl(tif, None, "struct " + struct_name + " *;", 0)
                    tmp += 1
                    vu.set_lvar_type(lvar, tif)
            # 获取经过类型传递之后的反编译代码
            print("change--->" + vu.cfunc)
            for var in vu.cfunc.get_lvars():
                if var.type() in struct_names:
                    type_dict[var.name] = var.type()
        ida.idaapi.close_pseudocode(ida.idaapi.find_widget("Pseudocode-A"))

    # ida.ida_pro.qexit(0)
    ida.close()
    return type_dict

