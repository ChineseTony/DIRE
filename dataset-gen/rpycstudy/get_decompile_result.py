# -*- coding: utf-8 -*-
import rpyc

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


conn = rpyc.classic.connect("localhost",port=18861)
class RemoteIDALink(object):
    def __init__(self,filename=None):
        self.filename = filename
        for m in IDA_MODULES:
            try:
                setattr(self, m, conn.root.getmodule(m))
            except ImportError:
                pass




link = RemoteIDALink("test")
conn.execute("import idautils")
print(conn.execute('idautils.Functions()'))


