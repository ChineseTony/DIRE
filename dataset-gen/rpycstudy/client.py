# -*- coding: utf-8 -*-
import sys

import rpyc

import idautils
from idc import *
import idaapi
import ida_struct
import idc
import ida_nalt
import ida_hexrays


# decomplie 所有变量类型
funcs = idautils.Functions()
ea = idaapi.get_screen_ea()
f = idaapi.get_func(ea)
function_name = idaapi.get_func_name(ea)
cfunc = None
try:
    cfunc = idaapi.decompile(f)
except ida_hexrays.DecompilationFailure as e:
    print('Failed to decompile %x: %s!' % (ea, function_name))
    raise e
tid_t = ida_struct.add_struc(1, "hashentry")
struct_id = ida_struct.get_struc_id("hashentry")
my_struct = ida_struct.get_struc(struct_id)
lvars = cfunc.get_lvars()
for lvar in lvars:
    if str(lvar.name) == 'j':
        tif = ida_typeinf.tinfo_t()
        ida_typeinf.parse_decl(tif, None, "struct hashentry;", 0)
        # tif.get_typ
        lvar.set_lvar_type(tif)
        print(str(lvar.name)+"--->"+str(lvar.type()))
    else:
        print(str(lvar.name) + "--->" + str(lvar.type()))
vu = idaapi.get_widget_vdui(idaapi.find_widget("Pseudocode-A"))
vu.refresh_ctext()
cfunc = None
try:
    cfunc = idaapi.decompile(f)
except ida_hexrays.DecompilationFailure as e:
    print('Failed to decompile %x: %s!' % (ea, function_name))
    raise e
conn = rpyc.classic.connect("localhost",port=18861)
rsys = conn.modules.sys
print(cfunc, file=conn.modules.sys.stdout)