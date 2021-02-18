# Usage: IDALOG=/dev/stdout ./idat64 -B -S/path/to/collect.py /path/to/binary

#-*- coding: utf-8 -*-
from collections import defaultdict
from util import UNDEF_ADDR, CFuncGraph, GraphBuilder, hexrays_vars, get_expr_name,ctype_trim,ctype_trim2
import idaapi
import ida_hexrays
import ida_kernwin
import ida_pro
import ida_gdl
import pickle
import os
import json
#from idamystruct import get_struct_info

varmap = dict()                 # frozenset of addrs -> varname

var_struct_info_dict = dict()
var_struct_type_dict = dict()


def get_struct_info(struct_name):

    mydict = {}

    struct_id = ida_struct.get_struc_id(struct_name)
    my_struct = ida_struct.get_struc(struct_id)

    if my_struct is None:
        print("struct :%s not exist" % struct_name)
        return ""
    count = ida_struct.get_struc(struct_id).memqty
    for i in range(0, count):
        member_t = ida_struct.get_struc(struct_id).get_member(i)
        mid = member_t.id
        #print(ida_struct.get_member_fullname(mid))
        #print(member_t.get_soff())
        tinfo = ida_typeinf.tinfo_t()
        ida_struct.get_member_tinfo(tinfo, member_t)
        #name = ida_struct.get_member_fullname(mid).replace(".","_")
        name = ida_struct.get_member_fullname(mid)
        #mydict[name+str("_")+str(tinfo)] = member_t.get_soff()
        mydict[name] = member_t.get_soff()

    #print("struct--->"+str(mydict))
    return mydict


# Collect a map of a set of addresses to a variable name.
# For each variable, this collects the addresses corresponding to its uses.
# 收集函数 变量名称 存放到 字典里面  地址+变量名字
class CollectGraph(CFuncGraph):
    def collect_vars(self):
        rev_dict = defaultdict(set)
        for n in xrange(len(self.items)):
            item = self.items[n]
            if item.op is ida_hexrays.cot_var:
                name = get_expr_name(item.cexpr)
                #name = ctype_trim(item.cexpr.type._print())
                var_struct_type_dict[name] = ctype_trim(item.cexpr.type._print())
                if not hexrays_vars.match(name):
                    if item.ea != UNDEF_ADDR:
                        rev_dict[name].add(item.ea)
                    else:
                        ea = self.get_pred_ea(n)
                        if ea != UNDEF_ADDR:
                            rev_dict[name].add(ea)
        # ::NONE:: is a sentinel value used to indicate that two different
        # variables map to the same set of addresses. This happens in small
        # functions that use all of their arguments to call another function.


        for name,struc_type in var_struct_type_dict.items():
            tmp = get_struct_info(struc_type)
            if tmp:
                var_struct_info_dict[name] = tmp


        for name, addrs in rev_dict.iteritems():
            # 每个变量的地址信息
            addrs = frozenset(addrs)
            if (addrs in varmap):
                varmap[addrs] = '::NONE::'
            else:
                #if  name in var_struct_info_dict.keys():
                    #varmap[addrs] = str(var_struct_info_dict[name].keys()[0]).split(".")[0]
                   # varmap[addrs] = str(var_struct_info_dict[name].keys()[0]).split(".")[0]
                #elif name in var_struct_type_dict.keys():
                if name in var_struct_type_dict.keys():
                    varmap[addrs] = var_struct_type_dict[name]
                else:
                    if name in var_all_type.keys():
                        varmap[addrs] = var_all_type[name]
                    else:
                        varmap[addrs] = name



def func(ea):
    f = idaapi.get_func(ea)
    if f is None:
        print('Please position the cursor within a function')
        return True
    cfunc = None
    try:
        # 使用idaapi 反编译函数中  cfg
        cfunc = idaapi.decompile(f)

    except ida_hexrays.DecompilationFailure:
        pass

    if cfunc is None:
        print('Failed to decompile %x!' % ea)
        return True

    # Build decompilation graph
    cg = CollectGraph(None)
    gb = GraphBuilder(cg)
    gb.apply_to(cfunc.body, None)
    cg.collect_vars()

class custom_action_handler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

# 收集每一个函数的变量
class collect_vars(custom_action_handler):
    def activate(self, ctx):
        print('Collecting vars.')
        for ea in Functions():
            func(ea)
        print('Vars collected.')
        return 1


class dump_info(custom_action_handler):
    def activate(self, ctx):
        # 获取 run_decpmpiler.py 的 COLLECTED_VARS 输出到临时文件中
        with open(os.environ['COLLECTED_VARS'], 'w') as vars_fh:
            # 把收集到的变量序列化输出
            pickle.dump(varmap, vars_fh)
            vars_fh.flush()

        # 把结构体信息 输出到 os环境变里面
        return 1

idaapi.auto_wait()
if not idaapi.init_hexrays_plugin():
    idaapi.load_plugin('hexrays')
    idaapi.load_plugin('hexx64')
    if not idaapi.init_hexrays_plugin():
        print('Unable to load Hex-rays')
    else:
        print('Hex-rays version %s has been detecetd' % idaapi.get_hexrays_version())

def main():
    # 收集所有 hex-rays 反编译出来的 变量 进行预测
    cv = collect_vars()
    cv.activate(None)
    dv = dump_info()
    dv.activate(None)

main()
ida_pro.qexit(0)
