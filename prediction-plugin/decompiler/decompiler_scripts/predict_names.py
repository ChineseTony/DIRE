from collections import defaultdict
from util import UNDEF_ADDR, CFuncGraph, GraphBuilder, hexrays_vars, get_expr_name
import idaapi
import ida_hexrays
import json
import jsonlines
import os
import re
import subprocess
import sys

from idc import *
import idaapi
import ida_struct
import idc
import ida_nalt


try:
    from CStringIO import StringIO ## for Python 2
except ImportError:
    from io import StringIO ## for Python 3

# Dictionary mapping variable ids to (orig, orig) pairs
varnames = dict()
oldvarnames = dict()
var_id = 0
count = 0
sentinel_vars = re.compile('@@VAR_[0-9]+')
vartypes = dict()

basic_types = ['short','int','float','double','char','long']
actname = "predict:vartypes"

dire_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..'))
RUN_ONE = os.path.join(dire_dir, "run_one.py")
MODEL = os.path.join(dire_dir, 'data', 'saved_models', 'model.hybrid.bin')


def get_expr_type(expr):
    return expr.type._print()

def ctype_trim(ctypestr):
    mystr = "".join(ctypestr.split())
    mystr = mystr.replace("[", "_")
    mystr = mystr.replace("]", "_")
    mystr = mystr.replace("_", "")
    mystr = mystr.replace("*", "")
    mystr = mystr.replace("const", "")
    return mystr


# Rename variables to sentinel representation
class RenamedGraphBuilder(GraphBuilder):
    def __init__(self, cg, func, vuu):
        self.func = func
        self.vuu = vuu
        super(RenamedGraphBuilder, self).__init__(cg)

    def visit_expr(self, e):
        global var_id
        if e.op is ida_hexrays.cot_var:
            # Save original name of variable
            original_name = get_expr_name(e)
            if not sentinel_vars.match(original_name):
                # Rename variables to @@VAR_[id]@@[orig name]@@[orig name]
                new_name = '@@VAR_' + str(var_id) + '@@' + original_name + '@@' + original_name
                self.vuu.rename_lvar(self.vuu.cfunc.get_lvars()[e.v.idx],
                                     str(new_name),
                                     True)
                # This is needed so that the NN graph sees the new
                # name without visiting the entire expression again.
                self.func.get_lvars()[e.v.idx].name = str(new_name)
                varnames[original_name] = new_name
                oldvarnames[new_name] = original_name
                var_id += 1
        return self.process(e)

# 获取name对应的变量类型信息
class FinalRename(ida_hexrays.ctree_visitor_t):
    def __init__(self, renamings, func, vuu):
        super(FinalRename, self).__init__(0)
        self.renamings = renamings
        self.func = func
        self.vuu = vuu

    def visit_expr(self, e):
        global count
        global vartypes
        if e.op is ida_hexrays.cot_var:
            original_name = get_expr_name(e)
            if original_name in self.renamings:
                new_type_name = self.renamings[original_name]
                if oldvarnames[original_name] != new_type_name:
                    print("get var typing name %s to %s"%(oldvarnames[original_name],new_type_name))
                tmp = original_name.split("@@")[2]
                self.vuu.rename_lvar(self.vuu.cfunc.get_lvars()[e.v.idx],str(tmp),True)
                self.func.get_lvars()[e.v.idx].name = tmp
                vartypes[tmp] = new_type_name
                # 动态刷新页面
                self.vuu = idaapi.get_widget_vdui(idaapi.find_widget("Pseudocode-A"))
                self.vuu.refresh_ctext()

        #         todo change the variable type

        return 0

# class ResetName(ida_hexrays.ctree_visitor_t):
#     def __init__(self, renamings, func, vuu):
#         super(ResetName, self).__init__(0)
#         self.func = func
#         self.vuu = vuu
#
#     def visit_expr(self, e):
#         global count
#         if e.op is ida_hexrays.cot_var:
#             original_name = get_expr_name(e)
#             tmp = original_name.split("@@")[2]
#             self.vuu.rename_lvar(self.vuu.cfunc.get_lvars()[e.v.idx],str(tmp),True)
#             self.func.get_lvars()[e.v.idx].name = tmp
#             # 动态刷新页面
#             self.vuu = idaapi.get_widget_vdui(idaapi.find_widget("Pseudocode-A"))
#             self.vuu.refresh_ctext()
#         return 0

def set_typedef_type(name:str):
    tinfo = ida_typeinf.tinfo_t()
    til = ida_typeinf.til_t()
    # tinfo.create_typedef(til, "MyBool", ida_typeinf.BTF_TYPEDEF, True)
    tinfo.create_typedef(til, name, ida_typeinf.BTF_TYPEDEF, True)


# todo 读取类型字典表 区分基本类型 自定义类型 还有 结构体类型变量
class ChangeType(ida_hexrays.ctree_visitor_t):
    def __init__(self,func, vuu):
        self.func = func
        self.vuu = vuu
        super(ChangeType, self).__init__(1)

    def visit_expr(self, e):
        global count
        global vartypes
        if e.op is ida_hexrays.cot_var:
            original_name = get_expr_name(e)
            print("vartype---->"+str(vartypes))
            lvar = self.vuu.cfunc.get_lvars()[e.v.idx]
            if original_name in vartypes.keys():
                predict_type_name = vartypes[original_name]
                original_type = get_expr_type(e)
                # 如果原来的类型 == 预测变量类型直接跳过
                if "sizet" not in predict_type_name and predict_type_name != ctype_trim(original_type):
                    tif = ida_typeinf.tinfo_t()
                    tid_t = ida_struct.add_struc(count, predict_type_name)
                    struct_id = ida_struct.get_struc_id(predict_type_name)
                    # 如果是基本类型
                    if predict_type_name in basic_types:
                        ida_typeinf.parse_decl(tif, None, predict_type_name + " ;", 0)
                    else:
                        if "*" in original_type:
                            ida_typeinf.parse_decl(tif, None, predict_type_name + "* ;", 0)
                        else:
                            ida_typeinf.parse_decl(tif, None, "struct " + predict_type_name + " ;", 0)
                    lvar.set_lvar_type(tif)
                    self.vuu = idaapi.get_widget_vdui(idaapi.find_widget("Pseudocode-A"))
                    self.vuu.refresh_ctext()
        return 0

# Process a single function given its EA
def func(ea, vuu):
    f = idaapi.get_func(ea)
    function_name = idaapi.get_func_name(ea)
    if f is None:
        print('Please position the cursor within a function')

    cfunc = None
    try:
        cfunc = idaapi.decompile(f)
    except ida_hexrays.DecompilationFailure as e:
        print('Failed to decompile %x: %s!' % (ea, function_name))
        raise e

    # Rename decompilation graph
    cg = CFuncGraph(None)
    gb = GraphBuilder(cg)
    gb.apply_to(cfunc.body, None)
    #ac = AddressCollector(cg)
    #ac.collect()
    rg = RenamedGraphBuilder(cg, cfunc, vuu)
    rg.apply_to(cfunc.body, None)
    
    # Create tree from collected names
    cfunc.build_c_tree()
    new_graph = CFuncGraph(None)
    new_builder = GraphBuilder(new_graph)
    new_builder.apply_to(cfunc.body, None)
    function_info = dict()
    function_info["function"] = function_name
    function_info["ast"] = new_graph.json_tree(0)
    raw_code = ""
    for line in cfunc.get_pseudocode():
        raw_code += idaapi.tag_remove(line.line) + '\n'
    function_info["raw_code"] = raw_code
    return function_info, cfunc

class predict_names_ah_t(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        print("Suggesting variable type names...")
        ea = idaapi.get_screen_ea()
        vuu = ida_hexrays.get_widget_vdui(ctx.widget)
        if ea is None:
            idaapi.warning("Current function not found.")
        else:
            f = StringIO()
            with jsonlines.Writer(f) as writer:
                try:
                    info, cfunc = func(ea, vuu)
                    # We must set the working directory to the dire dir to open the model correctly
                    os.chdir(dire_dir)
                    p = subprocess.Popen([RUN_ONE, '--model', MODEL], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, encoding=sys.getdefaultencoding())
                    #print(info)
                    writer.write(info)
                    comm = p.communicate(input=f.getvalue())
                    json_results = comm[0]
                    stderr = comm[1]
                    if p.returncode != 0:
                        print(stderr)
                        raise ValueError("Variable type prediction failed")
                    results = json.loads(json_results)
                    best_results = results[0][0]
                    #print("best: ", best_results)
                    tuples = map(lambda x: (varnames[x[0]] if x[0] in varnames else x[0], x[1]['new_name']), best_results.items())

                    FinalRename(dict(tuples), cfunc, vuu).apply_to(cfunc.body, None)

                except ida_hexrays.DecompilationFailure:
                    idaapi.warning("Decompilation failed")

                except ValueError as e:
                    idaapi.warning(str(e) + ". See output window for more details.")
            ChangeType(cfunc, vuu).apply_to(cfunc.body, None)
            # Force the UI to update
            vuu.refresh_ctext()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if \
            ctx.widget_type == idaapi.BWN_PSEUDOCODE else \
            idaapi.AST_DISABLE_FOR_WIDGET

class name_hooks_t(idaapi.Hexrays_Hooks):
    def __init__(self):
        idaapi.Hexrays_Hooks.__init__(self)
    def populating_popup(self, widget, phandle, vu):
        idaapi.attach_action_to_popup(vu.ct, None, actname)
        return 0

if idaapi.init_hexrays_plugin():
    idaapi.register_action(
        idaapi.action_desc_t(
            actname,
            "Predict variable type names",
            predict_names_ah_t(),
            "P"))
    name_hooks = name_hooks_t()
    name_hooks.hook()
else:
    print('Predict variable names: hexrays is not available.')

class plugin(idaapi.plugin_t):
    flags = 0
    comment = "Predicts variable names in decompiled code"

    wanted_name = "Predict variable type names"
    #wanted_hotkey = "P"

    def init(self):
        return idaapi.PLUGIN_KEEP

def PLUGIN_ENTRY():
    return plugin()
