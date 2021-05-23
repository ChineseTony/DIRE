from collections import defaultdict
from util import UNDEF_ADDR, CFuncGraph, GraphBuilder, hexrays_vars, get_expr_name,ctype_trim,ctype_trim2
import idaapi
import ida_hexrays
import ida_kernwin
import ida_pro
import json
import jsonlines
import pickle
import os
import re
from idc import *
import idautils

varmap = dict()
# Dictionary mapping variable ids to (orig, renamed) pairs
varnames = dict()
var_id = 0
sentinel_vars = re.compile('@@VAR_[0-9]+')
env = os.environ.copy()

class RenamedGraphBuilder(GraphBuilder):
    def __init__(self, cg, func, addresses):
        self.func = func
        self.addresses = addresses
        super(RenamedGraphBuilder, self).__init__(cg)

    def visit_expr(self, e):
        global var_id
        if e.op is ida_hexrays.cot_var:
            # Save original name of variable
            original_name = get_expr_name(e)
            original_type_name = ctype_trim(e.cexpr.type._print())
            types = dict()
            if not sentinel_vars.match(original_name):
                temp_dict = dict()
                addresses = frozenset(self.addresses[original_name])
                if addresses in varmap and varmap[addresses] != '::NONE::':
                    new_name = varmap[addresses]
                    if new_name in temp_dict.keys():
                        struct_info = temp_dict[new_name]
                        new_name = struct_info
                        # $ 为指针类型，类型传导 添加到环境变量用于类型传导
                        if "$" in new_name:
                            types[original_name] = new_name.replace("$","")
                            env['TYPES'] = types
                else:
                    new_name = original_type_name
                # varnames[var_id] = (original_name, new_name)
                var_id += 1
        return self.process(e)

class AddressCollector:
    def __init__(self, cg):
        self.cg = cg
        self.addresses = defaultdict(set)

    def collect(self):
        for item in self.cg.items:
            if item.op is ida_hexrays.cot_var:
                name = get_expr_name(item)
                mytpye = ctype_trim(item.type._print())
                if item.ea != UNDEF_ADDR:
                    self.addresses[name].add(item.ea)
                else:
                    item_id = self.cg.reverse[item]
                    ea = self.cg.get_pred_ea(item_id)
                    if ea != UNDEF_ADDR:
                        self.addresses[name].add(ea)

# Process a single function given its EA
def func(ea):
    f = idaapi.get_func(ea)
    function_name = get_func_name(ea)
    if f is None:
        print('Please position the cursor within a function')

    cfunc = None
    try:
        cfunc = idaapi.decompile(f)
    except ida_hexrays.DecompilationFailure as e:
        print('Failed to decompile %x: %s!' % (ea, function_name))
        raise e

    renamed_file = renamed_prefix + '_' + function_name + '.c'

    # Rename decompilation graph
    cg = CFuncGraph(None)
    gb = GraphBuilder(cg)
    gb.apply_to(cfunc.body, None)
    ac = AddressCollector(cg)
    ac.collect()
    rg = RenamedGraphBuilder(cg, cfunc, ac.addresses)
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
    return function_info

class custom_action_handler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

class collect_vars(custom_action_handler):
    def activate(self, ctx):
        print('Collecting vars.')
        print('Vars collected.')
        return 1

def main():
    global renamed_prefix
    global varmap
    global varnames
    renamed_prefix = os.path.join(os.environ['OUTPUT_DIR'], 'functions',
                                  os.environ['PREFIX'])
    # Load collected variables
    with open(os.environ['COLLECTED_VARS']) as vars_fh:
        varmap = pickle.load(vars_fh)

    # Collect decompilation info
    cv = collect_vars()
    cv.activate(None)

idaapi.auto_wait()
if not idaapi.init_hexrays_plugin():
    idaapi.load_plugin('hexrays')
    idaapi.load_plugin('hexx64')
    if not idaapi.init_hexrays_plugin():
        print('Unable to load Hex-rays')
    else:
        print('Hex-rays version %s has been detected' % idaapi.get_hexrays_version())
main()
ida_pro.qexit(0)
