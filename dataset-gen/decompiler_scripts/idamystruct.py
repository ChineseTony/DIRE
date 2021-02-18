# -*- coding: utf-8 -*-


import ida_struct
import idc
import ida_nalt
import ida_hexrays
import ida_typeinf


def get_struct_sub_type(struct_name, offset):

    struct_id = ida_struct.get_struc_id(struct_name)
    if struct_id is None:
        print("struct :%s not exist" % struct_name)
        return ""

    my_struct = ida_struct.get_struc(struct_id)
    my_struct_size = ida_struct.get_struc_size(my_struct)
    print("size:{}".format(my_struct_size))
    if offset >= my_struct_size:
        return ""
    print(ida_struct.get_struc_name(struct_id))

    # member_t
    my_member = ida_struct.get_member(my_struct, offset)

    # ida_struct.get_member_by_id()
    #
    # ida_struct.get_member_name()
    m_id = my_member.id
    #print(m_id)
    print(ida_struct.get_member_fullname(m_id))
    print(ida_struct.get_member_struc(ida_struct.get_member_fullname(m_id)))

    print(ida_struct.get_member_size(my_member))

    tinfo = ida_typeinf.tinfo_t()
    print(ida_struct.get_member_tinfo(tinfo,my_member))
    return tinfo



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


