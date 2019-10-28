#
# This script is mostly based on the previous work done by https://dougallj.wordpress.com/2018/06/04/writing-a-hex-rays-plugin-vmx-intrinsics/
# Now it's a python plugin and some renaming was necessary as MICROCODE API has changed (cf ida_hexrays.py)
# Use of mop_a/mop_addr_t for taking the address of registers for vmread/vmclear/vmptrld/vmptrst/vmxon
#

import idaapi
import ida_hexrays
import ida_allins
import ida_idp

# Identify 'tt' register
# import ida_hexrays
# for i in range(0, 0xFF):
#     print("0x{0:02X} => {1}".format(i, ida_hexrays.get_mreg_name(i, 1)))
IDA_TT = 0xC0

def is_gte_ida74():
    major, minor = map(int, idaapi.get_kernel_version().split("."))
    return (major == 7 and minor >= 4)

class MicroInstruction(ida_hexrays.minsn_t):

    def __init__(self, opcode, ea):
        ida_hexrays.minsn_t.__init__(self, ea)
        self.opcode = opcode
        self.l.zero()
        self.r.zero()
        self.d.zero()

class CallBuilder():

    def __init__(self, cdg, name, return_type=idaapi.tinfo_t(idaapi.BT_VOID)):
        self.emitted = False
        self.cdg = cdg
        self.callinfo = ida_hexrays.mcallinfo_t()
        self.callinfo.callee = idaapi.BADADDR
        self.callinfo.solid_args = 0x00
        self.callinfo.call_spd = 0x00
        self.callinfo.stkargs_top = 0x00
        self.callinfo.cc = idaapi.CM_CC_FASTCALL
        self.callinfo.return_type = return_type
        self.callinfo.flags = idaapi.FCI_SPLOK | idaapi.FCI_FINAL | idaapi.FCI_PROP
        self.callinfo.role = idaapi.ROLE_UNK

        glbhigh_off = cdg.mba.get_stack_region().off + cdg.mba.get_stack_region().size
        # what memory is visible to the call : GLBLOW - GLBHIGH
        self.callinfo.visible_memory.add(ida_hexrays.ivl_t(0x00, 0x100000))
        self.callinfo.visible_memory.add(ida_hexrays.ivl_t(glbhigh_off, 0xFFFFFFFFFFFFFFFF - glbhigh_off))
        # spoiled locations : GLBLOW - GLBHIGH
        self.callinfo.spoiled.mem.add(ida_hexrays.ivl_t(0x00, 0x100000))
        self.callinfo.spoiled.mem.add(ida_hexrays.ivl_t(glbhigh_off, 0xFFFFFFFFFFFFFFFF - glbhigh_off))

        self.callins = MicroInstruction(ida_hexrays.m_call, self.cdg.insn.ea)
        self.callins.l.make_helper(name)
        self.callins.d.t = ida_hexrays.mop_f
        self.callins.d.size = 0x00
        self.callins.d.f = self.callinfo

        if (return_type.is_void()):
            self.ins = self.callins
        else:
            self.callins.d.size = return_type.get_size()
            self.ins = MicroInstruction(ida_hexrays.m_mov, self.cdg.insn.ea)
            self.ins.l.t = ida_hexrays.mop_d
            self.ins.l.d = self.callins
            self.ins.l.size = self.callins.d.size
            self.ins.d.t = ida_hexrays.mop_r
            self.ins.d.r = 0x00
            self.ins.d.size = self.callins.d.size

    def add_register_argument(self, t, operand):
        ca = ida_hexrays.mcallarg_t()
        ca.t = idaapi.mop_r
        ca.r = operand
        ca.type = t
        ca.size = t.get_size()
        self.callinfo.args.push_back(ca)
        self.callinfo.solid_args += 1

    def add_register_address_argument(self, t, operand):
        addr_t = ida_hexrays.mop_addr_t()
        addr_t.t = idaapi.mop_r
        addr_t.r = operand
        addr_t.type = t
        addr_t.size = t.get_size()
        addr_t.insize = t.get_size()
        addr_t.outsize = t.get_size()

        ca = ida_hexrays.mcallarg_t()
        ca.t = idaapi.mop_a
        ca.a = addr_t
        t.create_ptr(t)
        ca.type = t
        ca.size = t.get_size()
        self.callinfo.args.push_back(ca)
        self.callinfo.solid_args += 1

    def set_return_register(self, reg):
        self.ins.d.r = reg

    def emit(self):
        if self.emitted == False:
            self.cdg.mb.insert_into_block(self.ins , self.cdg.mb.tail)
            self.emitted = True

    def emit_und_reg(self, reg, size):
        ins = MicroInstruction(ida_hexrays.m_und, self.cdg.insn.ea)
        ins.d.t = idaapi.mop_r
        ins.d.r = reg
        ins.d.size = size
        self.cdg.mb.insert_into_block(ins, self.cdg.mb.tail)

    def emit_reg_equals_number(self, result_reg, reg, number, size):
        ins = MicroInstruction(ida_hexrays.m_setz, self.cdg.insn.ea)
        ins.l.t = idaapi.mop_r
        ins.l.r = reg
        ins.l.size = size
        ins.r.make_number(number, size)
        ins.d.t = idaapi.mop_r
        ins.d.r = result_reg
        ins.d.size = 1;
        self.cdg.mb.insert_into_block(ins, self.cdg.mb.tail)

class VMXFilter(ida_hexrays.microcode_filter_t):

    def __init__(self, itype):
        ida_hexrays.microcode_filter_t.__init__(self)
        self.itype = itype
        self.installed = False
        self.toggle_install()

    def match(self, cdg):
        return cdg.insn.itype == self.itype

    def install(self):
        ida_hexrays.install_microcode_filter(self, True);
        self.installed = True

    def uninstall(self):
        ida_hexrays.install_microcode_filter(self, False);
        self.installed = False

    def toggle_install(self):
        if self.installed:
            self.uninstall()
        else:
            self.install()

class VMXVmwrite(VMXFilter):

    def __init__(self):
        VMXFilter.__init__(self, ida_allins.NN_vmwrite)
        self.name = "__vmx_vmwrite"

    def apply(self, cdg):
        builder = CallBuilder(cdg, self.name, idaapi.tinfo_t(idaapi.BT_INT8 | idaapi.BTMT_UNSIGNED))
        builder.add_register_argument(idaapi.tinfo_t(idaapi.BT_INT64 | idaapi.BTMT_UNSIGNED), cdg.load_operand(0))
        builder.add_register_argument(idaapi.tinfo_t(idaapi.BT_INT64 | idaapi.BTMT_UNSIGNED), cdg.load_operand(1))
        builder.emit()
        builder.set_return_register(IDA_TT)
        builder.emit_reg_equals_number(ida_hexrays.mr_zf, IDA_TT, 1, 1)
        builder.emit_reg_equals_number(ida_hexrays.mr_cf, IDA_TT, 2, 1)
        return idaapi.MERR_OK

class VMXVmread(VMXFilter):

    def __init__(self):
        VMXFilter.__init__(self, ida_allins.NN_vmread)
        self.name = "__vmx_vmread"

    def apply(self, cdg):
        builder = CallBuilder(cdg, self.name, idaapi.tinfo_t(idaapi.BT_INT8 | idaapi.BTMT_UNSIGNED))
        builder.add_register_argument(idaapi.tinfo_t(idaapi.BT_INT64 | idaapi.BTMT_UNSIGNED), cdg.load_operand(1))
        builder.add_register_address_argument(idaapi.tinfo_t(idaapi.BT_INT64 | idaapi.BTMT_UNSIGNED), cdg.load_operand(0))
        builder.emit()
        builder.set_return_register(IDA_TT)
        builder.emit_und_reg(ida_hexrays.mr_zf, 1)
        builder.emit_und_reg(ida_hexrays.mr_cf, 1)
        return idaapi.MERR_OK

class VMXVoidReturn(VMXFilter):

    def __init__(self, itype, name):
        VMXFilter.__init__(self, itype)
        self.name = name

    def apply(self, cdg):
        builder = CallBuilder(cdg, self.name, idaapi.tinfo_t(idaapi.BT_INT8 | idaapi.BTMT_UNSIGNED))
        builder.emit()
        builder.set_return_register(IDA_TT)
        builder.emit_reg_equals_number(ida_hexrays.mr_zf, IDA_TT, 1, 1)
        builder.emit_reg_equals_number(ida_hexrays.mr_cf, IDA_TT, 2, 1)
        return idaapi.MERR_OK

class VMXVoid(VMXFilter):

    def __init__(self, itype, name):
        VMXFilter.__init__(self, itype)
        self.name = name

    def apply(self, cdg):
        builder = CallBuilder(cdg, self.name)
        builder.emit()
        builder.emit_und_reg(ida_hexrays.mr_zf, 1)
        builder.emit_und_reg(ida_hexrays.mr_cf, 1)
        return idaapi.MERR_OK

class VMXVMCSReturn(VMXFilter):

    def __init__(self, itype, name):
        VMXFilter.__init__(self, itype)
        self.name = name

    def apply(self, cdg):
        builder = CallBuilder(cdg, self.name, idaapi.tinfo_t(idaapi.BT_INT8 | idaapi.BTMT_UNSIGNED))
        builder.add_register_address_argument(idaapi.tinfo_t(idaapi.BT_INT64 | idaapi.BTMT_UNSIGNED), cdg.load_operand(0))
        builder.emit()
        builder.set_return_register(IDA_TT)
        builder.emit_reg_equals_number(ida_hexrays.mr_zf, IDA_TT, 1, 1)
        builder.emit_reg_equals_number(ida_hexrays.mr_cf, IDA_TT, 2, 1)
        return idaapi.MERR_OK

class VMXIntrinsicIDAPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    comment = "VMX intrinsics plugin for Hex-Rays decompiler"
    help = ""
    wanted_name = "VMXIntrinsic"
    wanted_hotkey = ""

    def __init__(self):
        self.filters = []

    def init(self):
        if is_gte_ida74() == False:
            print("[-] {0} : for ida >= 7.4 only".format(self.wanted_name))
            return idaapi.PLUGIN_SKIP
        if idaapi.ph.id != idaapi.PLFM_386 and not idaapi.get_inf_structure().is_64bit():
            print("[-] {0} : for x64 only".format(self.wanted_name))
            return idaapi.PLUGIN_SKIP
        if not ida_hexrays.init_hexrays_plugin():
            print("[-] {0} : no decompiler available, skipping".format(self.wanted_name))
            return idaapi.PLUGIN_SKIP
        self.add_filter(VMXVmwrite())
        self.add_filter(VMXVmread())
        self.add_filter(VMXVoidReturn(ida_allins.NN_vmlaunch, "__vmx_vmlaunch"))
        self.add_filter(VMXVoidReturn(ida_allins.NN_vmresume, "__vmx_vmresume"))
        self.add_filter(VMXVoid(ida_allins.NN_vmxoff, "__vmx_off"))
        self.add_filter(VMXVMCSReturn(ida_allins.NN_vmclear, "__vmx_vmclear"))
        self.add_filter(VMXVMCSReturn(ida_allins.NN_vmptrld, "__vmx_vmptrld"))
        self.add_filter(VMXVMCSReturn(ida_allins.NN_vmptrst, "__vmx_vmptrst"))
        self.add_filter(VMXVMCSReturn(ida_allins.NN_vmxon, "__vmx_on"))

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        idaapi.warning("[-] {0} cannot be run as a script in IDA.".format(self.wanted_name))

    def add_filter(self, f):
        self.filters.append(f)

    def term(self):
        for f in self.filters:
            f.toggle_install()
        self.filters = []

def PLUGIN_ENTRY():
    return VMXIntrinsicIDAPlugin()
