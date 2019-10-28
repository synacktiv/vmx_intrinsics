# VMX_INTRINSICS

## Overview

This is a port of Dougall J'[dj_vmx_intrinsics](https://github.com/dougallj/dj_ida_plugins/tree/master/dj_vmx_intrinsics) to
[IDAPython](https://github.com/idapython/src).

This plugin allow to display unhandled VMX instructions into their respective intrinsic form when using the decompiler:

Original output (the value of the register `RAX` is not even displayed):

    _RCX = 0x41424344i64;
    __asm { vmwrite rax, rcx }

Output with the plugin (the value of the VMCS field is now displayed correctly):

    v8 = __vmx_vmwrite(0x681Eui64, 0x41424344ui64);

Some renaming was necessary as MICROCODE API has changed (cf `ida_hexrays.py`).

We use the operand type (`mop_a/mop_addr_t`) for output pointer as second argument for `vmread`/`vmclear`/`vmptrld`/`vmptrst`/`vmxon`.

e.g:

    mov     eax, 4816h
    vmread  rax, rax

will produce:

    v3 = 0x4816i64;
    __vmx_vmread(v3, &v3);

We have added the `GLBLOW` & `GLBHIGH` for visible_memory and spoiled memory to avoid optimization.

## Requirements

* IDA Pro >= 7.4

## Installation

Copy the file `vmx_instrincis.py` to the IDA plugins folder.

## Features

Intrinsics implemented:

* `__vmx_off`
* `__vmx_on`
* `__vmx_vmclear`
* `__vmx_vmlaunch`
* `__vmx_vmptrld`
* `__vmx_vmptrst`
* `__vmx_vmread`
* `__vmx_vmresume`
* `__vmx_vmwrite`