#include <intrin.h>
#include <stdint.h>
#include <stdio.h>

#define GUEST_RIP 0x0000681E

#pragma optimize("", off)
void test_all_vmx(void)
{
    int status;
    uint64_t FakePhysicalAddress = 0xB8000;
    uint64_t old_rip = 0x00;
    uint64_t new_rip = 0x41424344;

    __vmx_off();
    status = __vmx_on(&FakePhysicalAddress);
    if (status) {
        printf("[-] __vmx_on failed : %d\n", status);
    }
    status = __vmx_vmclear(&FakePhysicalAddress);
    if (status) {
        printf("[-] __vmx_vmclear failed : %d\n", status);
    }
    __vmx_vmlaunch();
    status = __vmx_vmptrld(&FakePhysicalAddress);
    if (status) {
        printf("[-] __vmx_vmptrld failed : %d\n", status);
    }
    __vmx_vmptrst(&FakePhysicalAddress);
    __vmx_vmread(GUEST_RIP, &old_rip);
    if (__vmx_vmwrite(GUEST_RIP, new_rip) != 0) {
        return;
    }
    status = __vmx_vmresume();
    if (status) {
        printf("[-] __vmx_vmresume failed : %d\n", status);
    }
}

int main(int arg, char* argv[])
{
    test_all_vmx();
    return 0;
}
