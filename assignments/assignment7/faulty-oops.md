# Analysis of oops message from faulty kernel

## Oops Message
```
# echo “hello\_world” > /dev/faulty
Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000
Mem abort info:
  ESR = 0x0000000096000045
  EC = 0x25: DABT (current EL), IL = 32 bits
  SET = 0, FnV = 0
  EA = 0, S1PTW = 0
  FSC = 0x05: level 1 translation fault
Data abort info:
  ISV = 0, ISS = 0x00000045
  CM = 0, WnR = 1
user pgtable: 4k pages, 39-bit VAs, pgdp=000000004129a000
[0000000000000000] pgd=0000000000000000, p4d=0000000000000000, pud=0000000000000000
Internal error: Oops: 0000000096000045 [#1] SMP
Modules linked in: hello(O) faulty(O) scull(O)
CPU: 0 PID: 153 Comm: sh Tainted: G           O       6.1.44 #1
Hardware name: linux,dummy-virt (DT)
pstate: 80000005 (Nzcv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--)
pc : faulty_write+0x10/0x20 [faulty]
lr : vfs_write+0xc8/0x390
sp : ffffffc008dfbd20
x29: ffffffc008dfbd80 x28: ffffff8001b9c240 x27: 0000000000000000
x26: 0000000000000000 x25: 0000000000000000 x24: 0000000000000000
x23: 0000000000000012 x22: 0000000000000012 x21: ffffffc008dfbdc0
x20: 000000555c309990 x19: ffffff8001bf4d00 x18: 0000000000000000
x17: 0000000000000000 x16: 0000000000000000 x15: 0000000000000000
x14: 0000000000000000 x13: 0000000000000000 x12: 0000000000000000
x11: 0000000000000000 x10: 0000000000000000 x9 : 0000000000000000
x8 : 0000000000000000 x7 : 0000000000000000 x6 : 0000000000000000
x5 : 0000000000000001 x4 : ffffffc000777000 x3 : ffffffc008dfbdc0
x2 : 0000000000000012 x1 : 0000000000000000 x0 : 0000000000000000
Call trace:
  faulty_write+0x10/0x20 [faulty]
  ksys_write+0x74/0x110
  __arm64_sys_write+0x1c/0x30
  invoke_syscall+0x54/0x120
  el0_svc_common.constprop.0+0x44/0xf0
  do_el0_svc+0x2c/0xc0
  el0_svc+0x2c/0x90
  el0t_64_sync_handler+0x114/0x120
  el0t_64_sync+0x18c/0x190
Code: d2800001 d2800000 d503233f d50323bf (b900003f) 
---[ end trace 0000000000000000 ]---
```

## Analysis of message
The program counter (pc) tells us that the kernel panic occurred in the faulty kernel module, inside
the faulty\_write function. Specifically, 16 bytes into the function which is 32 bytes long.
We can use objdump to inspect the assembly for the faulty\_write function and determine which lin ecaused the null dereference. 
### Objdump output
```
0000000000000000 <faulty_write>:
   0:	d2800001 	mov	x1, #0x0                   	// #0
   4:	d2800000 	mov	x0, #0x0                   	// #0
   8:	d503233f 	paciasp
   c:	d50323bf 	autiasp
  10:	b900003f 	str	wzr, [x1]
  14:	d65f03c0 	ret
  18:	d503201f 	nop
  1c:	d503201f 	nop
```

We can see from this assembly dump that the problematic line is str wzr. This line stores the zero
register (wzr) into the memory address stored in x1. We can also see that 0 was stored in x1 earlier
in the program. That is the null pointer dereference.
