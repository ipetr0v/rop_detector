CURRENT = $(shell uname -r)
KDIR = /lib/modules/$(CURRENT)/build
DEST = /lib/modules/$(CURRENT)/misc
PWD = $(shell pwd)
MODULE = rop
PROGRAM = rop_detector
JUNK = junk

BIN = $(PWD)/bin
SRC = $(PWD)/src
KERNEL = $(SRC)/kernel
ENGINE = $(SRC)/engine
RB_TREE = $(SRC)/rb_tree
CLASSIFIER = $(SRC)/classifier
DISASSEMBLER = $(SRC)/disassembler
LIBUDIS86 = $(DISASSEMBLER)/libudis86
LIBDISASM = $(DISASSEMBLER)/LIBDISASM
EMULATOR = $(SRC)/emulator
INJECTLIB = $(EMULATOR)/Injectlib
HOTPATCH = $(EMULATOR)/hotpatch
LIBEMU = $(EMULATOR)/libemu

obj-m    += $(MODULE).o
$(MODULE)-objs := kernel_main.o
$(MODULE)-objs += server.o

PROGRAM-SRC += $(ENGINE)/client.c
PROGRAM-SRC += $(ENGINE)/engine.c 
PROGRAM-SRC += $(ENGINE)/kernel_interface.c
PROGRAM-SRC += $(ENGINE)/memory_analyzer.c
PROGRAM-SRC += $(ENGINE)/process.c
PROGRAM-SRC += $(ENGINE)/auxiliary.c
PROGRAM-SRC += $(ENGINE)/sniffer.c 

PROGRAM-SRC += $(RB_TREE)/misc.c
PROGRAM-SRC += $(RB_TREE)/stack.c
PROGRAM-SRC += $(RB_TREE)/red_black_tree.c

PROGRAM-SRC += $(CLASSIFIER)/classifier.c

PROGRAM-SRC += $(DISASSEMBLER)/disassembler_interface.c
PROGRAM-SRC += $(LIBDISASM)/ia32_implicit.c
PROGRAM-SRC += $(LIBDISASM)/ia32_insn.c
PROGRAM-SRC += $(LIBDISASM)/ia32_invariant.c
PROGRAM-SRC += $(LIBDISASM)/ia32_modrm.c
PROGRAM-SRC += $(LIBDISASM)/ia32_opcode_tables.c
PROGRAM-SRC += $(LIBDISASM)/ia32_operand.c
PROGRAM-SRC += $(LIBDISASM)/ia32_reg.c
PROGRAM-SRC += $(LIBDISASM)/ia32_settings.c
PROGRAM-SRC += $(LIBDISASM)/x86_disasm.c
PROGRAM-SRC += $(LIBDISASM)/x86_format.c
PROGRAM-SRC += $(LIBDISASM)/x86_imm.c
PROGRAM-SRC += $(LIBDISASM)/x86_insn.c
PROGRAM-SRC += $(LIBDISASM)/x86_misc.c
PROGRAM-SRC += $(LIBDISASM)/x86_operand_list.c
PROGRAM-SRC += $(LIBUDIS86)/itab.c
PROGRAM-SRC += $(LIBUDIS86)/decode.c
PROGRAM-SRC += $(LIBUDIS86)/syn.c
PROGRAM-SRC += $(LIBUDIS86)/syn-intel.c
PROGRAM-SRC += $(LIBUDIS86)/syn-att.c
PROGRAM-SRC += $(LIBUDIS86)/udis86.c

PROGRAM-SRC += $(EMULATOR)/emulator_interface.c
PROGRAM-SRC += $(EMULATOR)/shared_memory_wrapper.c
PROGRAM-SRC += $(HOTPATCH)/exedetails.c
PROGRAM-SRC += $(HOTPATCH)/hotpatch.c
PROGRAM-SRC += $(HOTPATCH)/loader.c

PROGRAM-SRC += $(SRC)/main.c

JUNK-SRC += $(SRC)/junk.c

INJECT-SRC += $(INJECTLIB)/inject.c
INJECT-SRC += $(INJECTLIB)/gadget_searcher.c
INJECT-SRC += $(INJECTLIB)/emulator.c
INJECT-SRC += $(EMULATOR)/shared_memory_wrapper.c
INJECT-SRC += $(EMULATOR)/libemu_memory_access.c
INJECT-SRC += $(DISASSEMBLER)/disassembler_interface.c
INJECT-SRC += $(ENGINE)/auxiliary.c
# --- LIBDISASM ---
INJECT-SRC += $(LIBDISASM)/ia32_implicit.c
INJECT-SRC += $(LIBDISASM)/ia32_insn.c
INJECT-SRC += $(LIBDISASM)/ia32_invariant.c
INJECT-SRC += $(LIBDISASM)/ia32_modrm.c
INJECT-SRC += $(LIBDISASM)/ia32_opcode_tables.c
INJECT-SRC += $(LIBDISASM)/ia32_operand.c
INJECT-SRC += $(LIBDISASM)/ia32_reg.c
INJECT-SRC += $(LIBDISASM)/ia32_settings.c
INJECT-SRC += $(LIBDISASM)/x86_disasm.c
INJECT-SRC += $(LIBDISASM)/x86_format.c
INJECT-SRC += $(LIBDISASM)/x86_imm.c
INJECT-SRC += $(LIBDISASM)/x86_insn.c
INJECT-SRC += $(LIBDISASM)/x86_misc.c
INJECT-SRC += $(LIBDISASM)/x86_operand_list.c
INJECT-SRC += $(LIBUDIS86)/itab.c
INJECT-SRC += $(LIBUDIS86)/decode.c
INJECT-SRC += $(LIBUDIS86)/syn.c
INJECT-SRC += $(LIBUDIS86)/syn-intel.c
INJECT-SRC += $(LIBUDIS86)/syn-att.c
INJECT-SRC += $(LIBUDIS86)/udis86.c
# --- LIBEMU ---
INJECT-SRC += $(LIBEMU)/emu.c
INJECT-SRC += $(LIBEMU)/emu_breakpoint.c
INJECT-SRC += $(LIBEMU)/emu_cpu.c
INJECT-SRC += $(LIBEMU)/emu_cpu_data.c
INJECT-SRC += $(LIBEMU)/emu_memory.c
INJECT-SRC += $(LIBEMU)/emu_getpc.c
INJECT-SRC += $(LIBEMU)/emu_graph.c
INJECT-SRC += $(LIBEMU)/emu_hashtable.c
INJECT-SRC += $(LIBEMU)/emu_list.c
INJECT-SRC += $(LIBEMU)/emu_log.c
INJECT-SRC += $(LIBEMU)/emu_queue.c
INJECT-SRC += $(LIBEMU)/emu_source.c
INJECT-SRC += $(LIBEMU)/emu_stack.c
INJECT-SRC += $(LIBEMU)/emu_string.c
INJECT-SRC += $(LIBEMU)/emu_track.c
INJECT-SRC += $(LIBEMU)/environment/emu_env.c
INJECT-SRC += $(LIBEMU)/environment/emu_profile.c
INJECT-SRC += $(LIBEMU)/environment/linux/emu_env_linux.c
INJECT-SRC += $(LIBEMU)/environment/linux/env_linux_syscall_hooks.c
INJECT-SRC += $(LIBEMU)/functions/aaa.c
INJECT-SRC += $(LIBEMU)/functions/adc.c
INJECT-SRC += $(LIBEMU)/functions/add.c
INJECT-SRC += $(LIBEMU)/functions/and.c
INJECT-SRC += $(LIBEMU)/functions/call.c
INJECT-SRC += $(LIBEMU)/functions/cmp.c
INJECT-SRC += $(LIBEMU)/functions/cmps.c
INJECT-SRC += $(LIBEMU)/functions/dec.c
INJECT-SRC += $(LIBEMU)/functions/div.c
INJECT-SRC += $(LIBEMU)/functions/group_1.c
INJECT-SRC += $(LIBEMU)/functions/group_2.c
INJECT-SRC += $(LIBEMU)/functions/group_3.c
INJECT-SRC += $(LIBEMU)/functions/group_4.c
INJECT-SRC += $(LIBEMU)/functions/group_5.c
INJECT-SRC += $(LIBEMU)/functions/group_10.c
INJECT-SRC += $(LIBEMU)/functions/idiv.c
INJECT-SRC += $(LIBEMU)/functions/imul.c
INJECT-SRC += $(LIBEMU)/functions/inc.c
INJECT-SRC += $(LIBEMU)/functions/int.c
INJECT-SRC += $(LIBEMU)/functions/jcc.c
INJECT-SRC += $(LIBEMU)/functions/jmp.c
INJECT-SRC += $(LIBEMU)/functions/lodscc.c
INJECT-SRC += $(LIBEMU)/functions/loopcc.c
INJECT-SRC += $(LIBEMU)/functions/misc.c
INJECT-SRC += $(LIBEMU)/functions/mov.c
INJECT-SRC += $(LIBEMU)/functions/movsx.c
INJECT-SRC += $(LIBEMU)/functions/movzx.c
INJECT-SRC += $(LIBEMU)/functions/mul.c
INJECT-SRC += $(LIBEMU)/functions/neg.c
INJECT-SRC += $(LIBEMU)/functions/not.c
INJECT-SRC += $(LIBEMU)/functions/or.c
INJECT-SRC += $(LIBEMU)/functions/pop.c
INJECT-SRC += $(LIBEMU)/functions/push.c
INJECT-SRC += $(LIBEMU)/functions/rcl.c
INJECT-SRC += $(LIBEMU)/functions/rcr.c
INJECT-SRC += $(LIBEMU)/functions/repcc.c
INJECT-SRC += $(LIBEMU)/functions/ret.c
INJECT-SRC += $(LIBEMU)/functions/rol.c
INJECT-SRC += $(LIBEMU)/functions/ror.c
INJECT-SRC += $(LIBEMU)/functions/sal.c
INJECT-SRC += $(LIBEMU)/functions/sar.c
INJECT-SRC += $(LIBEMU)/functions/sbb.c
INJECT-SRC += $(LIBEMU)/functions/scas.c
INJECT-SRC += $(LIBEMU)/functions/shr.c
INJECT-SRC += $(LIBEMU)/functions/stoscc.c
INJECT-SRC += $(LIBEMU)/functions/sub.c
INJECT-SRC += $(LIBEMU)/functions/test.c
INJECT-SRC += $(LIBEMU)/functions/xchg.c
INJECT-SRC += $(LIBEMU)/functions/xor.c
INJECT-SRC += $(LIBEMU)/libdasm.c
#INJECT-SRC += $(LIBEMU)/emu_shellcode.c
#INJECT-SRC += $(LIBEMU)/libdasm.h
#INJECT-SRC += $(LIBEMU)/opcode_tables.h
#INJECT-SRC += $(LIBEMU)/environment/win32/emu_env_w32.c
#INJECT-SRC += $(LIBEMU)/environment/win32/emu_env_w32_dll.c
#INJECT-SRC += $(LIBEMU)/environment/win32/emu_env_w32_dll_export.c
#INJECT-SRC += $(LIBEMU)/environment/win32/env_w32_dll_export_kernel32_hooks.c
#INJECT-SRC += $(LIBEMU)/environment/win32/env_w32_dll_export_urlmon_hooks.c
#INJECT-SRC += $(LIBEMU)/environment/win32/env_w32_dll_export_ws2_32_hooks.c
# --- LIBEMU ---

INJECT-OBJ += inject.o
INJECT-OBJ += gadget_searcher.o
INJECT-OBJ += emulator.o
INJECT-OBJ += shared_memory_wrapper.o
INJECT-OBJ += libemu_memory_access.o
INJECT-OBJ += disassembler_interface.o
INJECT-OBJ += auxiliary.o

INJECT-OBJ += ia32_implicit.o
INJECT-OBJ += ia32_insn.o
INJECT-OBJ += ia32_invariant.o
INJECT-OBJ += ia32_modrm.o
INJECT-OBJ += ia32_opcode_tables.o
INJECT-OBJ += ia32_operand.o
INJECT-OBJ += ia32_reg.o
INJECT-OBJ += ia32_settings.o
INJECT-OBJ += x86_disasm.o
INJECT-OBJ += x86_format.o
INJECT-OBJ += x86_imm.o
INJECT-OBJ += x86_insn.o
INJECT-OBJ += x86_misc.o
INJECT-OBJ += x86_operand_list.o
INJECT-OBJ += itab.o
INJECT-OBJ += decode.o
INJECT-OBJ += syn.o
INJECT-OBJ += syn-intel.o
INJECT-OBJ += syn-att.o
INJECT-OBJ += udis86.o

INJECT-OBJ += emu.o
INJECT-OBJ += emu_breakpoint.o
INJECT-OBJ += emu_cpu.o
INJECT-OBJ += emu_cpu_data.o
INJECT-OBJ += emu_memory.o
INJECT-OBJ += emu_getpc.o
INJECT-OBJ += emu_graph.o
INJECT-OBJ += emu_hashtable.o
INJECT-OBJ += emu_list.o
INJECT-OBJ += emu_log.o
INJECT-OBJ += emu_queue.o
INJECT-OBJ += emu_source.o
INJECT-OBJ += emu_stack.o
INJECT-OBJ += emu_string.o
INJECT-OBJ += emu_track.o
INJECT-OBJ += emu_env.o
INJECT-OBJ += emu_profile.o
INJECT-OBJ += emu_env_linux.o
INJECT-OBJ += env_linux_syscall_hooks.o
INJECT-OBJ += aaa.o
INJECT-OBJ += adc.o
INJECT-OBJ += add.o
INJECT-OBJ += and.o
INJECT-OBJ += call.o
INJECT-OBJ += cmp.o
INJECT-OBJ += cmps.o
INJECT-OBJ += dec.o
INJECT-OBJ += div.o
INJECT-OBJ += group_1.o
INJECT-OBJ += group_2.o
INJECT-OBJ += group_3.o
INJECT-OBJ += group_4.o
INJECT-OBJ += group_5.o
INJECT-OBJ += group_10.o
INJECT-OBJ += idiv.o
INJECT-OBJ += imul.o
INJECT-OBJ += inc.o
INJECT-OBJ += int.o
INJECT-OBJ += jcc.o
INJECT-OBJ += jmp.o
INJECT-OBJ += lodscc.o
INJECT-OBJ += loopcc.o
INJECT-OBJ += misc.o
INJECT-OBJ += mov.o
INJECT-OBJ += movsx.o
INJECT-OBJ += movzx.o
INJECT-OBJ += mul.o
INJECT-OBJ += neg.o
INJECT-OBJ += not.o
INJECT-OBJ += or.o
INJECT-OBJ += pop.o
INJECT-OBJ += push.o
INJECT-OBJ += rcl.o
INJECT-OBJ += rcr.o
INJECT-OBJ += repcc.o
INJECT-OBJ += ret.o
INJECT-OBJ += rol.o
INJECT-OBJ += ror.o
INJECT-OBJ += sal.o
INJECT-OBJ += sar.o
INJECT-OBJ += sbb.o
INJECT-OBJ += scas.o
INJECT-OBJ += shr.o
INJECT-OBJ += stoscc.o
INJECT-OBJ += sub.o
INJECT-OBJ += test.o
INJECT-OBJ += xchg.o
INJECT-OBJ += xor.o
INJECT-OBJ += libdasm.o
#INJECT-OBJ += emu_shellcode.o
#INJECT-OBJ += $(LIBEMU)/libdasm.h
#INJECT-OBJ += $(LIBEMU)/opcode_tables.h
#INJECT-OBJ += $(LIBEMU)/environment/win32/emu_env_w32.o
#INJECT-OBJ += $(LIBEMU)/environment/win32/emu_env_w32_dll.o
#INJECT-OBJ += $(LIBEMU)/environment/win32/emu_env_w32_dll_export.o
#INJECT-OBJ += $(LIBEMU)/environment/win32/env_w32_dll_export_kernel32_hooks.o
#INJECT-OBJ += $(LIBEMU)/environment/win32/env_w32_dll_export_urlmon_hooks.o
#INJECT-OBJ += $(LIBEMU)/environment/win32/env_w32_dll_export_ws2_32_hooks.o

INJECT_FORK-SRC += $(INJECTLIB)/inject_fork.c
INJECT_FORK-SRC += $(EMULATOR)/shared_memory_wrapper.c # BUTTERFLY EFFECT

default:
	mkdir $(BIN)
	
	$(MAKE) -C $(KDIR) M=$(KERNEL) modules	
	@mv $(KERNEL)/$(MODULE).ko $(BIN)
	
	gcc $(PROGRAM-SRC) -o $(PROGRAM) -ldl -lpcap -g
	mv $(PROGRAM) $(BIN)
	
	gcc -c -Wall -Werror -nostartfiles -fpic $(INJECT-SRC) -g
	gcc -shared -o libinject.so $(INJECT-OBJ)
	mv libinject.so $(BIN)
	rm inject.o
	
	gcc -c -Wall -D_GNU_SOURCE -Werror -nostartfiles -fpic $(INJECT_FORK-SRC) -g
	gcc -shared -o libinject_fork.so inject_fork.o shared_memory_wrapper.o -ldl
	mv libinject_fork.so $(BIN)
	rm inject_fork.o
	
	gcc $(JUNK-SRC) -o $(JUNK) -g
	mv $(JUNK) $(BIN)

clean:
	@rm -f $(BIN)/$(MODULE).ko
	@rm -f $(BIN)/$(PROGRAM)
	
	@rm -f *.o .*.cmd .*.flags *.mod.c *.order
	@rm -f .*.*.cmd *.symvers *~ *.*~
	@rm -fR .tmp*
	@rm -rf .tmp_versions
	
	@rm -f $(KERNEL)/.*.o.cmd
	@rm -f $(KERNEL)/.*.cmd
	@rm -f $(KERNEL)/*.o
	@rm -f $(KERNEL)/*.symvers
	@rm -f $(KERNEL)/*.order
	@rm -f $(KERNEL)/.*.cmd
	@rm -f $(KERNEL)/*.mod.c
	@rm -rf $(KERNEL)/.tmp_versions

	@rm -f $(ENGINE)/.*.o.cmd
	@rm -f $(ENGINE)/.*.cmd
	@rm -f $(ENGINE)/*.o
	
	@rm -f $(SRC)/*.o
	