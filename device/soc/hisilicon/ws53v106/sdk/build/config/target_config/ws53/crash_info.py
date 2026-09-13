import struct
import sys
import os

path = sys.argv[1:]

bin_path = "./crashinfo.bin"
format_path  = "./crashinfo.txt"
if len(path) >= 1:
    for i in path:
        if i.endswith("bin") and os.path.isfile(i):
            bin_path = i
        elif i.endswith("txt"):
            format_path = i
        else:
            print("invalid parameter: ", i)
txt_path = "./crashinfo_bin.txt"
ret = []

def exc_info_get_phase(phase):
    str = {
        0 : "Init",
        1 : "Task",
        2 : "Irq",
        3 : "Exc"
    }
    return str.get(phase, None)

if __name__ == "__main__":
    with open(bin_path, 'rb') as file:
        data = file.read()
        for byte in data:
            ret.append(f"{byte:02x}")

    with open(txt_path,'w') as file:
        line_index = 0
        for byte in ret:
            file.write(byte)
            line_index += 1
            if line_index >= 16 :
                file.write('\n')
                line_index = 0
            else:
                file.write(' ')

    file = open(bin_path, "rb")
    with open(format_path,'w') as write_file:
        file.seek(4,1)

        flag = struct.unpack('<I', file.read(4))[0]
        write_file.write(f"{hex(flag)}" + '\n')

        # TASK NAME
        task_name_len = struct.unpack('<I', file.read(4))[0]    
        write_file.write('task_name:')
        for i in range(task_name_len):
            char = struct.unpack('<c', file.read(1))[0]
            write_file.write(str(char)[2])
        write_file.write('\n')
        file.seek(1,1)

        # EXC INFO
        write_file.write('==== EXC INFO ====\n')
        exc_info_phase = struct.unpack('<H', file.read(2))[0]
        write_file.write('phase:' + exc_info_get_phase(exc_info_phase) + '\n')
        exc_info_type = struct.unpack('<H', file.read(2))[0]
        write_file.write('type:' + f"{hex(exc_info_type)}" + '\n')
        exc_info_faultAddr = struct.unpack('I', file.read(4))[0]
        write_file.write('faultAddr:' + f"{hex(exc_info_faultAddr)}" + '\n')
        exc_info_thrdPid = struct.unpack('<I', file.read(4)[0:4])[0]
        write_file.write('thrdPid:' + f"{hex(exc_info_thrdPid)}" + '\n')
        exc_info_nestCnt = struct.unpack('<H', file.read(2))[0]
        write_file.write('nestCnt:' + f"{hex(exc_info_nestCnt)}" + '\n')
        exc_info_reserved = struct.unpack('<H', file.read(2))[0]
        write_file.write('reserved:' + f"{hex(exc_info_reserved)}" + '\n')
        exc_info_context = struct.unpack('<I', file.read(4))[0]
        write_file.write('context:' + f"{hex(exc_info_context)}" + '\n')

        # EXC CONTEXT
        write_file.write('==== EXC CONTEXT INFO ====\n')
        exc_context_ccause = struct.unpack('<I', file.read(4))[0]
        write_file.write('ccause:' + f"{hex(exc_context_ccause)}" + '\n')
        exc_context_mcause = struct.unpack('<I', file.read(4))[0]
        write_file.write('mcause:' + f"{hex(exc_context_mcause)}" + '\n')
        exc_context_mtval = struct.unpack('<I', file.read(4))[0]
        write_file.write('mtval:' + f"{hex(exc_context_mtval)}" + '\n')
        exc_context_gp = struct.unpack('<I', file.read(4))[0]
        write_file.write('gp:' + f"{hex(exc_context_gp)}" + '\n')
        # EXC TASK CONTEXT
        exc_task_context_mstatus = struct.unpack('<I', file.read(4))[0]
        exc_task_context_mepc = struct.unpack('<I', file.read(4))[0]
        exc_task_context_tp = struct.unpack('<I', file.read(4))[0]
        exc_task_context_sp = struct.unpack('<I', file.read(4))[0]
        exc_task_context_s11 = struct.unpack('<I', file.read(4))[0]
        exc_task_context_s10 = struct.unpack('<I', file.read(4))[0]
        exc_task_context_s9 = struct.unpack('<I', file.read(4))[0]
        exc_task_context_s8 = struct.unpack('<I', file.read(4))[0]
        exc_task_context_s7 = struct.unpack('<I', file.read(4))[0]
        exc_task_context_s6 = struct.unpack('<I', file.read(4))[0]
        exc_task_context_s5 = struct.unpack('<I', file.read(4))[0]
        exc_task_context_s4 = struct.unpack('<I', file.read(4))[0]
        exc_task_context_s3 = struct.unpack('<I', file.read(4))[0]
        exc_task_context_s2 = struct.unpack('<I', file.read(4))[0]
        exc_task_context_s1 = struct.unpack('<I', file.read(4))[0]
        exc_task_context_s0 = struct.unpack('<I', file.read(4))[0]
        exc_task_context_t6 = struct.unpack('<I', file.read(4))[0]
        exc_task_context_t5 = struct.unpack('<I', file.read(4))[0]
        exc_task_context_t4 = struct.unpack('<I', file.read(4))[0]
        exc_task_context_t3 = struct.unpack('<I', file.read(4))[0]
        exc_task_context_a7 = struct.unpack('<I', file.read(4))[0]
        exc_task_context_a6 = struct.unpack('<I', file.read(4))[0]
        exc_task_context_a5 = struct.unpack('<I', file.read(4))[0]
        exc_task_context_a4 = struct.unpack('<I', file.read(4))[0]
        exc_task_context_a3 = struct.unpack('<I', file.read(4))[0]
        exc_task_context_a2 = struct.unpack('<I', file.read(4))[0]
        exc_task_context_a1 = struct.unpack('<I', file.read(4))[0]
        exc_task_context_a0 = struct.unpack('<I', file.read(4))[0]
        exc_task_context_t2 = struct.unpack('<I', file.read(4))[0]
        exc_task_context_t1 = struct.unpack('<I', file.read(4))[0]
        exc_task_context_t0 = struct.unpack('<I', file.read(4))[0]
        exc_task_context_ra = struct.unpack('<I', file.read(4))[0]
        write_file.write('mstatus:' + f"{hex(exc_task_context_mstatus)}" + '\n')
        write_file.write('mepc:' + f"{hex(exc_task_context_mepc)}" + '\n')
        write_file.write('ra:' + f"{hex(exc_task_context_ra)}" + '\n')
        write_file.write('sp:' + f"{hex(exc_task_context_sp)}" + '\n')
        write_file.write('tp:' + f"{hex(exc_task_context_tp)}" + '\n')
        write_file.write('t0:' + f"{hex(exc_task_context_t0)}" + '\n')
        write_file.write('t1:' + f"{hex(exc_task_context_t1)}" + '\n')
        write_file.write('t2:' + f"{hex(exc_task_context_t2)}" + '\n')
        write_file.write('s0:' + f"{hex(exc_task_context_s0)}" + '\n')
        write_file.write('s1:' + f"{hex(exc_task_context_s1)}" + '\n')
        write_file.write('a0:' + f"{hex(exc_task_context_a0)}" + '\n')
        write_file.write('a1:' + f"{hex(exc_task_context_a1)}" + '\n')
        write_file.write('a2:' + f"{hex(exc_task_context_a2)}" + '\n')
        write_file.write('a3:' + f"{hex(exc_task_context_a3)}" + '\n')
        write_file.write('a4:' + f"{hex(exc_task_context_a4)}" + '\n')
        write_file.write('a5:' + f"{hex(exc_task_context_a5)}" + '\n')
        write_file.write('a6:' + f"{hex(exc_task_context_a6)}" + '\n')
        write_file.write('a7:' + f"{hex(exc_task_context_a7)}" + '\n')
        write_file.write('s2:' + f"{hex(exc_task_context_s2)}" + '\n')
        write_file.write('s3:' + f"{hex(exc_task_context_s3)}" + '\n')
        write_file.write('s4:' + f"{hex(exc_task_context_s4)}" + '\n')
        write_file.write('s5:' + f"{hex(exc_task_context_s5)}" + '\n')
        write_file.write('s6:' + f"{hex(exc_task_context_s6)}" + '\n')
        write_file.write('s7:' + f"{hex(exc_task_context_s7)}" + '\n')
        write_file.write('s8:' + f"{hex(exc_task_context_s8)}" + '\n')
        write_file.write('s9:' + f"{hex(exc_task_context_s9)}" + '\n')
        write_file.write('s10:' + f"{hex(exc_task_context_s10)}" + '\n')
        write_file.write('s11:' + f"{hex(exc_task_context_s11)}" + '\n')
        write_file.write('t3:' + f"{hex(exc_task_context_t3)}" + '\n')
        write_file.write('t4:' + f"{hex(exc_task_context_t4)}" + '\n')
        write_file.write('t5:' + f"{hex(exc_task_context_t5)}" + '\n')
        write_file.write('t6:' + f"{hex(exc_task_context_t6)}" + '\n')

        # EXCPTS VALUE
        excpts_val = struct.unpack('<I', file.read(4))[0]
        write_file.write('cxcptsc :' + f"{hex(excpts_val)}" + '\n')

        # BACKTRACE INFO
        write_file.write('==== BACKTRACE INFO ====\n')
        backtrace_count = struct.unpack('<I', file.read(4))[0]
        write_file.write('backtrace count:' + f"{str(backtrace_count)}" + '\n')
        for i in range(backtrace_count):
            backtrace_sp = struct.unpack('<I', file.read(4))[0]
            backtrace_sp_content = struct.unpack('<I', file.read(4))[0]
            write_file.write('sp addr : ' + f"{hex(backtrace_sp)}" + ' , sp content : ' + f"{hex(backtrace_sp_content)}" + '\n')
        move_size = 80 - backtrace_count * 8
        file.seek(move_size,1)

        # MCPU TRACE
        cpu_trace_len1 = struct.unpack('<I', file.read(4))[0]
        cpu_trace_start_addr1 = struct.unpack('<I', file.read(4))[0]
        write_file.write('acore_cpu_trace_print: ')
        write_file.write('addr:' + f"{hex(cpu_trace_start_addr1)}" + ' - ')
        write_file.write(f"{hex(cpu_trace_start_addr1 + cpu_trace_len1)}" + ', ')
        write_file.write('len:' + f"{str(cpu_trace_len1)}" + ', ')
        write_file.write('sample_done_addr:' + f"{hex(0)}" + '\n')
        for i in range(cpu_trace_len1 // 12):
            item_time1 = struct.unpack('<I', file.read(4))[0]
            item_lr1 = struct.unpack('<I', file.read(4))[0]
            item_pc1 = struct.unpack('<I', file.read(4))[0]
            write_file.write('acore_cpu_trace ' + f"{str(i)}" + ' --- ')
            write_file.write('addr ' + f"{hex(cpu_trace_start_addr1 + i * 12)}" + ', ')
            write_file.write('time: ' + f"{hex(item_time1)}" + ', ')
            write_file.write('LR: ' + f"{hex(item_lr1)}" + ', ')
            write_file.write('PC: ' + f"{hex(item_pc1)}" + '.\n')
        write_file.write('=================before low power suspend data==================.\n')
        cpu_trace_len2 = struct.unpack('<I', file.read(4))[0]
        cpu_trace_start_addr2 = struct.unpack('<I', file.read(4))[0]
        write_file.write('acore_cpu_trace_print: ')
        write_file.write('addr:' + f"{hex(cpu_trace_start_addr2)}" + ' - ')
        write_file.write(f"{hex(cpu_trace_start_addr2 + cpu_trace_len2)}" + ', ')
        write_file.write('len:' + f"{str(cpu_trace_len2)}" + ', ')
        write_file.write('sample_done_addr:' + f"{hex(0)}" + '\n')
        for i in range(cpu_trace_len2 // 12):
            item_time2 = struct.unpack('<I', file.read(4))[0]
            item_lr2 = struct.unpack('<I', file.read(4))[0]
            item_pc2= struct.unpack('<I', file.read(4))[0]
            write_file.write('acore_cpu_trace ' + f"{str(i)}" + ' --- ')
            write_file.write('addr ' + f"{hex(cpu_trace_start_addr2 + i * 12)}" + ', ')
            write_file.write('time: ' + f"{hex(item_time2)}" + ', ')
            write_file.write('LR: ' + f"{hex(item_lr2)}" + ', ')
            write_file.write('PC: ' + f"{hex(item_pc2)}" + '.\n')
    print('crash info resolve done')