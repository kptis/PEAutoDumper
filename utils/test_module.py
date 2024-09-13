############################################################################################################################################
##
##   _______  __   __  ___   _______  _______    ______    _______  _______  __   __  ___   ___      ______  
##  |       ||  | |  ||   | |   _   ||       |  |    _ |  |       ||  _    ||  | |  ||   | |   |    |      | 
##  |    _  ||  |_|  ||   | |  |_|  ||_     _|  |   | ||  |    ___|| |_|   ||  | |  ||   | |   |    |  _    |
##  |   |_| ||       ||   | |       |  |   |    |   |_||_ |   |___ |       ||  |_|  ||   | |   |    | | |   |
##  |    ___||_     _||   | |       |  |   |    |    __  ||    ___||  _   | |       ||   | |   |___ | |_|   |
##  |   |      |   |  |   | |   _   |  |   |    |   |  | ||   |___ | |_|   ||       ||   | |       ||       |
##  |___|      |___|  |___| |__| |__|  |___|    |___|  |_||_______||_______||_______||___| |_______||______| 
## 
##
##  ========================== Brute forcing absolute memory addresses since 2017! ==========================
##
##
##  Use this library to rebuild the import address table for a PE dumped from memory. 
##
##  WARNING! I only wrote this because I couldn't find an existing tool with python bindings. 
##  This is not a replacement for ImpREC. ImpREC will always be a better choice because it's awesome 
##  and eats malware for breakfast while shooting lasers out of it's eyes!! 
##  Only use this inferior tool if you need to do some automated reconstruction via python.
##  
##  This library must be run _on_the_host_ where the PE is being dumped and the process that the PE 
##  was dumped from must still be active. **The setup is the same as the famous ImpREC tool.
##  
##  For this library to work you will need to have a valid PE file (as a binary string). 
##  "Valid" means that the PE file must already be in its unmapped format with a valid base address. 
##  You will also need the process that the PE was dumped from to still be active.
##
##  WARNING Part 2! Currently pyIAT_Rebuild does not handle relocation : (
##
#############################################################################################################################################

import sys
import struct
import argparse
import os as p_os

# This is not cross platform! 
# How can you attach to PE process on anything but windows :)
# If you try to force this you will find some nice evil errors with winappdbg at execution time...
assert sys.platform == "win32", "This library can only be run on Windows!"

import winappdbg
from winappdbg import System, Process
from winappdbg.win32 import *

from elfesteem import pe_init

try:
    import distorm3
except ImportError as e:
    raise ImportError('''Cannot import module distorm3. 
        Pro-tip: on Windows instead of attempting to install via pip download and execute the installer from: 
            https://pypi.python.org/pypi/distorm3''')


__AUTHOR__ = '@n33r9'
__VERSION__ = 1.0



#############################################################################################################################################
#
# Functions _call_or_unc_jmp and call_scan are heavily influenced and partially copied from the volitility plugin "impscan.py"
#
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (c) 2010 - 2012 Michael Ligh <michael.ligh@mnin.org>
#
# https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/malware/impscan.py
#
#############################################################################################################################################
def _call_or_unc_jmp(op):
    """Determine if an instruction is a call or an
    unconditional jump
    @param op: a distorm3 Op object
    """
    return ((op.flowControl == 'FC_CALL' and op.mnemonic == "CALL") or  (op.flowControl == 'FC_UNC_BRANCH' and  op.mnemonic == "JMP"))


def call_scan(data_vr_address, data, start_limit=None, end_limit=None):
    """Disassemble a block of data and yield possible calls to imported functions."""
    if start_limit == None:
        start_limit = data_vr_address
    if end_limit == None:
        end_limit = data_vr_address + len(data)
    
    iat_ptrs = []
    reg_redirect = {"EAX":0x0, "EBX":0x0, "ECX":0x0, "EDX":0x0}
    mode = distorm3.Decode32Bits
    
    for op in distorm3.DecomposeGenerator(data_vr_address, data, mode):
        if not op.valid:
            continue
        
        iat_loc = None
        
        # Handle direct calls and jumps
        if _call_or_unc_jmp(op) and op.operands[0].type == 'AbsoluteMemoryAddress':
            iat_loc = (op.operands[0].disp) & 0xffffffff
        
        # Handle indirect calls through registers (for stolen bytes technique)
        elif op.mnemonic == "CALL" and op.operands[0].type == 'Register':
            iat_loc = reg_redirect[str(op.operands[0])]
        
        # Track register values for indirect calls
        elif op.mnemonic == "MOV" and op.operands[0].type == 'Register' and op.operands[1].type == 'AbsoluteMemoryAddress':
            reg_redirect[str(op.operands[0])] = op.operands[1].disp
        
        # Handle push-ret sequences (another form of obfuscated calls)
        elif op.mnemonic == "PUSH" and op.operands[0].type == 'AbsoluteMemoryAddress':
            next_op = next(distorm3.DecomposeGenerator(op.address + op.size, data[op.address - data_vr_address + op.size:], mode))
            if next_op.mnemonic == "RET":
                iat_loc = (op.operands[0].disp) & 0xffffffff
        
        if iat_loc and start_limit <= iat_loc <= end_limit and iat_loc not in iat_ptrs:
            iat_ptrs.append(iat_loc)
    
    return iat_ptrs


def _iat_candidate(op):
    """Determine if an instruction is able to reference an IAT pointer
    @param op: a distorm3 Op object
    """
    return (op.mnemonic == "CALL") or  (op.mnemonic == "JMP") or  (op.mnemonic == "MOV") or  (op.mnemonic == "PUSH") or  (op.mnemonic == "LEA")

def resolve_iat_pointers(pid, iat_ptrs):
    """Use winappdbg to resolve IAT pointers to their respective module and function names
    @param pid: process ID to connect to
    @param iat_ptrs: list of pointer addresses to be resolved
    """
    ######################################################################
    #
    # Attach to process and start using winappdbg
    #
    ######################################################################
    # Request debug privileges.
    System.request_debug_privileges()

    # Attach to process
    process = Process(pid)
    # Lookup the process modules.
    process.scan_modules()

    # imp_table[ <funct_pointer> ] = [ <module_name>, <function_name> ] 
    imp_table = {}
    for iat_ptr in iat_ptrs:
        # For each iat pointer get the function name as a label populated by winappdbg
        label = process.get_label_at_address(process.peek_dword(iat_ptr))
        module,function,offset = Process.split_label_strict(label)
        # Only add functions that have valid labels
        if function != None:
            imp_table[iat_ptr] = [module, function]

    assert len(imp_table) != 0, "Unable to find imports in code!"
    
    ######################################################################
    #
    # Because we may have missed some IAT pointers with our scanner we 
    # are going to attempt to locate the full mapped IAT directory in the 
    # section then enumerate ever pointer in the directory. And use that 
    # list instead. 
    #
    ######################################################################
    imp_table_new={}
    for iat_ptr in range(min(imp_table.keys()), max(imp_table.keys())+4, 4):
        # Resolve the requested label address.
        label = process.get_label_at_address(process.peek_dword(iat_ptr))
        module,function,offset = Process.split_label_strict(label)
        if function != None:
            imp_table_new[iat_ptr] = [module, function]
    return imp_table_new


def rebuild_iat(pid, pe_data, base_address, oep, newimpdir="newimpdir", newiat="newiat", loadfrommem=True):
    """Rebuild the import address table for the pe_data that was passed."""
    # ... (rest of the function remains unchanged)

    # Scan for potential IAT pointers
    iat_ptrs = call_scan(data_vr_addr, pdata, start_limit=base_address, end_limit=base_address+len(pe_data))
    assert len(iat_ptrs) != 0, "Unable to find IAT pointer candidates in code!"

    imp_table = resolve_iat_pointers(pid, iat_ptrs)

    # ... (rest of the function remains unchanged)

    # Patch the code section
    odata = pdata
    mode = distorm3.Decode32Bits
    
    for op in distorm3.DecomposeGenerator(data_vr_addr, pdata, mode):
        if not op.valid:
            continue
        
        if _iat_candidate(op):
            for operand in op.operands:
                test_operand = operand.disp & 0xffffffff
                if test_operand in iat_map.keys():
                    op_ptr = op.address - data_vr_addr
                    op_size = op.size
                    orig_op = odata[op_ptr:op_ptr+op_size]
                    orig_operand = struct.pack('<I', test_operand)
                    new_operand = struct.pack('<I', iat_map[test_operand])
                    new_op = orig_op.replace(orig_operand, new_operand)
                    odata = odata[:op_ptr] + new_op + odata[op_ptr+op_size:]
                    break
        
        # Handle push-ret sequences
        elif op.mnemonic == "PUSH" and op.operands[0].type == 'AbsoluteMemoryAddress':
            test_operand = op.operands[0].disp & 0xffffffff
            if test_operand in iat_map.keys():
                next_op = next(distorm3.DecomposeGenerator(op.address + op.size, pdata[op.address - data_vr_addr + op.size:], mode))
                if next_op.mnemonic == "RET":
                    op_ptr = op.address - data_vr_addr
                    op_size = op.size
                    orig_op = odata[op_ptr:op_ptr+op_size]
                    orig_operand = struct.pack('<I', test_operand)
                    new_operand = struct.pack('<I', iat_map[test_operand])
                    new_op = orig_op.replace(orig_operand, new_operand)
                    odata = odata[:op_ptr] + new_op + odata[op_ptr+op_size:]

    # ... (rest of the function remains unchanged)

def get_mem_map(process):
    """Get a memory map of process
    @param process: winappdbg.process object
    @return list: [ {'BaseAddress': <>, 'RegionSize' <>, 'State': <>, 'Protect': <>, 'Type': <> 'Owner': <> }, ... ]
    """
    # Get the process memory map
    memoryMap = process.get_memory_map()

    # For each memory block in the map...
    #mem_map = [... , {Address, Size, State, Access, Type, Owner}]
    mem_map_arr = []
    for mbi in memoryMap:
        mem_page = {}
        # Address and size of memory block.
        mem_page['BaseAddress'] = mbi.BaseAddress
        mem_page['RegionSize'] = mbi.RegionSize

        # State (free or allocated).
        if   mbi.State == MEM_RESERVE:
            mem_page['State'] = "Reserved"
        elif mbi.State == MEM_COMMIT:
            mem_page['State'] = "Commited"
        elif mbi.State == MEM_FREE:
            mem_page['State'] = "Free"
        else:
            mem_page['State'] = "Unknown"

        # Page protection bits (R/W/X/G).
        if mbi.State != MEM_COMMIT:
            mem_page['Protect'] = ""
        else:
            if   mbi.Protect & PAGE_NOACCESS:
                mem_page['Protect'] = "--- "
            elif mbi.Protect & PAGE_READONLY:
                mem_page['Protect'] = "R-- "
            elif mbi.Protect & PAGE_READWRITE:
                mem_page['Protect'] = "RW- "
            elif mbi.Protect & PAGE_WRITECOPY:
                mem_page['Protect'] = "RC- "
            elif mbi.Protect & PAGE_EXECUTE:
                mem_page['Protect'] = "--X "
            elif mbi.Protect & PAGE_EXECUTE_READ:
                mem_page['Protect'] = "R-X "
            elif mbi.Protect & PAGE_EXECUTE_READWRITE:
                mem_page['Protect'] = "RWX "
            elif mbi.Protect & PAGE_EXECUTE_WRITECOPY:
                mem_page['Protect'] = "RCX "
            else:
                mem_page['Protect'] = "??? "

            if   mbi.Protect & PAGE_GUARD:
                mem_page['Protect'] += "G"
            else:
                mem_page['Protect'] += "-"

            if   mbi.Protect & PAGE_NOCACHE:
                mem_page['Protect'] += "N"
            else:
                mem_page['Protect'] += "-"

            if   mbi.Protect & PAGE_WRITECOMBINE:
                mem_page['Protect'] += "W"
            else:
                mem_page['Protect'] += "-"

        # Type (file mapping, executable image, or private memory).
        if   mbi.Type == MEM_IMAGE:
            mem_page['Type'] = "Image"
        elif mbi.Type == MEM_MAPPED:
            mem_page['Type'] = "Mapped"
        elif mbi.Type == MEM_PRIVATE:
            mem_page['Type'] = "Private"
        elif mbi.Type == 0:
            mem_page['Type'] = "Free"
        else:
            mem_page['Type'] = "Unknown"

        # Get the page owner
        hProcess = process.get_handle( PROCESS_VM_READ | PROCESS_QUERY_INFORMATION ) 
        mem_page['Owner'] = ''
        if mbi.Type in (MEM_IMAGE, MEM_MAPPED): 
            try:
                fileName = GetMappedFileName(hProcess, mbi.BaseAddress) 
                file_path = winappdbg.PathOperations.native_to_win32_pathname(fileName)
                mem_page['Owner'] = p_os.path.basename(file_path)
            except WindowsError as e: 
                mem_page['Owner'] = "???"

        #add page info to map
        mem_map_arr.append(mem_page)
    return mem_map_arr

# use to rebuild dumped PE file 
def dump_and_rebuild_pe_based(pid, oep, orig_pe, newimpdir="MTAimpdir", newiat="MTAiat"):
    '''Dump pe-based packer process and rebuild with new original entry point.
    This function requires the original PE file in order to use the header and 
    header corrumption anti-dumping techniques.
    @param pid: process ID
    @param oep: original entry point
    @param orig_pe: binary string containing unmapped original PE file 
    @param newimpdir: name for new section that will contain imports
    @param newiat: name for new section that will contain new IAT
    '''
    System.request_debug_privileges()
    process = Process( pid )
    try:
        process.suspend()
    except WindowsError as e:
        pass
    file_path = process.get_filename()
    file_name = p_os.path.basename(file_path)

    #######################################################################
    # 
    # REBUILD THE DUMPED PE
    #
    # I'm sure there is a better way to do this because all we are really 
    # doing is dumping the PE mapped sections. Suggestions welcome!
    #
    # The crazy way we do this is to get a memory map of the whole process
    # then find the pages that are owned by the file that spawned the process.
    #
    #######################################################################
    mem_map = get_mem_map(process)

    temp_data_arr = {}
    for page in mem_map:
        if file_name.upper() in page["Owner"].upper():
            dump_data = process.peek(page["BaseAddress"],page["RegionSize"])
            temp_data_arr[page["BaseAddress"]] = dump_data
    
    # we need to work with the dump as one contiguous data block in "mapped" format.
    ordered_mem = temp_data_arr.keys()
    ordered_mem.sort()
    block_data = temp_data_arr[ordered_mem[0]]
    for addr_ptr in range(1,len(ordered_mem)):
        padding_len  = ordered_mem[addr_ptr] - (ordered_mem[0] + len(block_data))
        #print "Padding: %d" % padding_len
        # These should be contiguous pages so there should be no need for padding!
        block_data += temp_data_arr[ordered_mem[addr_ptr]] + '\x00'*padding_len

    # The lowest mapped section is the base address
    base_address = ordered_mem[0]

    # Elfesteem has a small issue with the way it loads mapped PE files
    # instead of using the virtual size for segments it uses the raw size
    # this messes up unpacker dumps so we will fix it manually. 

    pf = pe_init.PE(loadfrommem=False, pestr=orig_pe)
    new_sections = []
    for tmp_section in pf.SHList:
         new_sections.append({"name": tmp_section.name ,"offset": tmp_section.addr ,"size": tmp_section.size ,"addr": tmp_section.addr ,"flags": tmp_section.flags ,"rawsize": tmp_section.size})

    # Remove existing sections
    pf.SHList.shlist=[]
    
    for tmp_section in new_sections:
        pf.SHList.add_section(name=tmp_section["name"], 
            data=block_data[tmp_section["offset"]:tmp_section["offset"] + tmp_section["rawsize"]], 
            size=tmp_section["size"], 
            addr=tmp_section["addr"], 
            offset=tmp_section["offset"], 
            rawsize=tmp_section["rawsize"])

    pf.NThdr.ImageBase = base_address
    pf.Opthdr.AddressOfEntryPoint = oep
    # Disable rebase, since addresses are absolute any rebase will make this explode
    pf.NThdr.dllcharacteristics = 0x0

    # Null out the imports they will be wrong anyway and may cause issues when importing into elfesteem
    try:
        pf.DirImport.impdesc.l=[]
    except:
        pf.DirImport.impdesc =[]

    #######################################################################
    # 
    # At this point pf contains a fully reconstructed PE but with a 
    # broken IAT. Fix the IAT!
    #
    #######################################################################
    return rebuild_iat(pid, str(pf), base_address, oep, newimpdir=newimpdir, newiat=newiat, loadfrommem=False)

# use for cmdline interface, using full addr of OEP 
# to dump file PE and rebuild IAT
def dump_and_rebuild(pid, oep, newimpdir="MTAimpdir", newiat="MTAiat"):
    '''Dump process and rebuild with new original entry point.
    @param pid: process ID
    @param oep: original entry point
    @param newimpdir: name for new section that will contain imports
    @param newiat: name for new section that will contain new IAT
    '''
    System.request_debug_privileges()
    process = Process( pid )
    try:
        process.suspend()
    except WindowsError as e:
        pass
    file_path = process.get_filename()
    file_name = p_os.path.basename(file_path)

    #######################################################################
    # 
    # REBUILD THE DUMPED PE
    #
    # I'm sure there is a better way to do this because all we are really 
    # doing is dumping the PE mapped sections. Suggestions welcome!
    #
    # The crazy way we do this is to get a memory map of the whole process
    # then find the pages that are owned by the file that spawned the process.
    #
    #######################################################################
    mem_map = get_mem_map(process)

    temp_data_arr = {}
    for page in mem_map:
        if file_name.upper() in page["Owner"].upper():
            dump_data = process.peek(page["BaseAddress"],page["RegionSize"])
            temp_data_arr[page["BaseAddress"]] = dump_data
    
    # we need to work with the dump as one contiguous data block in "mapped" format.
    ordered_mem = temp_data_arr.keys()
    ordered_mem.sort()
    block_data = temp_data_arr[ordered_mem[0]]
    for addr_ptr in range(1,len(ordered_mem)):
        padding_len  = ordered_mem[addr_ptr] - (ordered_mem[0] + len(block_data))
        #print "Padding: %d" % padding_len
        # These should be contiguous pages so there should be no need for padding!
        block_data += temp_data_arr[ordered_mem[addr_ptr]] + '\x00'*padding_len

    # The lowest mapped section is the base address
    base_address = ordered_mem[0]

    # Elfesteem has a small issue with the way it loads mapped PE files
    # instead of using the virtual size for segments it uses the raw size
    # this messes up unpacker dumps so we will fix it manually. 

    pf = pe_init.PE(loadfrommem=True, pestr=block_data)
    new_sections = []
    for tmp_section in pf.SHList:
         new_sections.append({"name": tmp_section.name ,"offset": tmp_section.addr ,"size": tmp_section.size ,"addr": tmp_section.addr ,"flags": tmp_section.flags ,"rawsize": tmp_section.size})

    # Remove existing sections
    pf.SHList.shlist=[]
    
    for tmp_section in new_sections:
        pf.SHList.add_section(name=tmp_section["name"], 
            data=block_data[tmp_section["offset"]:tmp_section["offset"] + tmp_section["rawsize"]], 
            size=tmp_section["size"], 
            addr=tmp_section["addr"], 
            offset=tmp_section["offset"], 
            rawsize=tmp_section["rawsize"])

    pf.NThdr.ImageBase = base_address
    # print "type base_address: %s" % type(base_address)
    # print "Base_address: 0x%s" % hex(base_address)
    pf.Opthdr.AddressOfEntryPoint = oep
    # Disable rebase, since addresses are absolute any rebase will make this explode
    pf.NThdr.dllcharacteristics = 0x0
    #  turn off the dll character: dll can move 

    #######################################################################
    # 
    # At this point pf contains a fully reconstructed PE but with a 
    # broken IAT. Fix the IAT!
    #
    #######################################################################
    return rebuild_iat(pid, str(pf), base_address, oep, newimpdir=newimpdir, newiat=newiat, loadfrommem=False)

from collections import OrderedDict
from itertools import chain
from functools import partial

def dump_and_rebuild_script_auto(pid, oep_offset, newimpdir="MTAimpdir", newiat="MTAiat"):
    '''Dump process and rebuild with new original entry point.'''
    System.request_debug_privileges()
    process = Process(pid)
    try:
        process.suspend()
    except WindowsError:
        pass
    
    file_name = p_os.path.basename(process.get_filename()).upper()

    mem_map = get_mem_map(process)

    # Use OrderedDict to maintain order
    temp_data_arr = OrderedDict()
    peek = partial(process.peek)  # Create a partial function for process.peek
    
    # Use list comprehension
    temp_data_arr = OrderedDict(
        (page["BaseAddress"], peek(page["BaseAddress"], page["RegionSize"]))
        for page in mem_map if file_name in page["Owner"].upper()
    )

    # The lowest mapped section is the base address
    ordered_mem = sorted(temp_data_arr.keys())
    base_address = ordered_mem[0]
    
    # Elfesteem has a small issue with the way it loads mapped PE files
    # instead of using the virtual size for segments it uses the raw size
    # this messes up unpacker dumps so we will fix it manually. 

    # Use itertools.chain to concatenate data efficiently
    block_data = ''.join(chain(
        [temp_data_arr[ordered_mem[0]]],
        (temp_data_arr[addr] + '\x00' * (addr - (ordered_mem[0] + len(temp_data_arr[ordered_mem[0]])))
         for addr in ordered_mem[1:])
    ))

    pf = pe_init.PE(loadfrommem=True, pestr=block_data)
    
    # Use list comprehension for new_sections
    new_sections = [
        {
            "name": section.name,
            "offset": section.addr,
            "size": section.size,
            "addr": section.addr,
            "flags": section.flags,
            "rawsize": section.size
        }
        for section in pf.SHList
    ]

    pf.SHList.shlist = []
    
    # Use a list comprehension with map to add sections
    list(map(
        lambda s: pf.SHList.add_section(
            name=s["name"],
            data=block_data[s["offset"]:s["offset"] + s["rawsize"]],
            size=s["size"],
            addr=s["addr"],
            offset=s["offset"],
            rawsize=s["rawsize"]
        ),
        new_sections
    ))

    pf.NThdr.ImageBase = base_address
    # print "type base_address: %s" % type(base_address)
    # print "Base_address: 0x%s" % hex(base_address)
    oep = oep_offset + base_address
    pf.Opthdr.AddressOfEntryPoint = oep
    # Disable rebase, since addresses are absolute any rebase will make this explode
    pf.NThdr.dllcharacteristics = 0x0

