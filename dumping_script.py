from pyiatrebuild import *
# from pathlib import Path

import os as oss
import signal
import pefile
import subprocess

pe_dir = 'pefile_data'
# phan loai theo packer name 
#  each item = packer name
list_data_dir = oss.listdir(pe_dir)
# for directory in list_data_dir:
#     print directory

oep_data_dir = 'oep_data'
list_file_oep = oss.listdir(oep_data_dir)

# default_base_addr = 0x400000
def get_default_base_addr(pe_file):
    base_addr =  0x0
    # processing to get default base addr 
    try:
        with open(pe_file, "rb") as file:
            file.seek(0x94)
            # unpack -> unsigned int 4 bytes, little endian 
            Imagebase = struct.unpack('<I',(file.read(4)))
            print "Imagebase: 0x%x" % Imagebase[0]
            return hex(Imagebase[0])
    except Exception as e:
        print "Error: %s" % e
        return None
# get_default_base_addr('pefile_data\\FSG\\fsg_DTCPing.exe')

def get_OEP_data(filename, packer_dir):
    oep_filepath = ''
    for f in list_file_oep:
        if packer_dir.lower() in f.lower():
            oep_filepath = oss.path.join(oep_data_dir, f)
            break
    # continue here
    with open (oep_filepath, 'r') as f: 
        for line in f:
            if line.startswith(filename.split('\\')[2]):
                parts = line.split(',')
                #    aspack_efsdump.exe,a0x00402138pushl_ebp
                #    aspack_sync.exe,a0x004049fecall_0x0040a3a4
                #    aspack_dfrgui.exe,None
                if len(parts) > 1 and parts[1] != "None":
                    oep_part = parts[1].split('call')[0].split('pushl')[0].strip()
                    if oep_part.startswith('a'):
                        oep_hex = oep_part[1:]  # Remove the 'a' and get the rest
                        print int(oep_hex, 16)
                        return int(oep_hex, 16)  # Convert to hexadecimal
    return None

# print "OEP: 0x%x" % get_OEP_data('aspack_efsdump.exe', 'ASPack')

# def dump_and_rebuild(pid, oep, newimpdir="newimpdir", newiat="newiat"):
def get_pid(pe_file):
    print pe_file
    command = pe_file
    process = subprocess.Popen(command)
    return process.pid

# print "pid: %d" % get_pid(('pefile_data\\FSG\\fsg_DTCPing.exe'))
    
def is_pe(pe_file):
    try:
        with open(pe_file, "rb") as file:
            # Read the first two bytes of the file
            magic_number = file.read(2)
            # Check if the magic number is 'MZ'
            if magic_number == b'MZ':
                # Read the DOS Header to get the PE header offset
                file.seek(0x3C) # e_lfanew offset (its value = PE header location)
                pe_header_offset = struct.unpack('<H', file.read(2))[0]
                file.seek(pe_header_offset + 0x18)  # PE Header starts at e_lfanew, +0x18 is where the Optional Header starts
                #  read the value: 0x10B --> PE32, 0x20B --> PE64
                magic_value = struct.unpack('<H',(file.read(2)))[0]
                # unpack -> unsigned short 2 bytes, little endian 
                # print "Magic value: 0x%x" % (magic_value[0])          
                # Check if the PE32 or not 
                if magic_value == 0x10b: 
                    # print "True PE32"
                    return True
        return False
    except Exception as e:
        print "Error: %s" % e
        return False

# print "Check PE file: %s" % is_pe('pefile_data\\FSG\\fsg_DTCPing.exe')

dump_folder_path = 'dump_data'
def process_all_pe_files(directory):
    if not oss.path.exists(dump_folder_path):
        oss.makedirs(dump_folder_path)
    for packer_dir in oss.listdir(directory): # duyet tat ca folder packed file phan loai theo packer 
        print "Packer: %s" %packer_dir
        packer_dir_path = oss.path.join(directory,packer_dir)
        for file in oss.listdir(packer_dir_path): #duyet tat ca cac file bi packed trong tung folder
            file_path = oss.path.join(packer_dir_path, file)
            if is_pe(file_path):  # check PE32 
                try:
                    print "[+] Processing file: %s" % (file_path)
                    dump_file_path = oss.path.join(dump_folder_path, file.split('.')[0] + '.dmp')
                    oep = get_OEP_data(file_path, packer_dir)
                    pid = get_pid(file_path)
                    if oep!= None and pid!= None: 
                        pe_dump_data=dump_and_rebuild(pid, oep)
                        # ghi file dump vao folder dump rieng
                        open (dump_file_path, 'wb').write(pe_dump_data)
                    subprocess.Process(pid).kill()
                    # oss.kill(pid, signal.SIGTERM)
                except Exception as e:
                    print "Failed to process %s: %s\n" %  (file_path, e)
            # subprocess.Process(pid).terminate()
            # Process(pid).kill()
            

if __name__ == '__main__':
    process_all_pe_files('pefile_data')
    
    
