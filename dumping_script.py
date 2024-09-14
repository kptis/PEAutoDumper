# from pyiatrebuild import *
from MTA_dump_rebuild import *
# from pathlib import Path
import logging
import os as oss
import signal
import pefile
import subprocess
import psutil
import datetime 
pe_dir = 'pefile_data'
# phan loai theo packer name 
#  each item = packer name
list_data_dir = oss.listdir(pe_dir)
# for directory in list_data_dir:
#     print directory

oep_data_dir = 'oep_data'
list_file_oep = oss.listdir(oep_data_dir)

# Create a 'logs' directory if it doesn't exist
if not os.path.exists('logs'):
    os.makedirs('logs)
# log_file_path ='log_dumping_script.txt'
# Configure logging
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
handler = RotatingFileHandler('logs/dumping_script_%s.log' % timestamp, maxBytes=10000000, backupCount=5)
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[
                        handler,
                        logging.StreamHandler()
                    ])

logger = logging.getLogger(__name__)
# default_base_addr = 0x400000
# def get_default_base_addr(pe_file):
    # base_addr =  0x0
    # processing to get default base addr 
    # try:
        # with open(pe_file, "rb") as file:
            # file.seek(0x94)
            # unpack -> unsigned int 4 bytes, little endian 
            # Imagebase = struct.unpack('<I',file.read(4))
            # print "Imagebase: 0x%x" % Imagebase[0]
            # return Imagebase[0]
    # except Exception as e:
        # print "Error: %s" % e
        # return None
# get_default_base_addr('pefile_data\\FSG\\fsg_DTCPing.exe')

def get_default_base_addr(pe_file):
    try:
        pe = pefile.PE(pe_file)
        base_addr = pe.OPTIONAL_HEADER.ImageBase
        # print "ImageBase: 0x%x" % base_addr
        return base_addr
    except Exception as e:
        print "Error: %s" %e
        return None

def get_OEP_data(filename, packer_dir):
    oep_filepath = ''
    for f in list_file_oep:
        if packer_dir.lower() in f.lower():
            oep_filepath = oss.path.join(oep_data_dir, f)
            break
    if not oep_filepath:
        error_message = "Error: OEP file not found for %s" % packer_dir
        logger.error(error_message)
        return None    
    # Get the base address
    base_address = get_default_base_addr(filename)
    if base_address is None:
        error_message = "Error: Could not get base address for %s" % filename
        logger.error(error_message)
        return None   
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
                        # Remove the 'a' and get the rest
                        oep_offset = int(oep_part[1:], 16)  - get_default_base_addr(filename)
                        message = "RVA OEP data: 0x%x" %  oep_offset
                        print message
                        logger.info(message)
                        return  oep_offset
    error_message = "OEP data not found for %s" % filename
    logger.error(error_message)
    return None   
# print "OEP: 0x%x" % get_OEP_data('aspack_efsdump.exe', 'ASPack')

# def dump_and_rebuild(pid, oep, newimpdir="newimpdir", newiat="newiat"):
def get_pid(pe_file):
    # print pe_file
    command = pe_file
    process = subprocess.Popen(command, shell=False)
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

dump_folder_path = 'dump_data_2'
def process_all_pe_files(directory):
    if not oss.path.exists(dump_folder_path):
        oss.makedirs(dump_folder_path)
    for packer_dir in oss.listdir(directory): # duyet tat ca folder packed file phan loai theo packer 
        if packer_dir == '.gitkeep':
            continue  
        log_message = "Packer: %s" % packer_dir
        print log_message
        logger.info(log_message)
        packer_dir_path = oss.path.join(directory,packer_dir)
        for file in oss.listdir(packer_dir_path): #duyet tat ca cac file bi packed trong tung folder
            file_path = oss.path.join(packer_dir_path, file)
            if is_pe(file_path):  # check PE32 
                process = None
                try:
                    log_message = "Processing file: %s" % file_path
                    print log_message
                    logger.info(log_message)
                    dump_file_path = oss.path.join(dump_folder_path, file.split('.')[0] + '.dmp.exe')
                    oep_offset = get_OEP_data(file_path, packer_dir)
                    process = subprocess.Popen(file_path, shell=False)
                    pid = process.pid
                    if oep_offset is not None and pid is not None:
                        pe_dump_data = dump_and_rebuild_script_auto(pid, oep_offset)
                        with open(dump_file_path, 'wb') as f:
                            f.write(pe_dump_data)
                        logger.info("!!!Successfully processing file: %s" % file_path)
                except Exception as e:
                    error_message = "Failed to process %s: %s" % (file_path, str(e))
                    print error_message
                    logger.error(error_message)
                finally:
                    if process:
                        try:
                            parent = psutil.Process(process.pid)
                            for child in parent.children(recursive=True):
                                child.terminate()
                            parent.terminate()
                            parent.wait(timeout=5)
                        except psutil.NoSuchProcess:
                            pass
                        except psutil.TimeoutExpired:
                            parent.kill()
            # subprocess.Process(pid).terminate()
            # Process(pid).kill()
            

if __name__ == '__main__':
    process_all_pe_files('pefile_data')