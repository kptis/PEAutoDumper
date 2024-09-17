import os as oss
import subprocess
import shutil
import time
import pefile
import psutil
import struct

pe_dir = 'pefile_data'             # Directory containing PE files organized by packer
oep_data_dir = 'oep_data'          # Directory containing OEP data
dump_folder_path = 'dump_data_3'   # Directory to store dumped files
real_pe_data_dir = 'real_PE_data'  # Directory to store successfully running PE files
successful_files_count = {}        # Dictionary to keep track of successful files per packer

def is_pe(pe_file):
    try:
        with open(pe_file, "rb") as file:
            # Read the first two bytes of the file
            magic_number = file.read(2)
            # Check if the magic number is 'MZ'
            if magic_number == b'MZ' or magic_number == 'MZ':
                # Read the DOS Header to get the PE header offset
                file.seek(0x3C)  # e_lfanew offset (its value = PE header location)
                pe_header_offset = struct.unpack('<I', file.read(4))[0]
                file.seek(pe_header_offset + 0x18)  # PE Header starts at e_lfanew, +0x18 is where the Optional Header starts
                # Read the value: 0x10B --> PE32, 0x20B --> PE64
                magic_value = struct.unpack('<H', file.read(2))[0]
                # Check if it's PE32
                if magic_value == 0x10B:
                    return True
        return False
    except Exception as e:
        print "Error: %s" % e
        return False

def check_pe_file_run(pe_file_path):
    try:
        process = subprocess.Popen([pe_file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(5)
        if process.poll() is None:
            process.terminate()
            return True
        else:
            exit_code = process.returncode
            if exit_code == 0:
                return True
            else:
                return False
    except Exception as e:
        print "An error occurred while trying to execute the PE file %s: %s" % (pe_file_path, e)
        return False

def process_pe_files():
    if not oss.path.exists(real_pe_data_dir):
        oss.makedirs(real_pe_data_dir)
    
    for packer_dir in oss.listdir(pe_dir):
        if packer_dir == '.gitkeep':
            continue
        packer_dir_path = oss.path.join(pe_dir, packer_dir)
        print "Processing packer: %s" % packer_dir
        for file in oss.listdir(packer_dir_path):
            file_path = oss.path.join(packer_dir_path, file)
            if is_pe(file_path):
                print "Processing file: %s" % file_path
                # Check if the PE file runs successfully
                if check_pe_file_run(file_path):
                    # Copy the file to real_PE_data/<nameofpacker>
                    dest_dir = oss.path.join(real_pe_data_dir, packer_dir)
                    if not oss.path.exists(dest_dir):
                        oss.makedirs(dest_dir)
                    dest_file_name = packer_dir + '_' + oss.path.basename(file)
                    dest_file_path = oss.path.join(dest_dir, dest_file_name)
                    shutil.copyfile(file_path, dest_file_path)
                    print "Copied successful file to: %s" % dest_file_path
                    # Update the count of successful files
                    if packer_dir in successful_files_count:
                        successful_files_count[packer_dir] += 1
                    else:
                        successful_files_count[packer_dir] = 1
                else:
                    print "File did not run successfully: %s" % file_path
            else:
                print "File is not a valid PE file: %s" % file_path
    
    # Print out the number of successful files per packer
    print "\nNumber of successfully running files per packer:"
    total = 0
    for packer, count in successful_files_count.items():
        print "Packer: {0}, Successful Files: {1}".format(packer, count)
        total += count
    print "total: {0}".format(total)
if __name__ == '__main__':
    process_pe_files()