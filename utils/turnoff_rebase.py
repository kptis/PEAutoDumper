import pefile
import os as oss

# Flag that indicates the DLL can be relocated
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
count = 0

def turn_off_dll_can_move(pe_file_path):
    try:
        # Load the PE file
        pe = pefile.PE(pe_file_path)

        # Check if the IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE flag is set
        if pe.OPTIONAL_HEADER.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE:
            print "Turning off 'DLL can move' for: {}".format(pe_file_path)
            
            # Unset the dynamic base flag
            pe.OPTIONAL_HEADER.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
            
            # Write the modified PE file back to disk
            pe.write(filename=pe_file_path)
            print "Successfully modified: {}".format(pe_file_path)
            global count 
            count +=1
        else:
            print "'DLL can move' is already off for: {}".format(pe_file_path)
            global count 
            count+=1
    except Exception as e:
        print "Error processing {}: {}".format(pe_file_path, e)

def process_pe_files(pe_file_list):
    for pe_file in oss.listdir(pe_file_list):
        pe_file = oss.path.join(pe_file_list,pe_file)
        if oss.path.isfile(pe_file):
            turn_off_dll_can_move(pe_file)
        else:
            print "File not found: {}".format(pe_file)
 
if __name__ == "__main__":
    # Path of PE files to process
    pe_folder_path = 'pefile_data'
    # Process each PE file
    for packPE_path in oss.listdir(pe_folder_path):
        if '.gitkeep' in packPE_path:
            continue
        process_pe_files(oss.path.join(pe_folder_path,packPE_path))
        
    print count
