import os as os
import shutil

# Define the source and destination folders
source_folder = "pefile_data"
destination_folder = "pefile_data2"
folder_pefile_test_path = "list_pefile_test" 

# List of packer names (example)
packer_names = ['aspack', 'fsg', 'jdpack', 'mew', 'mpress', 'packman', 'pecompact', 'petitepacked', 'telock', 'upx', 'winupack', 'yodaC']
dict1 = {
    'aspack': 'ASPack',
    'fsg': 'FSG',
    'jdpack': 'JDPack',
    'mew': 'MEW',
    'MPRESS': 'MPRESS',
    'packman': 'Packman',
    'pecompact': 'PECompact',
    'petitepacked': 'PEtite',
    'telock': 'TELock',
    'upx': 'UPX',
    'winupack': 'WinUpack',
    'yodaC': 'Yoda-Crypter'
}
# # Create a dictionary where the key is lowercase and the value is capitalized
# packer_dict = {name.lower(): name.capitalize() for name in packer_names}
# # Print the resulting dictionary
# print(packer_dict)

count = 0
def copy_files(file_list_path):
    # Get the packer name from the text file name (without extension)
    packer_name = os.path.splitext(os.path.basename(file_list_path))[0]
    
    # Create the destination folder if it doesn't exist
    destination_packer_folder = os.path.join(destination_folder, dict1[packer_name])
    if not os.path.exists(destination_packer_folder):
        os.makedirs(destination_packer_folder)
    
    # Read the file that contains the list of executables
    with open(file_list_path, 'r') as file:
        for line in file:
            file_name = line.strip()  # Remove any surrounding spaces or newlines
            source_file_path = os.path.join(source_folder, dict1[packer_name], file_name)
            destination_file_path = os.path.join(destination_packer_folder, file_name)

            # Check if the source file exists before copying
            if os.path.exists(source_file_path):
                shutil.copy(source_file_path, destination_file_path)
                print "Copied: %s to %s" % (source_file_path, destination_file_path)
                global count
                count += 1
            else:
                print "File not found: %s" %source_file_path

# Call the function for the '{packername}.txt' file
# file_list_path

for filepath in os.listdir(folder_pefile_test_path):
    copy_files(os.path.join(folder_pefile_test_path, filepath))
    
print count 