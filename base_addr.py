import psutil

def get_base_address(process_name):
    for proc in psutil.process_iter(['pid', 'name', 'memory_maps']):
        if proc.info['name'] == process_name:
            for entry in proc.info['memory_maps']:
                if entry.path == '[stack]':  # You might need to adjust this based on your requirement
                    return entry.addr

    return None

if __name__ == "__main__":
    process_name = "aspack_ADInsight.exe"  # Replace this with the name of the process you're interested in
    base_address = get_base_address(process_name)
    if base_address:
        print(f"Base address of {process_name}: {base_address}")
    else:
        print(f"Process {process_name} not found or base address not available.")
