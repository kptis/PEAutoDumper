from MTA_dump_rebuild import *
import logging
from logging.handlers import RotatingFileHandler
import os as oss
import sys
import signal
import pefile
import subprocess
import psutil
import datetime 
import multiprocessing
from functools import partial
from multiprocessing import Process, Manager

pe_dir = 'pefile_data'
list_data_dir = oss.listdir(pe_dir)

oep_data_dir = 'oep_data'
list_file_oep = oss.listdir(oep_data_dir)

should_stop = False  # Global flag to indicate whether we should stop processing

def signal_handler(signum, frame):
    global should_stop
    print("Received signal to stop. Shutting down gracefully...")
    should_stop = True

def get_default_base_addr(pe_file):
    try:
        pe = pefile.PE(pe_file)
        base_addr = pe.OPTIONAL_HEADER.ImageBase
        return base_addr
    except Exception as e:
        print "Error: %s" % e
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
    # Continue here
    with open(oep_filepath, 'r') as f: 
        for line in f:
            if line.startswith(oss.path.basename(filename)):
                parts = line.strip().split(',')
                if len(parts) > 1 and parts[1] != "None":
                    oep_part = parts[1].split('call')[0].split('pushl')[0].strip()
                    if oep_part.startswith('a'):
                        # Remove the 'a' and get the rest
                        oep_offset = int(oep_part[1:], 16) - base_address
                        message = "RVA OEP data: 0x%x" % oep_offset
                        print message
                        logger.info(message)
                        return oep_offset
    error_message = "OEP data not found for %s" % filename
    logger.error(error_message)
    return None   

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

# Custom QueueHandler for Python 2
class QueueHandler(logging.Handler):
    """
    This handler sends events to a multiprocessing queue.
    """
    def __init__(self, queue):
        logging.Handler.__init__(self)
        self.queue = queue

    def emit(self, record):
        try:
            self.queue.put_nowait(record)
        except Exception:
            self.handleError(record)

def worker_configurer(queue):
    handler = QueueHandler(queue)
    logger = logging.getLogger()
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

def listener_process(queue, log_file_path):
    # Configure logging in the listener process
    logger = logging.getLogger()
    handler = RotatingFileHandler(log_file_path, maxBytes=10*1024*1024, backupCount=5)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    while True:
        try:
            record = queue.get()
            if record is None:  # Sentinel to stop the listener
                break
            logger.handle(record)
        except Exception:
            import sys
            import traceback
            print >> sys.stderr, 'Error in logging:', traceback.format_exc()

def worker_init(q):
    global logger
    worker_configurer(q)
    logger = logging.getLogger(__name__)

dump_folder_path = 'dump_data_2'

def process_file(file_path, packer_dir, dump_folder_path):
    global should_stop
    if should_stop:
        return
    if is_pe(file_path):
        process = None
        try:
            log_message = "Processing file: %s" % file_path
            print(log_message)
            logger.info(log_message)
            dump_file_path = oss.path.join(dump_folder_path, oss.path.basename(file_path).split('.')[0] + '.dmp.exe')
            oep_offset = get_OEP_data(file_path, packer_dir)
            process = subprocess.Popen([file_path], shell=False)
            pid = process.pid
            if oep_offset is not None and pid is not None:
                pe_dump_data = dump_and_rebuild_script_auto(pid, oep_offset)
                with open(dump_file_path, 'wb') as f:
                    f.write(pe_dump_data)
                logger.info("Successfully processing file: %s" % file_path)
        except Exception as e:
            error_message = "Failed to process %s: %s" % (file_path, str(e))
            print(error_message)
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

def process_file_wrapper(args):
    return process_file(args[0], args[1], dump_folder_path=args[2])

def process_all_pe_files(directory, log_queue):
    if not oss.path.exists(dump_folder_path):
        oss.makedirs(dump_folder_path)
    
    all_files = []
    for packer_dir in oss.listdir(directory):
        if packer_dir == '.gitkeep':
            continue
        log_message = "Packer: %s" % packer_dir
        print(log_message)
        logger.info(log_message)
        packer_dir_path = oss.path.join(directory, packer_dir)
        for file in oss.listdir(packer_dir_path):
            file_path = oss.path.join(packer_dir_path, file)
            all_files.append((file_path, packer_dir))
    
    logger.info("Found %d files to process" % len(all_files))
    
    # Use multiprocessing to process files in parallel
    pool = multiprocessing.Pool(processes=multiprocessing.cpu_count(), initializer=worker_init, initargs=(log_queue,))
    logger.info("Starting multiprocessing pool with {0} processes".format(multiprocessing.cpu_count()))
    try:
        for i, _ in enumerate(pool.imap_unordered(process_file_wrapper, [(f, p, dump_folder_path) for f, p in all_files])):
            if should_stop:
                logger.info("Stopping processing due to interrupt signal")
                break
            logger.info("Processed {0}/{1} files".format(i+1, len(all_files)))
    finally:
        pool.terminate()
        pool.join()
    
    logger.info("Finished processing files")

if __name__ == '__main__':
    # Create a 'logs' directory if it doesn't exist
    if not oss.path.exists('logs'):
        oss.makedirs('logs')

    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Create the logging queue
    manager = Manager()
    log_queue = manager.Queue(-1)

    # Get timestamp for the log file
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file_path = 'logs/dumping_script_%s.log' % timestamp

    # Start the listener process
    listener = Process(target=listener_process, args=(log_queue, log_file_path))
    listener.start()

    # Configure root logger to send logs to the queue
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    handler = QueueHandler(log_queue)
    logger.addHandler(handler)

    logger.info("----------------------Script started-------------------")
    multiprocessing.freeze_support()  # Needed for Windows
    try:
        process_all_pe_files('pefile_data', log_queue)
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received. Shutting down...")
    except Exception as e:
        logger.error("An unexpected error occurred: {0}".format(str(e)))
    finally:
        # Tell the listener to stop
        log_queue.put_nowait(None)
        listener.join()
        logger.info("----------------------Script finished------------------")
