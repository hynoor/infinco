#! python2
# -*- coding: utf-8 -*-
# 1. for NT platform, use 'pip install pypiwin32' to install win32security module
# 2. for Linux platform, 'nfs4-acl-tools' is required. test the existence by
# command 'nfs4-getfacl'
""" 
infinio.py is a handy, lightweight, flexible and powerful I/O tool designed to exercise
NAS device through rich types of data patterns and I/O modes. 
Detail information please refer the manual 
or contact hang.deng2@emc.com
"""
import sys
import os
import hashlib
import math
import getopt
import contextlib
import shutil
import collections
import random
import re
import filecmp
import time
import errno
import logging
import functools

from os import listdir, makedirs
from os.path import isfile, dirname, join, isdir, getsize, exists, split
from shutil import copyfile, move
from random import Random
from random import randint
from itertools import combinations, cycle

UNIQUE_DB = collections.defaultdict(lambda : False)

glogpath = None
groot = None
gfilenummode = 'percent'
gfilecount = 0
gdircount = 0
gdirs = set()
guser = None
gpermitted = 0
grandomace = False
gnameseed = 'random'
gnameprefix = ''
gencoding = 'utf8'
gstatecount = 0
gnumfile = 0
gnumlock = 0
gsymlinkcount = 0
ghardlinkcount = 0
gstartoffset = 0
gendoffset = 0
gnumcompresspattern = 1024 
gcompresspatternlen = 4
gopenmode = 'read' 
gopenduration = 100
gopenlock = None 
gbuffer = '' 
grewrite = False
gtreedepth = 1
gtreewidth = 1
gletters = u'abcdefghijklmnopqrstuvwxyz'
gnumbers = u'0123456789'
gnamelength = 8   # length of test file name
gblocksize = 8192 # set block size to 8k
gblocksizelist = [] # set block size for inline mode
gtargetpercent = 100 # delete all files by default
gnumfilepercent = '.100' # delete all files by default
gaclusers = 'cifsuer50-cifsuser100' # acl useres
gadsstreams = 'stream1' # acl useres
gfixeddata = '1Infino tools is powerful, flexible and lightweight!@#$%^^&*()~@'
gfixeddatalist = []
gbinbyte = b'x\11' # 1 byte
gdatabarn = os.urandom(1048576)  # 1MB size data granary for random data pattern
gicons = ['-', '\\', '|', '/']
platform = os.name

if platform == 'posix':
    import fcntl
    import struct
    # mode : (open_mode, lock_type, operation_type)
    LOCK_MODES = {
        'EXCLUSIVE'        : ('r+b', fcntl.F_WRLCK, fcntl.F_SETLK),
        'EXCLUSIVE_IO'     : ('r+b', fcntl.F_WRLCK, fcntl.F_SETLK),
        'EXCLUSIVE_BLK'    : ('r+b', fcntl.F_WRLCK, fcntl.F_SETLKW),
        'EXCLUSIVE_BLK_IO' : ('r+b', fcntl.F_WRLCK, fcntl.F_SETLKW),
        'SHARED'           : ('r+b', fcntl.F_RDLCK, fcntl.F_SETLK),
        'UNLOCK'           : ('r+b', fcntl.F_UNLCK, fcntl.F_SETLK),
    }
elif platform == 'nt':
    import msvcrt
    LOCK_MODES = {
        'EXCLUSIVE'        : ('r+b', msvcrt.LK_NBLCK),
        'EXCLUSIVE_IO'     : ('r+b', msvcrt.LK_NBLCK),
        'EXCLUSIVE_BLK'    : ('r+b', msvcrt.LK_LOCK),
        'EXCLUSIVE_BLK_IO' : ('r+b', msvcrt.LK_LOCK),
        'SHARED'           : ('r+b', msvcrt.LK_NBRLCK),
        'UNLOCK'           : ('r+b', msvcrt.LK_UNLCK),
    }
else:
    sys.exit("Unsupported Platform!")

USAGE_INFO = [
    "-----------------------------------------------------------------------------",
    "---------------------------- PRE-REQUISITES ---------------------------------",
    "Platform:",
    "Linux & Windows 2K8 or above\n",
    "Software:",
    "python2.66 or above version (infinio.py is NOT compatible with python3!)",
    "For Windows ACL manipulations, need python module win32security installed by command:",
    "# python -m pip install pypiwin32",
    "For Linux NFS ACL manipulations, need auxiliary tool nfs4-acl-tools installed by command:",
    "# install nfs4-acl-tools",
    "-----------------------------------------------------------------------------",
    "-------------------------------- USAGE --------------------------------------",
    "python infinio.py",
    "OPTIONS:",
    "--help               : help information",
    "--config-file=       : path to configuration file",
    "--directory=         : root directory used for create file tree",
    "--action=            : write           : create file tree without data integrity check",
    "                       create          : create file tree with instant integrity check",
    "                       rewrite         : overwrite/rewrite the existing files and data integrity check",
    "                       read            : read each files in tree with user given io size and seek mode",
    "                       list            : list all contained entries of given file tree",
    "                       copy            : copy file tree to other directory",
    "                       move            : move file tree to other directory", 
    "                       checksum        : checksum file tree and stores the results to db file",
    "                       truncate        : truncate file tree to specified size or proportion", 
    "                       verify          : verify checksum database db files", 
    "                       delete          : delete file tree", 
    "                       open            : open files in given file tree",
    "                       rename          : rename files in given file tree", 
    "                       append          : append files in given file tree", 
    "                       set-allowed-acl : Add allowed DACL ACEs to files in given file tree",
    "                       set-denied-acl  : Add denied DACL ACEs to files in given file tree",
    "                       remove--acl     : Remove DACL ACEs of files in given file tree",
    "                       dump-acl        : Dump all DACL ACEs of file in given file tree", 
    "                       wipe-acl        : Wipe all DACL ACEs of files in file tree", 
    "                       add-ads         : Add user defined Alternative Data Stream to every file in file tree",
    "                       update-ads      : Overwrite/Update user defined Alternative Data Stream to every file in file tree",
    "                       read-ads        : Read user defined Alternative Data Stream to every file in file tree",
    "                       remove-ads      : Remove user defined Alternative Data Stream to every file in file tree",
    "                       crawling-lock   : Manipulate byte-range locks\n",
    "[Parameters]",
    "--width=             : tree width to be created",
    "--level=             : tree level/depth to be created",
    "--file-size=         : size of each test file in byte",
    "--file-number=       : Total number of files to be manipulated, which accepts both ",
    "                       number and percentage of scoping the proportion of existing files",
    "--block-size=        : block size each write to be flushed into filesystem",
    "--name-length=       : length of name of test files to be created",
    "--data-pattern=      : data pattern of test files to be created, valid values ",
    "                       is one of  [ZEOR, ONE, bit, fixed, random, sparse, compress, complex-compress, [user defined], [inline mode]]",
    "--seek-type=         : defines the IO seeking direction, valid values [forth, back, random]",
    "--user=              : user used to run process, unix-like operation system supported only",
    "--name-seed=         : seed used to generate file/directory name",
    "--name-prefix=       : name prefix of the files to be created or exsiting files to be manipulated",
    "--open-strategy=     : strategy of open test files",
    "--dest-directory=    : destination tree root used for copy and move actions",
    "--checksum-database= : Database file path of checksum action",
    "--verify-database=   : Database file paths which to be verified",
    "--truncate-to=       : the proportion/size the file to be truncated to",
    "--append-delta=      : the proportion/size the file to be appended to",
    "--locking-mode=      : the locking mode which applies to locks",
    "--locking-strategy=  : the way of how locks be set. [start:length:interval:stop:duration]",
    "--acl-users=         : NT users or Unix users will be associated with ACL setting",
    "--ads-streams=       : Names of stream to be manipulated",
    "--symlink=           : symlink number that want to create",
    "--hardlink=          : hard number that want to create",
    "--file-offset=       : the startoffset and endoffset of the files that want to read or rewrite. [--file-offset=startoffset:endoffset], default is [--file-offset=0]",
    "--partner-ips=       : the IP address of partner host(s), which will be used in collective working
    [--partner-ips=192.168.1.2,192.168.1.3]",
    "--partner-cred=      : the user and password of partner host(s)",
    "[Global Parameters]",
    "--ITERATION=         : How many times the command be executed iteratively",
    "--LOG-LEVEL=         : Log level strategy to be applied for infinio.py",
    "--LOG-PATH=          : The path of log file to be placed\n",
    "-----------------------------------------------------------------------------",
    "------------------------------- USAGE ---------------------------------------\n",
    "{mandatory parameter} [optional parameter=default value]\n",
    "python infinio.py ",
    "--action=write           {--directory} [--data-pattern=fixed] [--file-number=1] [--name-prefix=] [--width=1] [--level=1] [--block-size=8k] [--seek-type=forth] [--file-size=8k] [--name-length=8] [--name-seed=random] [--encoding=utf8]",
    "--action=create          {--directory} [--data-pattern=fixed] [--file-number=1] [--name-prefix=] [--width=1] [--level=1] [--block-size=8k] [--seek-type=forth] [--file-size=8k] [--name-length=8] [--name-seed=random] [--encoding=utf8]",
    "--action=copy            {--directory} {--dest-directory} [--name-prefix=] [--file-number=.100]",
    "--action=move            {--directory} {--dest-directory} [--name-prefix=] [--file-number=.100]",
    "--action=rewrite         {--directory} [--name-prefix=] [--data-pattern=fixed] [--seek-type=forth] [--block-size=8k] [--file-number=.100]",
    "--action=read            {--directory} [--name-prefix=] [--seek-type=forth] [--block-size=8k] [--file-number=.100]",
    "--action=append          {--directory} [--append-delta=+.50] [--name-prefix=] [--data-pattern=fixed] [--block-size=8k] [--file-number=.100]", 
    "--action=rename          {--directory} [--name-length=8] [--name-prefix=] [--name-seed=random] [--file-number=.100]",
    "--action=checksum        {--directory} [--name-prefix=] [--checksum-database=cksum_db_timestamp.txt]",
    "--action=verify          {--verify-database}",
    "--action=open            {--directory} {--open-strategy=write:300} [--name-prefix=] [--file-number=.100]",
    "--action=truncate        {--directory} {--truncate-to=-.50} [--name-prefix=] [--file-number=.100]",
    "--action=add-ads         {--directory} [--ads-streams=stream1] [--name-prefix=] [--data-pattern=fixed] [--seek-type=forth] [--block-size=8k] [--file-n umber=.100]",
    "--action=update-ads      {--directory} [--ads-streams=stream1] [--name-prefix=] [--data-pattern=fixed] [--seek-type=forth] [--block-size=8k] [--file-number=.100]",
    "--action=read-ads        {--directory} [--ads-streams=stream1] [--name-prefix=] [--file-number=.100] [--block-size=8k] [--seek-type=forth]",
    "--action=remove-ads      {--directory} [--ads-streams=stream1] [--name-prefix=] [--file-number=.100]",
    "--action=set-denied-acl  {--directory} {--acl-users} [--name-prefix=]",
    "--action=remove-acl      {--directory} {--acl-users} [--name-prefix=]",
    "--action=dump-acl        {--directory} [--acl-users=ALL] [--name-prefix=]",
    "--action=wipe-acl        {--directory}",
    "--action=crawling-lock   {--directory} [--name-prefix=] [--locking-mode=exclusive]  [--locking-strategy=0:1:1:0:0]\n",
    "-----------------------------------------------------------------------------",
    "------------------------------- SAMPLES -------------------------------------\n",
    " 1 Create 10000 test files with 50% sparse data pattern contents:",
    " $ python infinio.py --directory=X:\\test_share\\test_dir --width=5 --level=5 --file-size=10m --file-number=10000 --block-size=8k --data-pattern=sparse:50 --action=create\n",
    " 1 Create 100 test files with 80% binary-zero and 20% binary-one contents:",
    " $ python infinio.py --directory=X:\\test_share\\test_dir --file-size=10m --file-number=100 --block-size=4K+1K --data-pattern=ZERO+ONE --action=create\n",
    " 2 Delete 50 existing files:",
    " $ python infinio.py --directory=/mnt/test_share/test_dir --file-number=50 --action=delete\n",
    " 3 Delete 60% of existing files:",
    " $ python infinio.py --directory=/mnt/test_share/test_dir --file-number=.60 --action=delete\n",
    " 4 Add 22(21+1) allowed DACL ACEs on all existing files with nt user cifsuser50-cifsuser70 and everyone:",
    " $ python infinio.py --directory=/mnt/test_share/test_dir --acl-users=cifsuer50-cifsuser70,everyone --action=set-allowed-acl\n",
    " 5 Remove 5 existing ACEs on all existing files from DACL which associated nt user are cifsuser66-cifsuser70",
    " $ python infinio.py --directory=/mnt/test_share/test_dir --acl-users=cifsuer66-cifsuser77 --action=remove-acl\n",
    " 6 Remove all existing ACEs from all files in test_dir:",
    " $ python infinio.py --directory=Z:\\test_share\\test_dir --action=wipe-acl\n",
    " 7 Truncate(shrink) all files to 50% size compare to its original size:",
    " $ python infinio.py --directory=/mnt/test_share/test_dir --action=truncate --truncate-to=-.50\n",
    " 8 Append all files to 175% size compare to its original size:",
    " $ python infinio.py --directory=/mnt/test_share/test_dir --action=append --append-delta=+.75\n",
    " 9 Truncate(re-size) each file to size of 10MB:",
    " $ python infinio.py --directory=/mnt/test_share/test_dir --action=truncate --truncate-to=10m\n",
    " 10 Create 1000 EXCLUSIVE locks on testfile.txt, then hold locks for 20 seconds",
    " $ python infinio.py --directory=Z:\\test_share\\test_dir\\testfile.txt --action=crawling-lock --locking-mode=EXCLUSIVE --locking-strategy=0:1:1:2000:20\n",
    " 11 Rename all files in file tree to new name with length of 32 and name seed of '12345abcdef'",
    " $ python infinio.py --directory=Z:\\test_share\\test_dir --action=rename --name-length --name=seed=12345abcdef\n",
    "Refer more advanced samples in Infinio Manual at:\n\nhttps://eos2git.cec.lab.emc.com/dengh2/Infinio\n",
    "------------------------------------------------------------------------------",
    "------------------------------------------------------------------------------",
]


class MyLogger:
    """ MyLogger Class
    Customerised logger class based upon python standard libarary logging.Logger
    """
    LOG_LEVELS = {
        'INFO'     : logging.INFO,
        'WARNING'  : logging.WARNING,
        'CRITICAL' : logging.CRITICAL,
        'DEBUG'    : logging.DEBUG,
    }

    def __init__(self, logger_name=__name__, 
                 record_path=None, log_level='INFO'):
        """
        init definition
        :param self        : self object
        :param logger_name : name of logger
        :param record_path : file path used to store log files
        :param log_level   : log level, on of ['INFO', 'WARN', 'DEBUG', 'ERROR']
        """ 
        global glogpath 

        if log_level not in self.LOG_LEVELS:
            sys.exit("parameter log_level is invalid")  

        if record_path is None:
            if not exists('infinio_logs'):
                try:
                    os.makedirs('infinio_logs')
                except IOError as e:
                    raise RuntimeError("Failed to create log directory with error: %s" % str(e))
            recordpath = 'infinio_logs/infinio.log-' + time.strftime("%Y%m%d%H%M%S", time.localtime()) 
        else:
            recordpaths = split(record_path)
            if recordpaths[0] != '':
                if not exists(recordpaths[0]):
                    try:
                        os.makedirs(recordpaths[0])
                    except IOError as e:
                        raise RuntimeError("Failed to create log directory with error: %s" % str(e))
                recordpath = record_path
            elif recordpaths[0] == '':
                if exists(recordpaths[1]) and isdir(record_path):
                    recordpath = join(recordpaths[1], \
                            'infinio.log-' + time.strftime("%Y%m%d%H%M%S", time.localtime()))
                else:
                    recordpath = recordpaths[1]

        glogpath = recordpath      
        self.__recordpath__ = recordpath
        self.__loggername__ = logger_name
        self.__loglevel__ = log_level
        self.__logger__ = logging.getLogger(logger_name)
        self.__logger__.setLevel(self.LOG_LEVELS[log_level])

        # create a logging format for console
        consoleformatter = logging.Formatter(
            '%(asctime)s - %(process)s:  %(message)s'
        )
        # create a logging format for log file
        logformatter = logging.Formatter(
            '%(asctime)s - %(process)s - %(levelname)s:  %(message)s'
        )

        # create file and console handlers
        self.__recordhandler__ = logging.FileHandler(self.__recordpath__)
        self.__recordhandler__.setFormatter(logformatter)
        self.__recordhandler__.setLevel(self.LOG_LEVELS[log_level])
        self.__consolehandler__ = logging.StreamHandler()
        self.__consolehandler__.setFormatter(consoleformatter)
        self.__consolehandler__.setLevel(self.LOG_LEVELS['INFO'])

        # add the handlers to the logger
        self.__logger__.addHandler(self.__recordhandler__)
        self.__logger__.addHandler(self.__consolehandler__)
 
    def get_logger(self): 
        return self.__logger__

    def update_logger(self, log_level=None):
        """" Update logger, for now only log level need to be udpated
        :param log_level  : level to be updated to 
        :return           : None
        """
        if log_level is None:
            return

        self.__recordhandler__.setLevel(self.LOG_LEVELS[log_level])
        self.__consolehandler__.setLevel(self.LOG_LEVELS[log_level])


def usage(): 
    """ 
    usage
    """
    print("\n".join(USAGE_INFO))

    sys.exit(1984)


def _set_fixed_buffer(block_size=gblocksize, pattern=gfixeddata):
    """ create the buffer contents by given requirements
    :param buffer_size : size of buffer
    :data_pattern      : data pattern to be used in filling buffer
    :return        : None 
    """
    global gbuffer
    gbuffer = ''
    buffersize = 0
    blocksize = block_size
    numblock = blocksize // len(pattern)
    blockremain = blocksize % len(pattern)
    gbuffer = pattern * numblock
    gbuffer += pattern[:blockremain]


def random_shoot(func):
    """ a decorator to radomly select the items from given generator
    there could be a unbear penalty of waiting time for auditing the 
    total number of item, which depends on how many items the generator it has,
    don't decorate rather huge generator, or you'll be devastated
    param percents : percentage of total items were permitted to yield
    yield val      : item to be yield one time
    """
    @functools.wraps(func) # copy all attributes of func to be wrappered
    def wrappered(*args, **kwargs):
        """ wrapper function 
        param *args    : all sequence type parameters
        param **kwargs : all keyword type parameter pairs
        """
        global gpermitted
        # computes the length of generator may time consuming
        percents=gnumfilepercent
        fg = func(*args, **kwargs)
        # count the progress
        total = 0
        logger.info("Auditing total existing files ...")
        for i in fg:
            total += 1
            _update_progress(0, total, "found")
        sys.stdout.write('\n')
        if gfilenummode == 'percent':
            gpermitted = int(float(percents)/float(100.00) * float(total)) + 1
        else:
            gpermitted = gnumfile
        # limit the length of randlist to one million to save memory 
        # a list with million items equivalents to 20M memory roughtly 
        million = 1000 * 1000
        numsplit = int(total/million)
        permittedsplit = 0
        if numsplit > 0:
            permittedsplit = gpermitted/numsplit
        start = 0
        stoplist = (((i + 1) * million) for i in xrange(numsplit))
        if numsplit > 0:
            for stop in stoplist:
                randlist = random.sample(xrange(start, stop), permittedsplit)
                fg = func(*args, **kwargs)
                for idx, val in enumerate(fg):
                    if idx in randlist:  
                        yield val
                start = stop
        else:
            if total < gpermitted:
                gpermitted = total
            randlist = random.sample(xrange(total), gpermitted) 
            fg = func(*args, **kwargs)
            for idx, val in enumerate(fg):
                if idx in randlist:  
                    if isfile(val):
                        yield val
    
    return wrappered


def _random_string(string_size=8, encoding='utf8'):
    """ generate a random string
    :param string_size : length of target string to be generated
    :return            : generated string
    """
    stringsize = string_size
    randomstring = '' 

    if gnameseed == 'random':
        chars = [(c) for c in unicode(gletters.lower()) + unicode(gletters.upper()) + unicode(gnumbers)]
    else:
        chars = [(c) for c in gnameseed.decode(encoding)]

    for _ in range(stringsize):
        # rand chars will generate a random
        # number between 0 and length of chars
        randobj = Random()
        offset = randobj.randint(0, len(chars)-1)
        randomstring += chars[offset]

    return randomstring


def _encipher_string(string=None, store=True):
    """ encode the given string to a checksum code, then put it in to db 
    :encipher : target string to be enciphered
    :return   : checksum of given string
    """
    if string is None:
        raise  ValueError("Parameter string is required")
    global UNIQUE_DB
    # using 'sha' result as unique db key to reduce the hosts' memory consumption
    stringcks = hashlib.sha224(string).hexdigest()
    # Start over if the string is already in the Database
    if store:
        if UNIQUE_DB[stringcks]: 
            return "collsion"
    
        UNIQUE_DB[stringcks] = True
    else:
        return stringcks


def _calc_files_per_sub_dir(tree_width=5, tree_depth=5, num_files=1000):
    """ Calculate the number of test files in each sub  directory. 
    The total directories is the sum of a geometric progression:
    the ratio is width,
    the first item is 1,
    the number of items is depth 
    totaldirs = width(power 1)+.....+width(power depth) 

    :param tree_width : the tree width
    :param tree_depth : the tree depth
    :return num_dir   : total directories
    """
    global gtreewidth
    global gtreedepth
    global gnumfile

    width = tree_width
    depth = tree_depth
    numfiles = num_files
    filesperdir = 0
    totaldirs = 0

    for i in range(depth):
        totaldirs += width**i

    if numfiles >= totaldirs:
        filesperdir = int(numfiles/totaldirs)
        remainder = numfiles % totaldirs
        logger.info("\nTotal Files: %d \
                     \nTree Width: %d \nTree Level/Depth: %d \
                 \nTotal Dirs: %d \nNumber Of Files Per Directory: %d \
                 \nRemainder: %d" % (numfiles, gtreewidth, gtreedepth, \
                 totaldirs, filesperdir, remainder))
    else:
        # there will be no tree but flat view files 
        # as long as numberfile less than totaldirs
        gtreedepth = 1
        gtreewidth = 1
        logger.info("\nTree Width: %d \nTree Depth: %d \
                 \nNumber Of Files Per-Sub-Dir: %d" % \
                 (gtreewidth, gtreedepth, numfiles))
        return (numfiles, 0)

    return (filesperdir, remainder) 


def _deploy_file(tree_root=None, data_pattern='fixed', file_size=2048,\
        file_number=1, pattern_percent=50, data_check=False,\
        rewrite=False, mode='forth'):
    """
    :param tree_root             : root path of file tree 
    :param file_size             : file size of file tree 
    :param file_number           : number of test file in tree 
    :param data_pattern          : data pattern
    :param pattern_percent       : pattern percentage
    :param encoding              : pattern encoding
    :return                      : None
    """
    global gfilecount
    global gnumfile
    global gnamelength 
    global gbuffer 
    global gdirs
    global UNIQUE_DB 
    namelength = gnamelength
    size = file_size

    for _, dir in zip(xrange(file_number), cycle(gdirs)):
        # file name building
        if gnameprefix == '':
            filename = _random_string(string_size=gnamelength, encoding=gencoding)
        else:
            filename = gnameprefix + _random_string(string_size=gnamelength-len(gnameprefix), encoding=gencoding)
        filepath = join(dir, filename)
        if not exists(filepath):
            try:
                if patternpercent > 0 and datapattern == 'sparse':
                    _punch_file(filepath, filesize, patternpercent, data_check, rewrite, seektype)
                elif datapattern == 'compress':
                    _compress_file(filepath, filesize, gblocksize, \
                            patternpercent, compresspattern, data_check, rewrite, seektype)
                elif datapattern == 'complex-compress':
                    _advance_compress_file(filepath, filesize, gblocksize, \
                            gcompresspatternlen, gnumcompresspattern, data_check, rewrite, seektype)
                else:
                    _write_file(filepath, size, datapattern, data_check, rewrite, seektype)
            except Exception as e:
                sys.exit("Exception caught while writing file: %s" % str(e))
            
            gfilecount += 1
            # update progress
            _update_progress(gnumfile, gfilecount, 'files created')
            logger.debug("test file: %s created" % filepath)
        
    
def _create_tree(tree_root=None, tree_width=5, tree_depth=5):
    """ Create file tree by given parameters
    :param tree_root             : root path of file tree 
    :param tree_width            : width of file tree 
    :param tree_depth            : depth path of file tree 
    :param encoding              : pattern encoding
    :return                      : None
    :Exception                   : IOError
    """
    if tree_root is None:
        raise ValueError("parameter tree_root is mandatory!")

    global gnamelength 
    global gdirs
    global gdircount

    root = tree_root
    namelength = gnamelength

    # create root dir 
    if not exists(root):
        os.makedirs(root)
        gdircount += 1
        _update_progress(0, gdircount, 'directory created')
        logger.debug("directory: %s created" % gdircount)
    gdirs.add(root)

    # create sub directories
    if tree_depth > 0:
        for w in range(tree_width):
            # recursively deploy sub trees 
            dirname = gnameprefix + _random_string(
                    string_size=gnamelength-len(gnameprefix),
                    encoding=gencoding)
            _create_tree(
                    tree_root=join(root, dirname),
                    tree_width=tree_width, 
                    tree_depth=tree_depth - 1,)


def _supply_index(block_size, number_write=0, remainder=0, mode='forth', start_offset=0, end_offset=0):
    """ this method calculate the index of each write will locates on
    this is the fundamental algrithm for --seek-type
    :param data_pattern : size of each write to be performaned
    :param remainder    : remainder size beyound the block size
    :return indexes     : a generate object to supply the indexes
    """
    blocksize = block_size
    numwrite = number_write
    filesize = numwrite * blocksize + remainder
    modfilesize = numwrite * blocksize
    if remainder > 0:
        if end_offset > remainder:
            yield (end_offset - remainder)
        else:
            yield (filesize - remainder)
    if mode == 'forth':
        #for idx in xrange(0, modfilesize, blocksize):
        for idx in xrange(0, numwrite):
            yield idx * blocksize + start_offset
    elif mode == 'back':
        for idx in xrange(numwrite, 0, -1):
            yield ((idx*blocksize) - blocksize) + start_offset
    elif mode == 'random':
            # one million rought use 20MB memory
            # it's not the fully random algorithm
            # while the number of I/O beyound a million
            # accroding to trial, 'random' mode could be 
            # up to 3x slower then 'forth'
            million = 1000 * 1000
            numslice = numwrite // million 
            remainder = numwrite % million
            slicegroup = []
            if numslice > 0:
                for idx in xrange(0, numwrite, million):
                    slicegroup.append([idx, idx+million])
                # remove last item is invalid which exceed 'numwrite'
                slicegroup.pop()
            if remainder > 0: 
                slicegroup.append([(numwrite - remainder), numwrite])
            random.shuffle(slicegroup)

            logger.debug("%d index groups to be iterated ..." % len(slicegroup))
            for s in slicegroup:
                logger.debug("current index group:(%d, %d)" % (s[0], s[1]))
                slicelist = list(range(s[0], s[1]))
                random.shuffle(slicelist)
                for idx in slicelist:
                    yield idx * blocksize + start_offset
                slicelist = []


def _convert_binary(bin_str='0'):
    """ this method is to converted binary string to hex number
    :param bin_str  : binary string to be converted
    :return         : hex number
    """
    binstr = bin_str
    hexres = ''
    if len(binstr) < 8:
        binstr = (8 - len(binstr)) * '0' + binstr
    if len(binstr) > 8:
        binstr = binstr[0:8]
    if int('0b' + binstr, 2) < 16:
        hexstr = hex(int('0b'+binstr, 2)).replace('0x', r'\x0').decode('string_escape')
    else:
        hexstr = hex(int('0b'+binstr, 2)).replace('0x', r'\x').decode('string_escape')

    return hexstr


def _hex_filter(raw_str=None):
    """ this method is to converted user given raw string to potential hex number
    :param bin_str  : raw string to be converted
    :return         : mixture of string and hex number
    """
    string = raw_str
    mixedstr = string.replace('0x', r'\x').decode('string_escape')

    return mixedstr

def _comprise_block(block_size_list=[8192], data_pattern_list=['fixed']):
    """ this method generates the specified content of each block
    :param data_pattern_list : data patterns of each portion to be comprised
    :param block_size_list   : data size of each portion to be comprised
    :return (content, comprisemode)
    """
    block = ''
    comprisemode = 'fixed'
    fixeddatalist = gfixeddatalist[:]
    if type(data_pattern_list) != type(block_size_list):
        sys.exit("ERROR: Invalid format, --data-pattern and --block-size should be aligned in inline mode")
    if type(data_pattern_list) is list \
            and type(block_size_list) is list \
            and len(block_size_list) == len(data_pattern_list):
        for dp, bs in zip(data_pattern_list, block_size_list):
            if dp == 'ZERO':
                block += '\x00' * bs
            elif dp == 'ONE':
                block += '\xff' * bs
            elif dp == 'fixed':
                if len(fixeddatalist) == 0:
                    _set_fixed_buffer(gblocksize, gfixeddata)
                else:
                    _set_fixed_buffer(gblocksize, fixeddatalist.pop())
                block += gbuffer[:bs] 
            elif dp == 'random':
                block += _get_rand_buffer(bs, gdatabarn)
                comprisemode = 'random'
    elif type(data_pattern_list) is str and type(block_size_list) is str:
        if data_pattern_list == 'ZERO':
            block = '\x00' * int(block_size_list)
        elif data_pattern_list == 'ONE':
            block = '\xff' * int(block_size_list)
        elif data_pattern_list == 'fixed':
            _set_fixed_buffer(int(block_size_list), gfixeddata)
            block = gbuffer[:int(block_size_list)]
        elif data_pattern_list == 'random':
            block = _get_rand_buffer(int(block_size_list), gdatabarn)
            comprisemode = 'random'
    elif type(data_pattern_list) is list \
            and type(block_size_list) is list \
            and len(data_pattern_list) != len(block_size_list):
        sys.exit("ERROR: Invalid format, --data-pattern and --block-size has different number of inline items")

    return  (block, comprisemode)


def _write_file(file_path=None, file_size=8192, data_pattern='fixed', \
        data_check=False, rewrite=False, mode='forth', start_offset=0, end_offset=0):
    """ this method creates a file according to given property
    :param filepath     : path of the file to be write
    :param data_pattern : data pattern to be referred as verification basis
    :param data_check   : indicates if check data integrity  
    :param rewrite      : indicates if overwrite existing files, start_offset and end_offset are only supported for rewrite
    :param direction    : indicates use forward write or backward write
    :return             : None
    :Exception          : IOError
    """
    global UNIQUE_DB 
    filepath = file_path
    size = file_size
    datapattern = data_pattern
    datacheck = data_check
    content, comprisemode = _comprise_block(gblocksizelist, datapattern)
    gbuffer = content
    if rewrite:
        openmode = 'rb+'
        if end_offset > 0:
            size = end_offset
            datacheck = False
        if start_offset > 0:
            size = size - start_offset
            datacheck = False
    else:
        openmode = 'wb+'
    numwrite = int(size / gblocksize)
    remainder = size % gblocksize
    remaindercontent = content[:remainder]
    index_supplier = _supply_index(gblocksize, numwrite, remainder, mode, start_offset, end_offset)
    if remainder > 0:
        rindex = next(index_supplier) # reaminder index
    try:
        with open(filepath, openmode) as f:
            if comprisemode == 'fixed':
                if remainder > 0 and mode == 'back':
                    f.seek(rindex)
                    f.write(remaindercontent)
                for index in index_supplier:
                    f.seek(index)
                    f.write(content)
                if remainder > 0 and (mode == 'forth' or mode == 'random'):
                    f.seek(rindex)
                    f.write(remaindercontent)
            elif comprisemode == 'random':
                if datacheck:
                    if remainder > 0 and mode == 'back':
                        f.seek(rindex)
                        content, _ = _comprise_block(gblocksizelist, datapattern)
                        content = content[:remainder]
                        _encipher_string(content)
                        f.write(content)
                    for index in index_supplier:
                        f.seek(index)
                        retry = 10
                        content, _ = _comprise_block(gblocksizelist, datapattern)
                        while _encipher_string(content) == 'collision' and retry > 0:
                            content, _ = _comprise_block(gblocksizelist, datapattern)
                            retry -= 1
                        f.write(content)
                    if remainder > 0 and (mode == 'forth' or mode == 'random'):
                        f.seek(rindex)
                        content, _ = _comprise_block(gblocksizelist, datapattern)
                        content = content[:remainder]
                        _encipher_string(content)
                        f.write(content)
                else:
                    if remainder > 0 and mode == 'back':
                        f.seek(rindex)
                        content, _ = _comprise_block(gblocksizelist, datapattern)
                        f.write(content(remainder, gdatabarn))
                    for index in index_supplier:
                        f.seek(index)
                        content, _ = _comprise_block(gblocksizelist, datapattern)
                        f.write(content)
                    if remainder > 0 and (mode == 'forth' or mode == 'random'):
                        f.seek(rindex)
                        content, _ = _comprise_block(gblocksizelist, datapattern)
                        f.write(content[:remainder])
    except Exception as e:
        raise Exception("ERROR: Exception caught while writing file: %s with error: %s" \
                    % (filepath, str(e)))

    if datacheck:
        _verify_file(filepath, datapattern) 
        UNIQUE_DB.clear() # reset database to release the memory


def _verify_file(file_path=None, data_pattern='fixed', sparse_locate=None):
    """ this method will check the data integrity of given file
    :param filepath : path of the file to be truncated
    :data_pattern   : data pattern to be referred as verification basis
    :return         : None
    :Exception      : IOError
    """
    global UNIQUE_DB 
    if file_path is None:
        raise ValueError("file_path is missing")
    filepath = file_path
    datapattern = data_pattern
     
    size = getsize(filepath) 
    numread = int(size/gblocksize)
    readcount = 0
    remainder = size%gblocksize
    content, comprisemode = _comprise_block(gblocksizelist, datapattern)
    remaindercontent = content[:remainder]
    try:
        if datapattern == 'sparse' and sparse_locate is not None:
            with open(filepath, 'rb') as f:
                for idx in sparse_locate[:-1]:
                    f.seek(idx * 8192)
                    readcksum = _encipher_string(f.read(8192), False)
                    if UNIQUE_DB[readcksum] is False:
                        sys.exit("Data integrity check failed on file: %s" % filepath)
        elif datapattern == 'fixed' or comprisemode == 'fixed' and datapattern != 'complex-compress':
            with open(filepath, 'rb') as f:
                while numread > 0:
                    read = f.read(gblocksize)
                    if read != content:
                        logger.exception("READ [index: %d] %s \n BUFFER: %s" \
                                % (readcount*gblocksize, read, content))
                        sys.exit("Data integrity check failed on file: %s" % filepath)
                    numread -= 1
                    readcount += 1
                if f.read(remainder) != remaindercontent:
                    sys.exit("Data integrity check failed on file: %s" % filepath)
        else:
            pos = 0
            with open(filepath, 'rb') as f:
                f.seek(0, 0)
                while numread > 0:
                    f.seek(pos,0)
                    readcksum = _encipher_string(f.read(gblocksize), False)
                    if UNIQUE_DB[readcksum] is False:
                        sys.exit("Data integrity check failed on file: %s" % filepath)
                    numread -= 1
                    pos += gblocksize
                if remainder > 0:
                    readcksum = _encipher_string(f.read(remainder), False)
                    if UNIQUE_DB[readcksum] is False:
                        sys.exit("Data integrity check failed on file: %s" % filepath)
    except Exception as e:
        raise Exception("ERROR: Exception caught while verifying file: %s with error: %s" \
                % (filepath, str(e)))


def _append_file(file_path=None, mode=None, data_pattern='fixed', delta=10):
    """ this method will truncate a file to expected delta percents
    :param filepath : path of the file to be truncated
    :param mode     : truncate mode, expand or shrink
    :delta          : percentage to be append
    :return         : None
    :Exception      : IOError
    """
    if file_path is None:
        raise ValueError("filepath is missing")
    filepath = file_path


    nowsize = getsize(file_path) 
    appendsize = filesize
    datapattern = data_pattern
    if mode == '+':
        appendsize =  nowsize + int(nowsize * delta/100) - nowsize
    elif mode == '-':
        sys.exit("ERROR: Append action doesn't support shrink ('-') mode")
    else:
        appendsize = delta
    try:
        _set_fixed_buffer(gblocksize, gfixeddata)
        if datapattern == 'fixed':
            numwrite = appendsize//len(gbuffer)
            remainder = appendsize%len(gbuffer)
            content = gbuffer
            remaindercontent = gbuffer[:remainder]
            with open(filepath, 'a') as f:
                while numwrite > 0:
                    f.write(content)
                    numwrite -= 1
                f.write(remaindercontent)
        elif datapattern == 'random':
            numwrite = appendsize//gblocksize
            remainder = appendsize%gblocksize
            with open(filepath, 'a') as f:
                while numwrite > 0:
                    f.write(_get_rand_buffer(gblocksize, gdatabarn))
                    numwrite -= 1
                f.write(_get_rand_buffer(gblocksize, gdatabarn)[:remainder])
    except IOError as e:
        logger.exception("Failed to append file %s with exception: %s" % (file_path, e))
        sys.exit(9009)


def _truncate_file(file_path=None, mode=None, delta=10):
    """ this method will truncate a file to expected delta percents
    :param filepath : path of the file to be truncated
    :param mode     : truncate mode, expand or shrink
    :delta      : percentage to be truncated
    :return     : None
    :Exception      : IOError
    """
    if file_path is None:
        raise ValueError("filepath is missing")
    nowsize = getsize(file_path) 
    truncatesize = filesize
    if mode == '+':
        truncatesize =  nowsize + int(nowsize * delta/100)
    elif mode == '-':
        truncatesize = nowsize - int(nowsize * delta/100)
    else:
        truncatesize = delta
    try:
        with open(file_path, 'a') as f:
            f.truncate(truncatesize)
    except IOError as e:
        raise IOError("Failed to truncate file %s to target size\
            %d with exception: %s" % (file_path, truncatesize, e))


def _read_file(path=None, block_size=8192, io_mode='forth', start_offset=0, end_offset=0):
    """ this method will read file with specified block size
    :param path       : path of the file tree to be read
    :param block_size : io size of each read 
    :return           : None
    :Exception        : IOError
    """
    size = getsize(path)
    if end_offset > 0:
        size = end_offset
    size = size - start_offset
    blocksize = block_size
    mode = io_mode
    numread = int(size/blocksize)
    remainder = size%blocksize
    global greadcount

    if path is None:
        raise ValueError("parameter path is missing")

    index_supplier = _supply_index(blocksize, numread, remainder, mode, start_offset, end_offset)
    if remainder > 0:
        rindex = next(index_supplier) # get index of remainder
    with open(path, 'r') as f:
        if remainder > 0 and mode == 'back':
            f.seek(rindex)
            f.read(remainder)
            greadcount += 1
            _update_progress(0, greadcount, 'data blocks were read')  
        for index in index_supplier:
            f.seek(index)
            f.read(blocksize)
            greadcount += 1
            _update_progress(0, greadcount, 'data blocks were read')  
        if remainder > 0 and (mode == 'forth' or mode == 'random'):
            f.seek(rindex)
            f.read(remainder)
            greadcount += 1
            _update_progress(0, greadcount, 'data blocks were read')  


def _list_tree(path=None):
    """ this method will list all the containing files and sub directories
    :param path     : path of the file tree to be listed
    :return         : None
    :Exception      : IOError
    """
    if path is None:
        raise ValueError("parameter path is missing")
    numdir = 0
    numfile = 0
    maxpathlen = 0
    prefixre = re.escape(gnameprefix)
    logger.info("Start to list %s" % path)
    # tree root first 
    if len(path) > maxpathlen:
        maxpathlen = len(path)
    if gnameprefix != '':
        entries = [(e) for e in os.listdir(path) \
                if re.search(prefixre, e) and isfile(join(path, e))]
    else:
        entries = [(e) for e in os.listdir(path) if isfile(join(path, e))]
    numfile += len(entries)
    _update_progress(0, numfile, 'entries were found')  
    for dir in _traverse_tree(path, 'dir'):
        if len(dir) > maxpathlen:
            maxpathlen = len(dir)
        if gnameprefix != '':
            entries = [(e) for e in os.listdir(dir) \
                    if re.search(prefixre, e) and isfile(join(dir, e))]
            if re.search(prefixre, dir):
                numdir += 1
        else:
            entries = [(e) for e in os.listdir(dir) if isfile(join(dir, e))]
            numdir += 1
        numfile += len(entries)
        _update_progress(0, numfile, 'entires were found')  
    sys.stdout.write('\n')
    if gnameprefix != '':
        logger.info("Total file with name prefix '%s' found : %d" \
                % (gnameprefix, numfile))
        logger.info("Total directory with name prefix '%s' found : %d" \
                % (gnameprefix, numdir))
    else:
        logger.info("Total files found : %d" % (numfile))
        logger.info("Total directories found : %d" % (numdir))
    logger.info("Max length of directory : %d" % maxpathlen)


@random_shoot
def _inspect_tree(tree_root=None, yield_type='both'):
    """ inspect every files and directories of given tree
    :param tree_root    : root path of file tree 
    :param yield_type   : type of item to be yield (both, dir, file)
    :return             : yield every single file met
    :Exception          : IOError
    """
    yieldtype = yield_type
    if tree_root is None:
        raise ValueError("parameter tree_root is mandatory!")
    elif not exists(tree_root):
        raise IOError("Given directory: %s does not exist" % tree_root)
    elif _islink(file_path=tree_root):
        if 'link' in yieldtype:
            yield tree_root
    elif isfile(tree_root):
        if 'both' in yieldtype or 'file' in yieldtype:
            yield tree_root
    elif isdir(tree_root):
        if ('dir' in yieldtype or 'both' in yieldtype) and tree_root != groot:
            yield tree_root
        # using generator expressions to hold 
        # dirs and file to reduce memory consumption
        if gnameprefix != '':
            prefixre = r"^" + re.escape(gnameprefix)
            files = (join(tree_root, f) for f in listdir(tree_root) if re.search(prefixre, f) and isfile(join(tree_root, f)) and not _islink(file_path=tree_root, file_name=f))
        else: 
            files = (join(tree_root, f) for f in listdir(tree_root) if isfile(join(tree_root, f)) and not _islink(file_path=tree_root, file_name=f))
        dirs = (join(tree_root, d) for d in listdir(tree_root) if isdir(join(tree_root, d)) and not _islink(file_path=tree_root, file_name=d))
        if 'link' in yieldtype:
            links = (join(tree_root, d) for d in listdir(tree_root) if _islink(file_path=tree_root, file_name=d))
            for l in links:
                yield l

        # return each file
        if 'both' in yieldtype or 'file' in yieldtype:
            for f in files:
                yield f

        # traverse directories recursively
        for d in dirs:
            for f in _traverse_tree(tree_root=d, yield_type=yieldtype):
                yield f

def _traverse_tree(tree_root=None, yield_type='both'):
    """ traverse given tree, which has exactly the same 
    function as _insepect_tree except 'random_shoot' decrator
    peeled off to gain beffer performance, I knew this is stupid 
    in logic, though it's the alternative for better performance
    :param tree_root    : root path of file tree 
    :param yield_type   : type of item to be yield (both, dir, file)
    :return             : yield every single file met
    :Exception          : IOError
    """
    yieldtype = yield_type
    if tree_root is None:
        raise ValueError("parameter tree_root is mandatory!")
    elif not exists(tree_root):
        raise IOError("Given directory: %s does not exist" % tree_root)
    elif _islink(file_path=tree_root):
        if 'link' in yieldtype:
            yield tree_root
    elif isfile(tree_root):
        if 'both' in yieldtype or 'file' in yieldtype:
            yield tree_root
    elif isdir(tree_root):
        if ('dir' in yieldtype or 'both' in yieldtype) and tree_root != groot:
            yield tree_root
        # using generator expressions to hold 
        # dirs and file to reduce memory consumption
        if gnameprefix != '':
            prefixre = r"^" + re.escape(gnameprefix)
            files = (join(tree_root, f) for f in listdir(tree_root) if re.search(prefixre, f) and isfile(join(tree_root, f)) and not _islink(file_path=tree_root, file_name=f))
        else: 
            files = (join(tree_root, f) for f in listdir(tree_root) if isfile(join(tree_root, f)) and not _islink(file_path=tree_root, file_name=f))
        dirs = (join(tree_root, d) for d in listdir(tree_root) if isdir(join(tree_root, d)) and not _islink(file_path=tree_root, file_name=d))
        if 'link' in yieldtype:
            links = (join(tree_root, d) for d in listdir(tree_root) if _islink(file_path=tree_root, file_name=d))
            for l in links:
                yield l

        # return each file
        if 'both' in yieldtype or 'file' in yieldtype:
            for f in files:
                yield f

        # traverse directories recursively
        for d in dirs:
            for f in _traverse_tree(tree_root=d, yield_type=yieldtype):
                yield f

def _advance_compress_file(file_path=None, file_size=8192, block_size=8192, \
        pattern_length=4, number_pattern=1, data_check=False, rewrite=False, mode='forth', start_offset=0, end_offset=0):
    """ build a compressilbe file according to giving parameters
    :param filepath         : root path of file tree
    :param filesize         : size of sparse file to be created
    :param block_size       : size of sparse file to be created
    :param compress_pattern : data pattern with one compress chunk
    """
    # a fullly comprehensive compressible paramter passed 
    # like: "compressilbe:65:'abcd':2048"

    if file_path is None:
        raise ValueError("parameter file_path is missing")

    datacheck = data_check
    filepath = file_path
    filesize = int(file_size)
    blocksize = int(block_size)
    patternlen = int(pattern_length)
    numpattern = int(number_pattern)

    if rewrite:
        openmode = 'rb+'
        if end_offset > 0:
            filesize = end_offset
            datacheck = False
        if start_offset > 0:
            filesize = filesize - start_offset
            datacheck = False
    else:
        openmode = 'wb+'
    numwrite = filesize/blocksize
    remainder = filesize % blocksize
    if (patternlen * numpattern) > blocksize:
        if numpattern > patternlen:
            # auto lower number of pattern
            numpattern = int(blocksize/patternlen)
        else:
            # auto lower length of pattern
            patternlength = int(blocksize/numpattern)

    def _carve_chunk():
        # build arbitary pattern to exercise compress engine
        patternset = [] 
        for _ in xrange(numpattern):
            pattern = _get_rand_buffer(patternlen, gdatabarn)
            patternset.append(pattern)

        maxpattern = len(patternset)
        maxrepeat = int(blocksize/100)
        cchunk = ''

        while len(cchunk) < blocksize:
            res = patternset[randint(0, maxpattern-1)] * randint(0, maxrepeat-1) 
            cchunk = cchunk + res 

        return cchunk[:blocksize]
        
    index_supplier = _supply_index(blocksize, numwrite, remainder, mode, start_offset, end_offset)
    if remainder > 0:
        rindex = next(index_supplier) # get index of remainder
    with open(filepath, openmode) as f:
        try:
            if datacheck:
                if remainder > 0 and mode == 'back':
                    f.seek(rindex)
                    content = _get_rand_buffer(blocksize, gdatabarn)[:remainder]
                    f.write(content)
                    _encipher_string(content)
                for index in index_supplier:
                    # build unique chunk
                    # f.seek(rindex)
                    cchunk = _carve_chunk()
                    while _encipher_string(cchunk) == 'collision' and retry > 0:
                        cchunk = _carve_chunk()
                        retry -= 1
                    f.write(cchunk)
                if remainder > 0 and (mode == 'forth' or mode == 'random'):
                    f.seek(rindex)
                    content = _get_rand_buffer(blocksize, gdatabarn)[:remainder]
                    f.write(content)
                    _encipher_string(content)
            else:
                if remainder > 0 and mode == 'back':
                    f.seek(rindex)
                    f.write(_get_rand_buffer(blocksize, gdatabarn)[:remainder])
                for index in index_supplier:
                    f.seek(index)
                    cchunk = _carve_chunk()
                    f.write(cchunk)
                    numwrite -= 1
                if remainder > 0 and (mode == 'forth' or mode == 'random'):
                    f.seek(rindex)
                    f.write(_get_rand_buffer(blocksize, gdatabarn)[:remainder])
        except Exception as e:
            logger.exception("Failed to write file: %s with error: %s" %  (filepath, e))
            sys.exit("Exception caught while writing file")
    if datacheck:
        _verify_file(filepath, datapattern) 
        UNIQUE_DB.clear() # reset database to release the memory


def _compress_file(file_path=None, file_size=8192, block_size=8192, compress_percent=50,\
        compress_pattern='\x00', data_check=False, rewrite=False, mode='forth', start_offset=0, end_offset=0):
    """ build a compressilbe file according to giving compress percents
    :param filepath         : root path of file tree
    :param filesize         : size of sparse file to be created
    :param block_size       : size of sparse file to be created
    :param compress_pattern : data pattern with one compress chunk
    """
    # a fullly comprehensive compressible paramter passed 
    # like: "compressilbe:65:'abcd':2048"

    if file_path is None:
        raise ValueError("parameter file_path is missing")
    filepath = file_path
    filesize = file_size
    blocksize = block_size
    compresspercent = int(compress_percent)
    pattern = compress_pattern
    if rewrite:
        openmode = 'rb+'
        if end_offset > 0:
            filesize = end_offset
        filesize = filesize - start_offset
    else:
        openmode = 'wb+'
    # build compressible chunk, fixed chunk size to 1024B
    if pattern == 'ZERO':
        pattern = '\x00'
    if pattern == 'ONE':
        pattern = '\xFF'
    if pattern is None:
        pattern = '\x00'
    
    if len(pattern) > int(blocksize/100) and (pattern != 'ZERO' or pattern !='ONE'):
        # when feeded data pattern is inproper
        # auto adjust to zero-ed byte
        pattern = '\x00'

    compresslen = int((float(compresspercent)/100) * blocksize)
    numlen = compresslen // len(pattern)
    remainderlen = compresslen%len(pattern)
    cchunk = numlen * pattern + (remainderlen * pattern)
    uchunksize = blocksize - len(cchunk)
    numwrite = filesize // blocksize
    remainder = filesize % blocksize
    
    index_supplier = _supply_index(blocksize, numwrite, remainder, mode, start_offset, end_offset)
    if remainder > 0:
        rindex = next(index_supplier) # get index of remainder
    with open(filepath, openmode) as f:
        retry = 100
        try:
            if datacheck:
                if remainder > 0 and mode == 'back':
                    f.seek(rindex)
                    content = _get_rand_buffer(blocksize, gdatabarn)[:remainder]
                    f.write(content)
                    _encipher_string(content)
                for index in index_supplier:
                    # build unique chunk
                    uchunk = _get_rand_buffer(uchunksize, gdatabarn)
                    while _encipher_string(uchunk) == 'collision' and retry > 0:
                        uchunk = _get_rand_buffer(gblocksize, gdatabarn)
                        retry -= 1
                    datablock = uchunk + cchunk
                    f.write(datablock)
                if remainder > 0 and (mode == 'forth' or mode == 'random'):
                    f.seek(rindex)
                    content = _get_rand_buffer(blocksize, gdatabarn)[:remainder]
                    f.write(content)
                    _encipher_string(content)
            else:
                if remainder > 0 and mode == 'back':
                    f.seek(rindex)
                    f.write(_get_rand_buffer(blocksize, gdatabarn)[:remainder])
                for index in index_supplier:
                    # build unique chunk
                    uchunk = _get_rand_buffer(uchunksize, gdatabarn)
                    datablock = uchunk + cchunk
                    f.write(datablock)
                if remainder > 0 and (mode == 'forth' or mode == 'random'):
                    f.seek(rindex)
                    f.write(_get_rand_buffer(blocksize, gdatabarn)[:remainder])
        except IOError as e:
            sys.exit("Exception caught while writing file")


def _punch_file(file_path=None, file_size=8192, sparse_percent=90,\
        data_check=False, rewrite=False, mode='forth'):
    """ create sparse file accroding to given sparse percentage
    :param file_path    : root path of file tree
    :param file_size    : size of sparse file to be created
    :param holepercent : proportion of holes to be punched in file
    """
    if file_path is None:
        raise ValueError("parameter filepath is missing")

    global UNIQUE_DB
    filepath = file_path
    filesize = file_size
    densepercent = 100 - int(sparse_percent)
    numsectorbytes = int((float(densepercent)/100) * filesize / 8192)
    randombytes = random.sample(xrange(int(float(filesize)/8192)), numsectorbytes)  
    randombytes.sort()
    if mode == 'back':
        tail = randombytes.pop()
        randombytes.reverse()
        randombytes.append(tail)

    if rewrite:
        openmode = 'rb+'
    else:
        openmode = 'w+b'

    try:
        with open(filepath, openmode) as f:
            # punching holes ...
            if data_check:
                for idx in randombytes:
                    retry = 100
                    # every single seek/write needs to be 
                    # flushed to bypass the python interval buffer
                    f.seek(idx * 8192)
                    content = _get_rand_buffer(8192, gdatabarn)
                    while _encipher_string(content) == 'collision' and retry > 0:
                        content = _get_rand_buffer(8192, gdatabarn)
                        retry -= 1
                    f.write(content)

            else:
                for idx in randombytes:
                    # every single seek/write needs to be 
                    # flushed to bypass the python interval buffer
                    f.seek(idx * 8192)
                    f.write(_get_rand_buffer(8192, gdatabarn))
            # deal closing ...
            f.seek(0)
            f.seek(filesize-1)
            f.write(b'\x00')
    except IOError as e:
        raise IOError("Error occurred while writting sparse file: %s" % e)

    if data_check:
        _verify_file(filepath, datapattern, randombytes) 
        UNIQUE_DB.clear() # reset database to release the memory



def _md5(file_path=None, db_path=None, chunk_size=4096):
    """ do checksum on the given file
    :param  file_path: file to be checksum
    :param  operation: operation to be manipulated
    :return      :
    """
    if file_path is None: 
        raise ValueError("parameter file_path is mandatory!")

    hashmd5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            hashmd5.update(chunk)
    cksum = hashmd5.hexdigest()

    with open(db_path, 'a') as cf:
        try:
            record = file_path.replace(directory, '[omitted]') + ',' + cksum + '\n'
            cf.write(record)
        except IOError as e:
            raise IOError("Failed to write checksume to db with error: %s" % e)


def _create_checksum_db(db_path=None):
    """ manipulate the checksum database 
    :param  path      : the db file path to be manipulated
    :param  operation : operation to be manipulated
    :return       :
    """
    if db_path is None: 
        raise ValueError("parameter tree_root is mandatory!")
    try:
        open(db_path, 'w+')
    except IOError as e:
        raise IOError("db file manipulation failed with error: %s" % e)


def _checksum_tree(tree_root=None, db_path=None):
    """ traverse all files in given tree and checksume all files
    :param tree_root : root path of file tree
    :return cksumdb  : a file path where stores the checksum results
    """
    if tree_root is None: 
        raise ValueError("parameter tree_root is required!")
    pattern = re.compile(r'.db')
    files = [join(tree_root, f) for f in listdir(tree_root) if isfile(join(tree_root, f)) and not _islink(file_path=tree_root, file_name=f)]
    files.sort() # sorting is required to make identical checksum db
    dirs = [join(tree_root, d) for d in listdir(tree_root) if isdir(join(tree_root, d)) and not _islink(file_path=tree_root, file_name=d)]
    dirs.sort()
    totalfiles = len(files)
    global gfilecount
    # md5 file(s)
    for f in files:
        try:
            _md5(f, db_path)
            gfilecount += 1
        except IOError as e:
            logger.exception("Failed to write checksum with exception: %s" %  e)
            sys.exit(9008)
        _update_progress(0, gfilecount, 'files checksum-ed')
    # md5 files under directories recursively
    for d in dirs:
        _checksum_tree(d, db_path)


def _compare_checksum_db(before=None, after=None):
    """ compare db files
    """
    return  filecmp.cmp(before, after)


def _get_rand_buffer(size, buffer):
    """ fetch a piece of random data
    :param size   : data size to be fetched
    :param buffer : source buffer pool where data stores
    """
    bufsize = len(buffer) - 33
    offset = randint(0,bufsize)
    bufend = bufsize - 1
    ret = ''
    while size>0:
        if (size > bufsize):
            buf = buffer[offset:bufend]
            ret+= buf
            size-= len(buf)
            offset = 0
        else:
            start = randint(0,bufsize-size)
            buf = buffer[start:start+size]
            ret+= buf
            size-= len(buf)

    return ret


def _update_progress(totalfile, filecount, act):
    """ update progress bar to stat progress, 
    come with 2 flavours, progress bar and spinning wheel
    :param totalfile : total file to be created
    :param filecount : current created number of files
    """
    global gstatecount

    if totalfile >= 20:
        granu = int(totalfile/20)
        remainder = filecount % granu
        remainder2 = filecount % 1000
        incr = int(filecount / granu)
        percents = float(filecount)/totalfile * 100
        if remainder == 0 or remainder2 == 0 or filecount <= 20:
            sys.stdout.write('\r')
            # the exact output you're looking for:
            sys.stdout.write("[|%-20s|%d%%] %d/%d %s" % \
                ('-'*incr, percents, filecount, totalfile, act))
            sys.stdout.flush()
    else: # this is for updating the spin wheel style 
        remainder = filecount % 50
        increment = filecount / 20 
        remainderb = filecount % 20
        if remainderb == 0 or remainderb <= 20:
            if remainder == 0 or remainder <= 50:
                gstatecount = filecount
            i = int(increment % 4 - 1)
            sys.stdout.write('\r')
            # the exact output you're looking for:
            sys.stdout.write("Totally %s: %d [%s]" % \
                    (act, gstatecount, gicons[i]))
            sys.stdout.flush()

        
""" NTFS(Windows) ACL
"""
def _find_sids(users=None, info_type='sid', ignore_absent_user=True):
    """ find out all sids for given user names
    param users  : list of user names used for finding their SIDs
    return sids  : list of SID been found 
    """
    res = []
    for n in users:
        try:
            ntuser = {}
            ntuser['sid'], ntuser['domain'], ntuser['type'] = ws.LookupAccountName("", n)
            res.append(ntuser[info_type])
        except:
            if ignore_absent_user:
                logger.warning("ignored user: %s, which wasn't found" % n)
            else:
                sys.exit("finding NT users' sid failed")

    return res


def _set_ntfs_dacl_ace(path=None, sids=None, ace_type='allowed'):
    """ Add Allowed/Denied ACEs of Discretionary ACL
    param path        : name of file which target ACEs dwelles
    param sids        : list of security id of owners to be set ace for,
                        however, a full controll everyone is must for 
                        later file operation (deletion etc.)
    param ace_type    : type of ACE to be set. (allowed or denied)

    caveat            : The size of an ACL varies with the number 
                        and size of its access control entries (ACEs). 
                        The maximum size of an ACL is 64 kilobytes (KB), 
                        or approximately 1,820 ACEs. However, for performance
                        reasons, the maximum size is not practical. 
    """
    global grandomace
    filename = path
    acetype = ace_type
    sidlist = sids
    if grandomace:
        sidlist = random.sample(sidlist,  random.randint(0, len(sidlist)))

    # get securit descriptor 
    sd = ws.GetFileSecurity(filename, ws.DACL_SECURITY_INFORMATION)
    dacl = sd.GetSecurityDescriptorDacl()
    secmaskgen = _offer_security_mask(length=5)

    if acetype == 'allowed':
        for sid, secmask in zip(sidlist, secmaskgen):
            dacl.AddAccessAllowedAce(
                    ws.ACL_REVISION_DS, 
                    nsc.FILE_GENERIC_READ|nsc.FILE_GENERIC_WRITE|
                    secmask[0]|secmask[1]|secmask[2]|secmask[3]|secmask[4],
                    sid)
    elif acetype == 'denied':
        for sid, secmask in zip(sidlist, secmaskgen):
            dacl.AddAccessDeniedAce(
                    ws.ACL_REVISION_DS, 
                    nsc.FILE_GENERIC_READ|nsc.FILE_GENERIC_WRITE|  \
                            secmask[0]|secmask[1]|secmask[2]|secmask[3]|secmask[4],
                    sid)
    elif acetype == 'wipe':
        # new a empty dacl for overwritting existing 
        dacl = ws.ACL()

    # applies dacl and security setting
    sd.SetSecurityDescriptorDacl(1, dacl, 0)
    ws.SetFileSecurity(filename, ws.DACL_SECURITY_INFORMATION, sd)
     

def _del_ntfs_dacl_ace(path=None, sids=None):
    """ Get the infos of all of ACEs of discretionary ACL
    param path  : name of file which target ACEs dwelled
    param sid   : sid to be associated to ACE 
    """
    global grandomace
    filename = path
    delsids = sids 
    if grandomace:
        delsids = random.sample(delsids,  random.randint(0, len(delsids)))
    sd = ws.GetFileSecurity(filename, ws.DACL_SECURITY_INFORMATION)
    dacl = sd.GetSecurityDescriptorDacl()
    acecount = dacl.GetAceCount()
    aclsize = dacl.GetAclSize()

    delindexes = []
    for idx in xrange(dacl.GetAceCount()):
        _, _, sid = dacl.GetAce(idx)
        if sid in delsids:
            delindexes.append(idx)  
    
    # sorry for below obscure and frustrating algorithm
    # as the indexes are changing dynamically. -_-!!
    counter = 0
    for i in delindexes:
        latest = i - counter
        try:
            dacl.DeleteAce(latest)
            counter += 1
        except: # for now the type of win32 exception is unknow to me
            logger.error("Faied to remove a ACE from file: %s" % filename)

    # applied updated dacl and security
    sd.SetSecurityDescriptorDacl(1, dacl, 0)
    ws.SetFileSecurity(filename, ws.DACL_SECURITY_INFORMATION, sd)


def _dump_ntfs_dacl_ace(path=None, users='ALL', dump_path=None):
    """ Getinfos of all of ACEs of given file
    param path : name of file which target ACEs dwelled
    """
    if path == None or dump_path == None:
        raise ValueError("Both parameter path and dump_path are reuqired")

    filename = path
    acldumpfile = dump_path
    sd = ws.GetFileSecurity(filename, ws.DACL_SECURITY_INFORMATION)
    dacl = sd.GetSecurityDescriptorDacl()
    aclsize = dacl.GetAclSize()
    content = '' 

    if users == 'ALL':
        for idx in xrange(dacl.GetAceCount()):
            (acetype, aceflag), mask, sid = dacl.GetAce(idx)
            ntname, _, _ = ws.LookupAccountSid(None, sid)
            content += filename + ',' + str(acetype) + ',' + str(aceflag)  \
                    + ',' + str(mask) + ',' + ntname + ',' +  str(sid)[6:] + '\n'
    else:
        for idx in xrange(dacl.GetAceCount()):
            (acetype, aceflag), mask, sid = dacl.GetAce(idx)
            ntname, _, _ = ws.LookupAccountSid(None, sid)
            if ntname in users:
                content += filename + ',' + str(acetype) + ',' + str(aceflag)  \
                    + ',' + str(mask) + ',' + ntname + ',' +  str(sid)[6:] + '\n'

    with open(acldumpfile, 'a') as f:
        f.write(content)


def _offer_security_mask(os_type='nt', length=3):
    """ generate all combinations from given security types
    param mask_lenght  : the length single security combination
    return pool        : a pool (set) has all well-generated security
                         combinations
    """
    # no guarantee of evey yield item a valid security mask
    # which is doesn't hurt as we're just emulating the 
    # random permissions
    if os_type == 'posix':
        nfs4permissions = ('r', 'w', 'a', 'x', 'd', 'D', \
            't', 'T', 'n', 'N', 'c', 'C', 'o', 'y') 
        for maskitem in combinations(nfs4permissions, length):
            mask = 'rw' 
            for m in maskitem:
                mask += m
            yield mask
             
    # import all security candidates, which is huge, damn NTFS ACL!
    # Looks like Microsoft do have lot of smart dudes
    if os_type == 'nt':
        ntfssecurities = (
            nsc.FILE_READ_ATTRIBUTES, 
            nsc.FILE_READ_DATA, 
            nsc.FILE_READ_EA, 
            nsc.SYNCHRONIZE,
            nsc.STANDARD_RIGHTS_READ, 
            nsc.STANDARD_RIGHTS_WRITE,
            nsc.STANDARD_RIGHTS_EXECUTE, 
            nsc.FILE_APPEND_DATA,
            nsc.FILE_WRITE_ATTRIBUTES, 
            nsc.FILE_WRITE_DATA,
            nsc.FILE_WRITE_EA, 
            nsc.WRITE_OWNER,
            nsc.WRITE_DAC, 
            nsc.READ_CONTROL,
            nsc.SI_ADVANCED, 
            nsc.SI_EDIT_AUDITS,
            nsc.SI_EDIT_PROPERTIES, 
            nsc.SI_EDIT_ALL,
            nsc.SI_PAGE_TITLE, 
            nsc.SI_RESET,
            nsc.SI_ACCESS_SPECIFIC, 
            nsc.SI_ACCESS_GENERAL,
            nsc.SI_ACCESS_CONTAINER, 
            nsc.SI_ACCESS_PROPERTY,
            nsc.FILE_ALL_ACCESS, 
            nsc.FILE_GENERIC_READ, 
            nsc.FILE_GENERIC_WRITE, 
            nsc.FILE_GENERIC_EXECUTE,
            nsc.OBJECT_INHERIT_ACE, 
            nsc.CONTAINER_INHERIT_ACE, 
            nsc.INHERIT_ONLY_ACE, 
            nsc.SI_PAGE_PERM, 
            nsc.SI_PAGE_ADVPERM, 
            nsc.SI_PAGE_AUDIT, 
            nsc.SI_PAGE_OWNER, 
            nsc.PSPCB_SI_INITDIALOG,
            nsc.SI_CONTAINER,
        )
        for maskitem in combinations(ntfssecurities, length):
            yield maskitem




""" NFS4 ACL
A type NFS4 ACE format: [type:flags:principal:permissions]
"""

def _manipulate_nfs4_acl(path=None, action='add', ace_info='rwx'):
    """ manipulates ACEs on given file or directory
    path                : path to target file or directory
    param action        : actions of ACE manipulation ['add', 'delete', 'get'].
    param ace_info      : specific permission code
    return res          : a list stores all ACEs  
    """
    if action == 'add': 
        acecmd = ('nfs4_setfacl', '-a', ace_info, path)
    elif action == 'delete': 
        acecmd = ('nfs4_setfacl', '-x', ace_info, path)
    elif action == 'get': 
        acecmd = ('nfs4_getfacl', path)
    else:
        raise ValueError("Invalid action set acl aciton")

    if action != 'get':
        try:
            res = block_run(acecmd)
        except Exception as e:
            raise IOError("Error: %s occured while set acl on file: %s" % (str(e), path))
    else:
        try:
            res = nonblock_run(acecmd)
        except Exception as e:
            raise IOError("Error: %s occured while set acl on file: %s" % (str(e), path))
        if res != '':
            return res.split('\n')[:-1]
    

def _set_nfs4_ace(path=None, sids=None, ace_type='allowed'):
    """ Set Allowed/Denied ACEs of NFS4 ACL
    param path     : name of file which target ACEs inhabit
    param sids     : list of security id of owners to be set ace for,
                     however, a full controll everyone is must for 
                     later file operation (deletion etc.), due to
                     the limits of nfs4-acl-tools, the maximu ACEs 
                     can be operated should no more then 600
    param ace_type : type of ACE to be set. (allowed or denied)
    """
    # get permission
    global grandomace
    aceflag = '' # empty means for users, while 'g' for group
    permissions = _offer_security_mask('posix', length=5)
    sidlist = sids
    if grandomace:
        sidlist = random.sample(sidlist,  random.randint(0, len(sidlist)))

    if ace_type == 'allowed':
        acetype = 'A'
        for sid, permission in zip(sidlist, permissions):
            aceinfo = acetype + ":" + aceflag + ":" + \
                    sid + ":" + permission
            _manipulate_nfs4_acl(path=path, action='add', ace_info=aceinfo)

    elif ace_type == 'denied':
        acetype = 'D'
        for sid, permission in zip(sidlist, permissions):
            aceinfo = acetype + ":" + aceflag + ":" + \
                    sid + ":" + permission
            _manipulate_nfs4_acl(path=path, action='add', ace_info=aceinfo)


def _del_nfs4_ace(path=None, sids=None):
    """ Add Allowed/Denied ACEs of NFS4 ACL
    param path     : name of file which target ACEs inhabit
    param sids     : list of user name or gid to be associated with ACEs
    """
    existingaces = _manipulate_nfs4_acl(path, 'get', sids)
    delsids = sids 
    if grandomace:
        delsids = random.sample(delsids,  random.randint(0, len(delsids)))
    if delsids == 'ALL': 
        for item in existingaces:
            _manipulate_nfs4_acl(path, 'delete', item)
    else:
        filteraces = [(ai) for ai in existingaces \
                if ai.split(':')[2] in delsids]

        for item in filteraces:
            _manipulate_nfs4_acl(path, 'delete', item)


def _dump_nfs4_ace(path=None, users='ALL', dump_path=None):
    """ Getinfos of all of nfs4 ACEs of given file
    param path : name of file which target ACEs dwelled
    """
    if path == None or dump_path == None:
        raise ValueError("Both parameter path and dump_path are reuqired")

    existingaces = _manipulate_nfs4_acl(path, 'get')
    content = ''
    if users == 'ALL':
        for ace in existingaces:
            acetype, aceflag, uid, permission = ace.split(':')
            match = re.search('\d+', uid)
            if match:
                uname = _user_to_uid(uid=uid)
            else:
                uname = uid
            if not aceflag:
                aceflag = 'u'
            content += path + ',' + str(acetype) + ',' + str(aceflag) + \
                    ',' + permission + ',' + uname + ',' +  str(uid) + '\n'
    else:
        for ace in existingaces:
            acetype, aceflag, uid, permission = ace.split(':')
            match = re.search('\d+', uid)
            if match:
                uname = _user_to_uid(uid=uid)
            else:
                uname = uid
            if uname in users:
                if not aceflag:
                    aceflag = 'u'
                content += path + ',' + str(acetype) + ',' + str(aceflag) + \
                        ',' + permission + ',' + uname + ',' +  str(uid) + '\n'

    with open(dump_path, 'a') as f:
        f.write(content)


""" Manipulate ADS Data
--add-ads
--update-ads
--remove-ads
"""

def _add_ads(path=None, streams=['stream1'], file_size=8192, \
        data_pattern='fixed', seek_type='forth'):
    """ create ads data
    param path    : target directory
    param streams : list which holds stream names
    """
    for s in streams:
        streampath = path + ':' + s
        if exists(streampath):
            logger.warning("Stream %s already exists" % streampath)
        else:
            _write_file(streampath, file_size, data_pattern, False, False, seek_type)
    
    logger.debug("User specified ADS data were wrote on file: %s" % path)
   

def _update_ads(path=None, streams=['stream1'], file_size=8192, \
        data_pattern='fixed', seek_type='forth'):
    """ update ads data
    param path    : target direcotry
    param streams : list which holds stream names
    """
    for s in streams:
        streampath = path + ':' + s
        if not exists(streampath):
            logger.warning("Given stream %s does not exist!" % streampath)
        else:
            _write_file(streampath, file_size, data_pattern, False, True, seek_type)
    
    logger.debug("User specified ADS data were updated on file: %s" % path)


def _read_ads(path=None, streams=['stream1'], block_size=8192, seek_type='forth'):
    """ read ads data
    param path    : target direcotry
    param streams : list which holds stream names
    """
    for s in streams:
        streampath = path + ':' + s
        if not exists(streampath):
            logger.warning("Given stream %s does not exist!" % streampath)
        else:
            _read_file(streampath, block_size, seek_type)
    
    logger.debug("User specified ADS read on file: %s" % path)


def _remove_ads(path=None, streams=['stream1']):
    """ remove ads data
    param path    : target direcotry
    param streams : list which holds stream names
    """
    for s in streams:
        streampath = path + ':' + s
        if not exists(streampath):
            logger.warning("Given stream %s does not exist!" % streampath)
        else:
            os.remove(streampath)
    
    logger.debug("User specified ADS were deleted on file: %s" % path)


def _massive_open(directory=None, open_mode='SHARED', holding=1, lock_func=None):
    """ open all file under given directory with user specified opens
    param directory   : target directory
    param number_open : number of opens per file
    """
    if directory is None:
        raise ValueError("parameter directory is mandatory!")

    global gpermitted 
    path = directory
    holdingtime = holding
    openmode = open_mode
    filehandles = []
    filecount = 0

    if gnumfilepercent == 100:
        go_through_tree = _traverse_tree 
        gpermitted = 0
    else:
        go_through_tree = _inspect_tree 
    for f in go_through_tree(path, yield_type='file'):
        fh = open(f, LOCK_MODES[openmode][0])
        if lock_func is not None:
            endoffset = int(getsize(f)) - 1
            lock_func(fh, openmode, 0, endoffset, None)
        filehandles.append(fh)
        filecount += 1
        _update_progress(gpermitted, filecount, 'files opened')
    sys.stdout.write('\n')
    logger.info("All file handles created, holding for %d seconds" % int(holdingtime)) 
    passtime = 0 

    if len(filehandles) > 0:
        while passtime < int(holdingtime):
            time.sleep(1) 
            passtime += 1
            _update_progress(int(holdingtime), passtime, 'seconds holding time passed')
        
    sys.stdout.write('\n')
    numhandles = len(filehandles)
    closedfh = 0
    while len(filehandles):
        fh = filehandles.pop()
        fh.close()
        closedfh += 1
        _update_progress(numhandles, closedfh, 'file handles were closed')
    sys.stdout.write('\n')



""" 
Utils functons
"""
def _user_to_uid(user=None, uid=None):
    """ get the uid of passed user name
    """
    import pwd
    if user:
        try:
            uid = pwd.getpwnam(user).pw_uid
        except KeyError:
            logger.warning("User: %s was not found, ignored" % user)
            return -1
        return uid
    if uid:
        try:
            name = pwd.getpwuid(int(uid)).pw_name
        except KeyError:
            logger.info("UID %s was not found, ignored" % str(uid))
            return
        return name


def _convert_size(raw_size):
    """ convert whatever passed size to byte unit
    param raw_size  : passed raw size
    return size     : size in byte
    """
    rawsize = raw_size
    sm = re.search('^(\d+)(\w{1,2})?', str(rawsize))
    if sm:
        number = sm.group(1)
        if sm.group(2):
            unit = sm.group(2)
            if unit.upper() == 'B':
                return number
            elif unit.upper() == 'K' or unit.upper() == 'KB':
                return str(int(number) * 1024)
            elif unit.upper() == 'M' or unit.upper() == 'MB':
                return str(int(number) * 1024 * 1024)
            elif unit.upper() == 'G' or unit.upper() == 'GB':
                return str(int(number) * 1024 * 1024 * 1024)
            elif unit.upper() == 'T' or unit.upper() == 'TB':
                return str(int(number) * 1024 * 1024 * 1024 * 1024)
            elif unit.upper() == 'P' or unit.upper() == 'PB':
                return str(int(number) * 1024 * 1024 * 1024 * 1024 * 1024)
            else:
                sys.exit("Invalid unit: %s" % unit)
        else:
            return number 
    else:
        return rawsize


def _set_user(user='root'):
    """ set the effective user of the process
    user     : user name
    """
    if os.name == 'posix':
        uid = int(_user_to_uid(user))
        if uid == -1:
            sys.exit("ERROR: user '%s' not found" % user)
        os.seteuid(uid)
    else: 
        sys.exit("Platform doesn't support")


def _get_range_value(string=None):
    """ examine passed vaidated string to list
    param string  : string to be serialized
    return values : a list stores the result
    """
    global grandomace
    targetstr = string
    head = None
    rear = None
    hindex = None
    rindex = None
    finalres = []
    rawres = targetstr.split(',')
    for r in rawres:
        m = re.search('^.*(-|~){1}.*$', r)
        if m is not None:
            if m.group(1) == '-':
                fineres = r.split('-')
            elif m.group(1) == '~':
                fineres = r.split('~')
                grandomace = True
            else:
                sys.exit("Error: Invalid name format passed!")
            if len(fineres) == 2:
                m = re.search('^\s*(\S*\D)(0*)(\d+)$', fineres[0])
                head = m.group(1)
                hmedium = m.group(2)
                hindex = m.group(3)
                m = re.search('^\s*(\S*\D)(0*)(\d+)$', fineres[1])
                rear = m.group(1)
                rmedium = m.group(2)
                rindex = m.group(3)
                if head != rear:
                    raise ValueError("Invalid format passed!")
                else:
                    for i in xrange(int(hindex), int(rindex) + 1):
                        digits = len(str(i)) - len(hindex)
                        finalres.append(head + '0' * (len(hmedium)-digits) + str(i))
            elif len(fineres) == 1:
                finalres.append(fineres[0])
            else:
                sys.exit("Error: Invalid name format passed!")
        else:
            finalres.append(r)
    return finalres


# POSIX Locks
def _get_posix_lock(file_handle=None, lock_mode='EXCLUSIVE', 
        off_set=0, range_length=0, with_io=None):
    """ POSIX'ed Locking single file with specific lock mode
    :param file_handle  : file handle of target file
    :param lock_mode    : lock mode to be used
    :param off_set      : start position of locking range of the target file
    :param range_length : length of the target file to lock
    :param with_io      : data will be write or read after lock
    """
    lockdata = struct.pack('hhllhh', LOCK_MODES[lock_mode][1], 
                           0, off_set, range_length, 0, 0)
    fh = file_handle
    lockmode = lock_mode
    withio = with_io
    try:
        logger.debug('Set %s lock on range[%d - %d] of file: %s ' 
                     % (lock_mode, off_set, off_set + range_length -1, 
                     fh.name))
        if withio: 
            if lockmode == 'EXCLUSIVE_IO' or lockmode == 'EXCLUSIVE_BLK_IO':
                rv = fcntl.fcntl(fh, LOCK_MODES[lock_mode][2], lockdata)
                fh.seek(0)
                fh.seek(off_set)
                # need to truncate extra content which exceeds end offset
                fh.write(withio[:range_length])
            elif lockmode == 'SHARED' or lockmode == 'UNLOCK':
                # WARNING!
                # the minimal size of kernel read is one page(4KB)
                # hence the read may failed if target bytes
                # which page was overlapped with other bytes 
                # owned by other lockowners
                fh.seek(off_set)
                readdata = fh.read(range_length) 
                if readdata != withio:
                    sys.stdout.write('\n')
                    sys.exit("ERROR: Data verification failed. expect: %s | actual: %s" % (withio, readdata))
                rv = fcntl.fcntl(fh, LOCK_MODES[lock_mode][2], lockdata)
        else:
            rv = fcntl.fcntl(fh, LOCK_MODES[lock_mode][2], lockdata)
                
    except IOError as e:
        raise IOError(e)

    return True


def _get_nt_lock(file_handle=None, lock_mode='EXCLUSIVE', \
        off_set=0, range_length=0, with_io=0):
    """ POSIX'ed Locking single file with specific lock mode
    :param file_handle  : file handle of target file
    :param lock_mode    : lock mode to be used
    :param offset       : start position of locking range of the target file
    :param length       : length of the target file to lock
    """
    fh = file_handle
    offset = off_set
    lockmode = lock_mode
    withio = with_io
    rangelength = range_length
    try:
        logger.debug('Set %s lock on range[%d - %d] of file: %s ' 
                     % (lock_mode, offset, offset + rangelength -1, fh.name))
        if withio: 
            if lockmode == 'EXCLUSIVE_IO' or lockmode == 'EXCLUSIVE_BLK_IO':
                fh.seek(offset)
                msvcrt.locking(fh.fileno(), LOCK_MODES[lock_mode][1], range_length)
                # need to truncate extra content which exceeds end offset
                fh.write(withio[:range_length])
            elif lockmode == 'SHARED' or lockmode == 'UNLOCK':
                fh.seek(offset)
                readdata = fh.read(rangelength) 
                if readdata != withio[:range_length]:
                    sys.exit("Data verification failed. expect: %s | actual: %s" % (withio, readdata))
                fh.seek(offset)
                msvcrt.locking(fh.fileno(), LOCK_MODES[lock_mode][1], range_length)
        else:
            fh.seek(offset)  # this will change the position to offset
            msvcrt.locking(fh.fileno(), LOCK_MODES[lock_mode][1], range_length)

    except IOError as e:
        raise IOError(e) 

    return True


def _compare_database(source=None, dest=None):
    """ compare given files line by line
    :param source      : file handle of target file
    :param destination : lock mode to be used
    """
    srcfile = source
    dstfile = dest

    srcfh = open(srcfile, 'r') 
    dstfh = open(dstfile, 'r') 
    verifycount = 0
    try:
        for srcline, dstline in zip(srcfh, dstfh):
            if srcline != dstline:
                sys.exit("\nData verification failed:\nsource:%sdest  :%s" \
                        % (srcline, dstline))
            else: 
                verifycount += 1
                _update_progress(0, verifycount, "files were verified")
        sys.stdout.write('\n')
    finally:
        srcfh.close()
        dstfh.close()


def _get_byte_range(file_size=None, start=0, 
        byte_range_length=1, step_interval=1, stop=0):
    """ create a range indicates which range of test file to be locked 
    :param file_size         : size of target file
    :param start             : the start offset to lock
    :param byte_range_length : length of each byte-range
    :param step_interval     : interval of each byte-range
    :param stop              : the stop offset to lock
    :return                  : (offset, length)
    """
    if file_size == None:    
        raise ValueError("parameter file_size is mandatory!")

    global gnumlock
    filesize = int(file_size)
    start = int(start)
    stop = int(stop)
    length = int(byte_range_length)
    interval = int(step_interval)

    if interval + start > filesize:
        interval = filesize - start

    if length > (filesize - start) or length == 0:
        length = filesize - start 
        stop = filesize

    if stop <= filesize and stop > 0:
        filesize = stop

    numiterate = int((filesize-start)/(interval+length))
    gnumlock = numiterate

    #if interval != 0:
    for o in xrange(0,(numiterate+1)):
        activeoffset = start + o * (length+interval)
        if length + activeoffset <= filesize:
            yield (activeoffset, length)


def _get_fileinfo(file_path=None, open_mode='EXCLUSIVE'):
    """ Open given file and yield the combined info of file
    :param file_path : Root direcotry of taraget test files
    :param open_mode : Open mode of test files 
    :yield           : target file info which includes file hanlde and file size
    """
    if file_path is None :
        logger.info("parameter file_path is mandatory!")
        raise ValueError
    if not isfile(file_path):
        logger.info("given path is not a file!")

    openMode = open_mode
    f = file_path

    # get all fileinfo tuples of (filehanle, filesize, filepath)
    try:
        fh = open(f, LOCK_MODES[openMode][0])
        return (fh, getsize(f), f)
    except Exception as e:
        if e.errno == 13:
            logger.error("open file failed with permission denined ")
        else:
            sys.exit("error occured: %s" % str(e))


def _digest_locking_strategy(strategy=None):
    """ A helper function plays the role of analysing locking strategy
    :param strategy : strategy code of locking 
    :return results : a dictinary stores the detail strategy
    """
    allstrategy = strategy.split('+') 
    allresdicts = []
    for s in allstrategy:
        strategymatch = re.search('^((\d+(\w)?:\d+(\w)?:\d+(\w)?:\d+(\w)?:\d+)\+?)+$', s)
        resdict = {'start':0, 'length':1, 'step':1, 'stop':0, 'duration':0}
        if strategymatch:
            strategyres = s.split(':')
            if len(strategyres) == 1:
                resdict['start'] = int(_convert_size(strategyres[0]))
            elif len(strategyres) == 2:
                resdict['start'] = int(_convert_size(strategyres[0]))
                resdict['length'] = int(_convert_size(strategyres[1]))
            elif len(strategyres) == 3:
                resdict['start'] = int(_convert_size(strategyres[0]))
                resdict['length'] = int(_convert_size(strategyres[1]))
                resdict['step'] = int(_convert_size(strategyres[2]))
            elif len(strategyres) == 4:
                resdict['start'] = int(_convert_size(strategyres[0]))
                resdict['length'] = int(_convert_size(strategyres[1]))
                resdict['step'] = int(_convert_size(strategyres[2]))
                resdict['stop'] = int(_convert_size(strategyres[3]))
            elif len(strategyres) == 5:
                resdict['start'] = int(_convert_size(strategyres[0]))
                resdict['length'] = int(_convert_size(strategyres[1]))
                resdict['step'] = int(_convert_size(strategyres[2]))
                resdict['stop'] = int(_convert_size(strategyres[3]))
                resdict['duration'] = int(_convert_size(strategyres[4]))
        else:
            logger.info("Use default --locking-strategy=0:1:1:0")
            pass

        allresdicts.append(resdict)

    return allresdicts

def _compound_string(string=None, quantity=1, data_type=int, default=None, seperator='#'):
    """ to serialized give string for feeding compound command
    param string    : target string to be serialized
    param length    : max length of queue
    param seperator : seperator used to split 
    """
    if string == None:
        target = default

    target = string.split(seperator)
    numitem = len(target) 
    
    if numitem > quantity:
        target = target[:quantity]

    elif numitem <= quantity:
        for i in xrange(numitem,quantity):
            target.append(data_type(target[::-1][0]))
    return target
    

def _join_list(target_list=None, anchor='#'):
    """ compose a input format string 
    """
    res = ''
    if len(target_list) > 1:
        for i in target_list:
            res = str(i) + anchor
    else:
        return str(target_list[0])

    return str(res[::-1][0])


def _parse_config(file_path=None):
    """ read configuration file and format the parameters
    file_path  : path of configuration files
    """
    configpath = file_path
    results = []
    with open(configpath, 'r') as cf:
        content = cf.read()
        items = re.split('\s+|^(\n+)', content)
        for item in items: 
            if item == '' or item is None:
                next
            else:
                match = re.search('^(--)?(\S+)=(\S+)$', item)
                if match:
                    dash = match.group(1)
                    name = match.group(2)
                    value = match.group(3)
                    if dash is None:
                        dash = '--'
                    results.append((dash + name, value))
                else:
                    print("Invalid parameter %s in configuration file!" % item)

    return results

def _create_link(path=None):
    """ this method will create symlink and hardlink in the related path
    :param path     : path of the file tree to be created link
    :return         : None
    :Exception      : IOError
    """
    global ghardlinkcount
    global gsymlinkcount
    if platform == 'nt':
        ghardlinkcount=0

    if path is None:
        raise ValueError("parameter path is missing")
    if ghardlinkcount <= 0 and gsymlinkcount <= 0:
        return
    prefixre = re.escape(gnameprefix)
    # tree root first
    if gnameprefix != '':
        entries = [(e) for e in os.listdir(path) \
                if re.search(prefixre, e) and not os.path.islink(join(path, e))]
    else:
        entries = [(e) for e in os.listdir(path) if not os.path.islink(join(path, e))]
    for entry in entries:
        if isfile(join(path, entry)) and ghardlinkcount > 0:
            os.link(join(path, entry), join(path, entry+'hardln'+_random_string(string_size=8, encoding=gencoding)))
            ghardlinkcount -= 1
        if gsymlinkcount > 0:
            os.symlink(join(path, entry), join(path, entry + 'symln' + _random_string(string_size=8, encoding=gencoding)))
            gsymlinkcount -= 1
    for entry in entries:
        if isdir(join(path, entry)):
            _create_link(path=join(path, entry))

def _islink(file_path, file_name=None):
    """ this method will determine whether the related file is symlink or hardlink
    :param file_path : path of the file or dir
    :param file_name : file name to be checked
    :return         : None
    :Exception      : IOError
    """

    if file_path is None:
        raise ValueError("parameter file_path is missing")
    issymlink=False
    ishardlink=False
    p = file_path
    if file_name is not None:
        p = join(file_path, file_name)
    if os.path.islink(p):
        issymlink = True
    elif isfile(p):
        if re.search('^(.*)(hardln\w+)', p):
            ishardlink = True
    if issymlink or ishardlink:
        return True
    else:
        return False


def _copyright():
    print("\nInfinio v2.3 - Versatile NAS I/O Tool")
    print("Copyright (C) 2017 Hang Deng")
    print("Last Modify: Oct. 16th 2017\n")
    print("www.dellemc.com\n")

if __name__ == "__main__":

    _copyright()
    if len(sys.argv) == 3 and (sys.argv[1] == '--config-file' or sys.argv[1] == '-c'):
        opts = _parse_config(sys.argv[2])
    elif len(sys.argv) == 1:
        usage()
    else: 
        try:
            opts, args = getopt.getopt(sys.argv[1:], 
                    "h:", 
                                           ["help",
                                            "action=",
                                            "directory=",
                                            "dest-directory=",
                                            "width=",
                                            "level=",
                                            "file-size=",
                                            "block-size=",
                                            "file-number=",
                                            "truncate-to=",
                                            "append-delta=",
                                            "locking-mode=",
                                            "locking-strategy=",
                                            "open-strategy=",
                                            "target-percent=",
                                            "acl-users=",
                                            "ads-streams=",
                                            "checksum-database=",
                                            "verify-database=",
                                            "name-length=",
                                            "name-seed=",
                                            "name-prefix=",
                                            "encoding=",
                                            "symlink=",
                                            "hardlink=",
                                            "file-offset=",
                                            "data-pattern=",
                                            "io-mode=",
                                            "seek-type=",
                                            "user=",
                                            "ITERATION=",
                                            "LOG-PATH=",
                                            "LOG-LEVEL="])
        except getopt.GetoptError as e:
            # print help information and exit:
            sys.exit("\n[LOOK HERE]: %s \n\nPlease check helper:\npython infinio.py --help" % str(e))

    directory = None
    destdirectory = None
    verifydb = None
    checksumdb = None
    action = "write"
    width = 5   
    level = 5   
    filesize = 8192
    numfile = 1
    datapattern = 'fixed'
    lockstrategy = '0:1:1:0:0'
    loglevel = 'INFO'
    taction = '-'
    tdelta = 0;
    aclusers = 'ALL'
    adsstreams='stream1'
    compoundnum = 1
    iteration = 1
    widthqueue = [1]
    levelqueue = [1]
    lockmodequeue = ['EXCLUSIVE']
    blocksizequeue = [8192]
    filesizequeue = [8192]
    numfilequeue = ['.100']
    actionqueue = []
    verifydbqueue = [None]
    checksumdbqueue = [None]
    directoryqueue = [None]
    lockstrategyqueue = ['0:1:1:0:0']
    openstrategyqueue = ['read:20']
    truncatetoqueue = ['-.50']
    appenddeltaqueue = ['+.50']
    targetpercentqueue = [100]
    datapatternqueue = ['fixed']
    seektypequeue = ['forth']
    userqueue = [None]
    aclusersqueue = ['ALL']
    adsstreamsqueue = ['stream1']
    namelengthqueue = [8]
    nameseedqueue = ['random']
    nameprefixqueue = ['']
    encodingqueue = ['utf8']
    symlinkqueue = [0]
    hardlinkqueue = [0]
    fileoffsetqueue = ['0:0']
    destdirectoryqueue = [None]
    compoundnum = 1

    whodefault = {
        'action'       :1,
        'directory'    :1,
        'destdirectory':1,
        'width'        :1,
        'level'        :1,
        'lockmode'     :1,
        'blocksize'    :1,
        'filesize'     :1,
        'numfile'      :1,
        'lockstrategy' :1,
        'openstrategy' :1,
        'truncateto'   :1,
        'appenddelta'  :1,
        'targetpercent':1,
        'datapattern'  :1,
        'seektype'     :1,
        'user'         :1,
        'aclusers'     :1,
        'adsstreams'   :1,
        'verifydb'     :1,
        'checksumdb'   :1,
        'namelength'   :1,
        'nameseed'     :1,
        'nameprefix'   :1,
        'encoding'     :1,
        'symlink'      :1,
        'hardlink'     :1,
        'fileoffset'  :1,
    }

    for o, a in opts:
        if o in ("", "--action"):
            if re.search('\#+', a):
                actionqueue = a.split('#')
                compoundnum = len(actionqueue)

    for o, a in opts:
        if o in ("-d", "--directory"):
            directoryqueue = _compound_string(a, compoundnum, str)
        elif o in ("", "--dest-directory"):
            destdirectoryqueue = _compound_string(a, compoundnum, str)
        elif o in ("", "--action"):
            actionqueue = _compound_string(a, compoundnum, str)
            for i in actionqueue:
                if not i in ('write', 'rewrite', 'move', 'copy', 'open',\
                        'rename', 'delete', 'verify', 'read', 'truncate',\
                        'append', 'list', 'checksum', 'create', 'rewrite',\
                        'set-allowed-acl', 'set-denied-acl', 'remove-acl', \
                        'add-ads', 'update-ads', 'read-ads', 'remove-ads', \
                        'dump-acl', 'wipe-acl', 'crawling-lock'):
                    sys.exit("Invalid value: %s of --action" % i)
        elif o in ("-w", "--width"):
            widthqueue = _compound_string(a, compoundnum)
            whodefault['width'] = 0
        elif o in ("-l", "--level"):
            levelqueue = _compound_string(a, compoundnum)
            whodefault['level'] = 0
        elif o in ("-s", "--file-size"):
            filesizequeue = _compound_string(a, compoundnum, str)
            whodefault['filesize'] = 0
        elif o in ("-b", "--block-size"):
            blocksizequeue = _compound_string(a, compoundnum, str)
            whodefault['blocksize'] = 0
        elif o in ("", "--locking-mode"):
            lockmodequeue = _compound_string(a, compoundnum, str)
            whodefault['lockmode'] = 0
        elif o in ("", "--locking-strategy"):
            lockstrategyqueue = _compound_string(a, compoundnum, str)
            whodefault['lockstrategy'] = 0
        elif o in ("", "--open-strategy"):
            openstrategyqueue = _compound_string(a, compoundnum, str)
            whodefault['openstrategy'] = 0
        elif o in ("-t", "--truncate-to"):
            truncatetoqueue = _compound_string(a, compoundnum, str)
            whodefault['truncateto'] = 0
        elif o in ("", "--append-delta"):
            appenddeltaqueue = _compound_string(a, compoundnum, str)
            whodefault['appenddelta'] = 0
        elif o in ("-k", "--target-percent"):
            sys.exit("Parameter Error: --target-percent is obsoleted, please use --file-number instead")
            targetpercentqueue = _compound_string(a, compoundnum)
            whodefault['targetpercent'] = 0
        elif o in ("-u", "--acl-users"):
            aclusersqueue = _compound_string(a, compoundnum, str)
            whodefault['aclusers'] = 0
        elif o in ("", "--ads-streams"):
            adsstreamsqueue = _compound_string(a, compoundnum, str)
            whodefault['adsstreams'] = 0
        elif o in ("", "--verify-database"):
            verifydbqueue = _compound_string(a, compoundnum, str)
            whodefault['verifydb'] = 0
        elif o in ("", "--checksum-database"):
            checksumdbqueue = _compound_string(a, compoundnum, str)
            whodefault['checksumdb'] = 0
        elif o in ("-n", "--file-number"):
            numfilequeue = _compound_string(a, compoundnum, str)
            whodefault['numfile'] = 0
        elif o in ("-x", "--name-length"):
            namelengthqueue = _compound_string(a, compoundnum)
            whodefault['namelength'] = 0
        elif o in ("", "--name-seed"):
            nameseedqueue = _compound_string(a, compoundnum, str)
            whodefault['nameseed'] = 0
        elif o in ("", "--name-prefix"):
            nameprefixqueue = _compound_string(a, compoundnum, str)
            whodefault['nameprefix'] = 0
        elif o in ("-p", "--data-pattern"):
            datapatternqueue = _compound_string(a, compoundnum, str)
            whodefault['datapattern'] = 0
        elif o in ("", "--io-mode"):
            sys.exit("Parameter --io-mode is obsolote, use --seek-type instead")
        elif o in ("", "--seek-type"):
            seektypequeue = _compound_string(a, compoundnum, str)
            whodefault['seektype'] = 0
        elif o in ("", "--encoding"):
            encodingqueue = _compound_string(a, compoundnum, str)
            whodefault['encoding'] = 0
        elif o in ("-p", "--user"):
            userqueue = _compound_string(a, compoundnum, str)
            whodefault['user'] = 0
        elif o in ("", "--symlink"):
            symlinkqueue = _compound_string(a, compoundnum, str)
            whodefault['symlink'] = 0
        elif o in ("", "--hardlink"):
            hardlinkqueue = _compound_string(a, compoundnum, str)
            whodefault['hardlink'] = 0
        elif o in ("", "--file-offset"):
            fileoffsetqueue = _compound_string(a, compoundnum, str)
            whodefault['fileoffset'] = 0
        elif o in ("", "--ITERATION"):
            iteration = int(a)
        elif o in ("", "--LOG-PATH"):
            glogpath = a
        elif o in ("-z", "--LOG-LEVEL"):
            if a not in MyLogger.LOG_LEVELS.keys():
                raise ValueError("Invalid --LOG-LEVEL!")
            loglevel = a 
        elif o in ("-h", "--help"):
            usage()
        else:
            assert False, "unhandled option" 

    if len(actionqueue) == 0: 
        sys.exit("Parameter Error: --action is required!")

    if len(directoryqueue) == 0 and 'verify' not in actionqueue: 
        sys.exit("Parameter Error: --directory is required!")

    # fulfill the iterator with last value as default, this is ugly code too.
    if len(widthqueue) < compoundnum \
        and whodefault['width'] == 1:
        widthqueue = _compound_string(_join_list(widthqueue),\
            compoundnum, int, widthqueue[::1])
    if len(levelqueue) < compoundnum \
        and whodefault['level'] == 1:
        levelqueue = _compound_string(_join_list(levelqueue), \
            compoundnum, int, levelqueue[::1])
    if len(lockmodequeue) < compoundnum \
        and whodefault['lockmode'] == 1:
        lockmodequeue = _compound_string(_join_list(lockmodequeue), \
            compoundnum, str, lockmodequeue[::1])
    if len(blocksizequeue) < compoundnum \
        and whodefault['blocksize'] == 1:
        blocksizequeue = _compound_string(_join_list(blocksizequeue), \
            compoundnum, str, blocksizequeue[::1])
    if len(filesizequeue) < compoundnum \
        and whodefault['filesize'] == 1:
        filesizequeue = _compound_string(_join_list(filesizequeue), \
            compoundnum, int, filesizequeue[::1])
    if len(numfilequeue) < compoundnum \
        and whodefault['numfile'] == 1:
        numfilequeue = _compound_string(_join_list(numfilequeue), \
            compoundnum, str, numfilequeue[::1])
    if len(actionqueue) < compoundnum \
        and whodefault['action'] == 1:
        actionqueue = _compound_string(_join_list(actionqueue), \
            compoundnum, str, actionqueue[::1])
    if len(lockstrategyqueue) < compoundnum \
        and whodefault['lockstrategy'] == 1:
        lockstrategyqueue = _compound_string(_join_list(lockstrategyqueue), \
            compoundnum, str, lockstrategyqueue[::1])
    if len(openstrategyqueue) < compoundnum \
        and whodefault['openstrategy'] == 1:
        openstrategyqueue = _compound_string(_join_list(openstrategyqueue), \
            compoundnum, str, openstrategyqueue[::1])
    if len(truncatetoqueue) < compoundnum \
        and whodefault['truncateto'] == 1:
        truncatetoqueue = _compound_string(_join_list(truncatetoqueue), \
            compoundnum, str, truncatetoqueue[::1])
    if len(appenddeltaqueue) < compoundnum \
        and whodefault['appenddelta'] == 1:
        appenddeltaqueue = _compound_string(_join_list(appenddeltaqueue), \
            compoundnum, str, appenddeltaqueue[::1])
    if len(targetpercentqueue) < compoundnum \
        and whodefault['targetpercent'] == 1:
        targetpercentqueue = _compound_string(_join_list(targetpercentqueue), \
            compoundnum, int, targetpercentqueue[::1])
    if len(datapatternqueue) < compoundnum \
        and whodefault['datapattern'] == 1:
        datapatternqueue = _compound_string(_join_list(datapatternqueue), \
            compoundnum, str, datapatternqueue[::1])
    if len(seektypequeue) < compoundnum \
        and whodefault['seektype'] == 1:
        seektypequeue = _compound_string(_join_list(seektypequeue), \
            compoundnum, str, seektypequeue[::1])
    if len(userqueue) < compoundnum \
        and whodefault['user'] == 1:
        userqueue = _compound_string(_join_list(userqueue), \
            compoundnum, str, userqueue[::1])
    if len(aclusersqueue) < compoundnum \
        and whodefault['aclusers'] == 1:
        aclusersqueue = _compound_string(_join_list(aclusersqueue), \
            compoundnum, str, aclusersqueue[::1])
    if len(adsstreamsqueue) < compoundnum \
        and whodefault['adsstreams'] == 1:
        adsstreamsqueue = _compound_string(_join_list(adsstreamsqueue), \
            compoundnum, str, adsstreamsqueue[::1])
    if len(verifydbqueue) < compoundnum \
        and whodefault['verifydb'] == 1:
        verifydbqueue = _compound_string(_join_list(verifydbqueue), \
            compoundnum, str, verifydbqueue[::1])
    if len(checksumdbqueue) < compoundnum \
        and whodefault['checksumdb'] == 1:
        checksumdbqueue = _compound_string(_join_list(checksumdbqueue), \
            compoundnum, str, checksumdbqueue[::1])
    if len(namelengthqueue) < compoundnum \
        and whodefault['namelength'] == 1:
        namelengthqueue = _compound_string(_join_list(namelengthqueue), \
            compoundnum, int, namelengthqueue[::1])
    if len(nameseedqueue) < compoundnum \
        and whodefault['nameseed'] == 1:
        nameseedqueue = _compound_string(_join_list(nameseedqueue), \
            compoundnum, str, nameseedqueue[::1])
    if len(nameprefixqueue) < compoundnum \
        and whodefault['nameprefix'] == 1:
        nameprefixqueue = _compound_string(_join_list(nameprefixqueue), \
            compoundnum, str, nameprefixqueue[::1])
    if len(symlinkqueue) < compoundnum \
        and whodefault['symlink'] == 1:
        symlinkqueue = _compound_string(_join_list(symlinkqueue), \
            compoundnum, str, symlinkqueue[::1])
    if len(hardlinkqueue) < compoundnum \
        and whodefault['hardlink'] == 1:
        hardlinkqueue = _compound_string(_join_list(hardlinkqueue), \
            compoundnum, str, hardlinkqueue[::1])
    if len(fileoffsetqueue) < compoundnum \
        and whodefault['fileoffset'] == 1:
        fileoffsetqueue = _compound_string(_join_list(fileoffsetqueue), \
            compoundnum, str, fileoffsetqueue[::1])
    if len(encodingqueue) < compoundnum \
        and whodefault['encoding'] == 1:
        encodingqueue = _compound_string(_join_list(encodingqueue), \
            compoundnum, str, encodingqueue[::1])
    if len(destdirectoryqueue) < compoundnum \
        and whodefault['destdirectory'] == 1:
        destdirectoryqueue = _compound_string(_join_list(destdirectoryqueue), \
            compoundnum, str, destdirectoryqueue[::1])

    mylogger = MyLogger(
            logger_name='infinio', 
            record_path=glogpath, 
            log_level=loglevel)

    logger = mylogger.get_logger()

    newlogheader = 'NEW LOG STARTs @' + time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime()) 
    logger.info("\n==== %s ====" % newlogheader)

    infomsg = '\n'
    for info in opts:
        infomsg += info[0] + "=" + info[1] + '\n'
    logger.info(infomsg)
    count = 1
    totalcount = iteration
    while iteration > 0:
        if totalcount > 1:
            print("\t===| ITERATION %d/%d |===\t" % (count, totalcount))
        for directory, destdirectory, action, width, level, numfile, \
            filesize, blocksize, lockmodes, lockstrategy, openstrategy, \
            checksumdb, truncateto, appenddelta, targetpercent, aclusers, adsstreams,\
            verifydb, namelength, nameseed, nameprefix, encoding, symlink, hardlink, datapattern,\
            fileoffset, seektype, user in zip(directoryqueue, destdirectoryqueue, \
            actionqueue, widthqueue, levelqueue, numfilequeue, \
            filesizequeue, blocksizequeue, lockmodequeue, lockstrategyqueue, \
            openstrategyqueue, checksumdbqueue, truncatetoqueue, appenddeltaqueue, \
            targetpercentqueue, aclusersqueue, adsstreamsqueue, verifydbqueue, \
            namelengthqueue, nameseedqueue, nameprefixqueue, encodingqueue, symlinkqueue, hardlinkqueue, \
            datapatternqueue, fileoffsetqueue, seektypequeue, userqueue):
             
            gfilecount = 0
            gdircount = 0
            gdirs = set()
            grewrite = False
            groot = directory
            print("[action: %s]" % action)
            if width == '-': 
                pass
            else:
                gtreewidth = int(width)
            if level == '-': 
                pass
            else:
                gtreedepth = int(level)
            if blocksize == '-': 
                pass
            else:
                blocksizelist = str(blocksize).split('+')
                if len(blocksizelist) > 1:
                    totalsize = 0
                    sizelist = []
                    for i in blocksizelist:
                        size = int(_convert_size(i))
                        sizelist.append(size)
                        totalsize += size 
                    gblocksizelist = sizelist[:]
                    gblocksize = totalsize
                elif len(blocksizelist) == 1:
                    gblocksize = int(_convert_size(blocksize))
                    gblocksizelist = _convert_size(blocksize)
            if namelength == '-': 
                gnamelength = 8 
                pass
            else:
                gnamelength = int(namelength)
            if nameseed == '-': 
                gnameseed = 'random'
                pass
            else:
                gnameseed = nameseed
            if nameprefix == '-': 
                gnameprefix = ''
                pass
            else:
                gnameprefix = nameprefix
            if encoding == '-': 
                gencoding = 'utf8'
                pass
            else:
                gencoding = encoding
            if symlink == '-':
                pass
            else:
                gsymlinkcount= int(symlink)
            if hardlink == '-':
                pass
            else:
                ghardlinkcount = int(hardlink)
            if fileoffset == '-':
                pass
            else:
                offsetmatch = re.search('^(\d+(\w{1,2})?)(:\d+(\w{1,2})?)?$', fileoffset)
                if not offsetmatch:
                    sys.exit("Invalid value of --file-offset: %s" % fileoffset)
                offsets = fileoffset.split(':')
                if len(offsets) == 1:
                    gstartoffset=int(_convert_size(offsets[0]))
                if len(offsets) == 2:
                    gendoffset = int(_convert_size(offsets[1]))
            if targetpercent == '-': 
                pass
            else:
                gtargetpercent = int(targetpercent)
            if filesize == '-': 
                pass
            else:
                filesize = int(_convert_size(filesize))
            # doing
            if numfile == '-': 
                pass
            else:
                ninfo = numfile.split('.')
                if len(ninfo) == 1:
                    numfile = int(numfile)
                    gnumfile = numfile
                    gfilenummode = 'number'
                elif len(ninfo) == 2:
                    if int(ninfo[1]) > 100: 
                        sys.exit("Invalid value: %s of --file-number, percents should be less than 100"\
                                % numfile)
                    else:
                        gnumfile = 1
                        gnumfilepercent = int(ninfo[1])
                        gfilenummode = 'percent'
                else:
                    sys.exit("Invalid value: %s of --file-number" % numfile)
            if aclusers == '-': 
                pass
            elif aclusers != 'ALL':
                aclusers = _get_range_value(string=aclusers)
            if adsstreams == '-': 
                pass
            else:
                adsstreams = _get_range_value(string=adsstreams)
            if gtargetpercent > 100 or gtargetpercent < 0:
                sys.exit("Invalid value of --target-percent: %s" % gtargetpercent)
            elif gtargetpercent == '-':
                pass
            if datapattern == '-':
                pass
            else:
                patternlist = datapattern.split('+')
                # inline mode
                if len(patternlist) > 1:
                    pattern = []
                    for item in patternlist:
                        if not re.search('^ZERO|ONE|bit:((0|1)+)$|fixed|random|sparse(:(\d)+)?|complex-compress(:\d+){0,2}|compress((:\d+)(:.+)?)?$', item):
                            gfixeddatalist.append(item)
                            gfixeddata=item
                            pattern.append('fixed')
                        elif re.search('^sparse(:(\d)+)?|complex-compress(:\d+){0,2}|compress((:\d+)(:.+)?)?$', item):
                            sys.exit("data pattern: %s is not supported in inline mode" % item)
                        elif re.search('^bit:((0|1)+)$', item):
                            m = re.search('^bit:((0|1)+)?$', item)
                            pattern.append('fixed')
                            hexstr = _convert_binary(m.group(1))
                            gfixeddatalist.append(hexstr)
                        else:
                            pattern.append(_hex_filter(item))
                    datapattern = pattern[:]
                    gfixeddatalist.reverse()
                # usual mode
                elif len(patternlist) == 1:
                    if not re.search('^ZERO|ONE|fixed|random|sparse(:(\d)+)?|complex-compress(:\d+){0,2}|compress((:\d+)(:.+)?)?$', datapattern):
                        if re.search('^bit:((0|1)+)$', datapattern):
                            m = re.search('^bit:((0|1)+)$', datapattern)
                            hexstr = _convert_binary(m.group(1))
                            datapattern = 'fixed'
                            gfixeddata = hexstr
                        else:
                            gfixeddata=_hex_filter(datapattern)
                            datapattern = 'fixed'
            if seektype == '-':
                pass
            elif seektype not in ['forth', 'random', 'back']:
                sys.exit("Invalid value: %s of --io-mode, values values is one of [forth, random, back]" % seektype)
            else:
                gseektype = seektype
            if user == '-':
                pass
            else:
                guser = user
            if lockmodes == '-':
                pass
            elif not re.search('^((EXCLUSIVE|EXCLUSIVE_IO|SHARED|EXCLUSIVE_BLK|EXCLUSIVE_BLK_IO|UNLOCK)\+?)+$', \
                    lockmodes.upper()):
                sys.exit("Invalid value: %s of --locking-mode" % lockmodes)
            if lockstrategy == '-':
                pass
            elif not re.search('^((\d+(\w)?:\d+(\w)?:\d+(\w)?:\d+(\w)?:\d+)\+?)+$', \
                    lockstrategy):
                sys.exit("Invalid value: %s of --locking-strategy" % lockstrategy)
            if openstrategy == '-':
                pass
            elif not re.search('^(read|write)(:\d+)?(:lock)?$', openstrategy):
                sys.exit("Invalid value: %s of --open-strategy" % openstrategy)
            if truncateto == '-': 
                pass
            else: 
                tinfo = truncateto.split('.')
            if appenddelta == '-': 
                pass
            else: 
                ainfo = appenddelta.split('.')
            patternpercent = 50
            if type(datapattern) is str:
                # sparse data pattern
                sparsematch = re.search('^sparse(:\d+)?$', datapattern)
                if sparsematch:
                    sparseres = datapattern.split(':')
                    if len(sparseres) == 1:
                        pass
                    elif len(sparseres) == 2:
                        patternpercent = sparseres[1]
                        datapattern = sparseres[0]
                    else:
                        raise ValueError("Invalid format 'sparse' parameter!")
                    logger.info("\nNOTE The minimal file size for best accuracy of given sparse percentage is 3200KB")

                # compress data pattern
                compressmatch = re.search('^compress((:\d+)(:.+)?)?$', datapattern)
                if compressmatch:
                    compresspattern = None
                    compresses = datapattern.split(':')
                    if len(compresses) == 1:
                        pass
                    elif len(compresses) == 2:
                        patternpercent = compresses[1]
                        datapattern = compresses[0]
                    elif len(compresses) == 3:
                        compresspattern = compresses[2]
                        patternpercent = compresses[1]
                        datapattern = compresses[0]
                    else:
                        raise ValueError("Invalid format of 'compress'")

                # complex compress data pattern
                compressmatch = re.search('^complex-compress(:\d+)?(:\d+)?$', datapattern)
                if compressmatch:
                    compresspattern = None
                    compresses = datapattern.split(':')
                    if len(compresses) == 1:
                        pass
                    elif len(compresses) == 2:
                        patternpercent = compresses[1]
                        datapattern = compresses[0]
                    elif len(compresses) == 3:
                        gnumcompresspattern = compresses[2]
                        gcompresspatternlen = compresses[1]
                        datapattern = compresses[0]
                    else:
                        raise ValueError("Invalid format of 'complex-compress'")
                openmatch = re.search('^(read|write)(:\d+)?(:lock)?$', openstrategy)
                if openmatch:
                    openpattern = None
                    opens = openstrategy.split(':')
                    if len(opens) == 1:
                        gopenmode = opens[0]
                    elif len(opens) == 2:
                        gopenmode = opens[0]
                        gopenduration = opens[1]
                    elif len(opens) == 3:
                        gopenmode = opens[0]
                        gopenduration = opens[1]
                        gopenlock = opens[2]
                    else:
                        raise ValueError("Invalid format of '--open-strategy'")

            # set user
            if guser is not None and guser != 'None':
                _set_user(guser)

            if directory is None and action != 'verify':
                sys.exit("Parameter Error: '--directory=' is required")

            # list action
            if action == 'list':
                if directory is None:
                    sys.exit("Parameter Error: '--directory=' is required")
                _list_tree(directory)

            # copy action
            # move action
            if action == 'copy' or action == 'move':
                if action == 'copy':
                    manipulate = copyfile
                elif action == 'move':
                    manipulate = move
                if directory is None or destdirectory is None:
                    sys.exit("Parameter Error: '--directory=' and '--dest-directory=' are required")
                elif directory == destdirectory:
                    sys.exit("Parameter Error: '--directory=' and '--dest-directory=' are the same, which way doesn't be support for copy | move action")
                if not exists(destdirectory):
                    os.makedirs(destdirectory)

                rootdir = directory 
                rootdestdir = destdirectory 
                dirs= []
                filefound = 0
                for d in _traverse_tree(directory, 'dir'):
                    try: 
                        dirs.append(d)
                        dstdir = d.replace(rootdir, rootdestdir)
                        if not exists(dstdir):
                            os.makedirs(dstdir)
                    except IOError as e:
                        raise RuntimeError("Failed to %s directory %s with exception: \
                                %s" % (action, directory, e))
                # copy files ...
                if gnumfilepercent == 100:
                    _go_through_tree = _traverse_tree
                else:
                    _go_through_tree = _inspect_tree
                for f in _go_through_tree(directory, 'file'):
                    try: 
                        dstfile = f.replace(rootdir, rootdestdir)
                        manipulate(f, dstfile)
                        gfilecount += 1 
                    except IOError as e:
                        logger.exception("Failed to %s directory %s with \
                                exception: %s" % (action, directory, e))
                    _update_progress(gpermitted, gfilecount, \
                            'files transmitted')
                sys.stdout.write('\n')
                if action == 'move' and gnumfilepercent == 100:
                    dirs.reverse()
                    for d in dirs:
                        try: 
                            if isdir(d):
                                os.rmdir(d)
                        except IOError as e:
                            logger.exception("Failed to delete directory \
                                    %s with exception: %s" % (action, directory, e))
                            sys.exit()

            # rename action
            if action == 'rename':
                dirs= []
                dstname = None
                if gnumfilepercent == 100:
                    renamegen = _traverse_tree(directory, 'file')
                    for f in renamegen:
                        try: 
                            if gnameprefix != '':
                                dstname = os.path.join(os.path.dirname(f), gnameprefix\
                                        + _random_string(string_size=gnamelength-len(gnameprefix), encoding=gencoding))
                            else:
                                dstname = os.path.join(os.path.dirname(f), \
                                        _random_string(string_size=gnamelength, encoding=gencoding))

                            os.rename(f, dstname)
                            gfilecount += 1 
                        except IOError as e:
                            logger.exception("Failed to rename %s with exception: %s" \
                                % (tree_root, e))
                        _update_progress(0, gfilecount, 'files name updated')
                    sys.stdout.write('\n')
                    logger.info("All files in tree were renamed")

                else: # need use _inspect_tree to audit the number of total files
                    logger.info("Partly manipulating file tree requires auditing total number of files, please be patient ...")
                    dirs= []
                    renamegen = _inspect_tree(directory, 'file')
                    for f in renamegen:
                        try: 
                            if gnameprefix != '':
                                dstname = os.path.join(os.path.dirname(f), gnameprefix\
                                        + _random_string(string_size=gnamelength-len(gnameprefix), encoding=gencoding))
                            else:
                                dstname = os.path.join(os.path.dirname(f), \
                                        _random_string(string_size=gnamelength, encoding=gencoding))
                            os.rename(f, dstname)
                            gfilecount += 1 
                        except IOError as e:
                            logger.exception("Failed to rename %s with exception: %s" \
                                % (tree_root, e))

                        _update_progress(gpermitted, gfilecount, 'files name updated')
                    sys.stdout.write('\n')
                    logger.info("%d of files in tree were renamed" % gfilecount)


            if action == 'delete':
                dirs= []
                dircount = 0
                if gnumfile == 0:
                    prefixre = re.escape(gnameprefix)
                    deletegen = list(_traverse_tree(directory, 'dir+link'))
                    for d in deletegen[::-1]:
                        if gnameprefix != '':
                            if re.search(prefixre, d):
                                if _islink(file_path=d):
                                    os.unlink(d)
                                    continue
                                os.rmdir(d)
                                dircount += 1
                                _update_progress(0, dircount, 'directories deleted')
                        else:
                            if _islink(file_path=d):
                                os.unlink(d)
                                continue
                            os.rmdir(d)
                            dircount += 1
                            _update_progress(0, dircount, 'directories deleted')

                elif gnumfilepercent == 100:
                    deletegen = _traverse_tree(directory, 'both+link')
                    for f in deletegen:
                        try:
                            if _islink(file_path=f):
                                os.unlink(f)
                            elif isdir(f):
                                dirs.append(f)
                            else:
                                os.remove(f)
                                gfilecount += 1 
                                _update_progress(0, gfilecount, 'files deleted')
                        except Exception as e:
                            if re.search('No such file or directory', str(e)):
                                logger.warning("Failed to remove directory %s with exception: %s" % (f, str(e)))
                                pass
                            else:
                                logger.exception("Failed to remove file %s with exception: %s" \
                                    % (f, e))
                                sys.exit(9001)
                    sys.stdout.write('\n')
                    for d in dirs[::-1]:
                        try:
                            os.rmdir(d)
                            dircount += 1 
                            _update_progress(0, dircount, 'directories deleted')
                        except Exception as e:
                            if re.search('\.etc', str(e)):
                                logger.warning("Failed to remove directory %s with exception: %s" % (d, str(e)))
                                pass
                            elif re.search('No such file or directory', str(e)):
                                logger.warning("Failed to remove directory %s with exception: %s" % (d, str(e)))
                                pass
                            else:
                                logger.exception("Failed to remove directory %s with exception: %s" \
                                    % (d, e))
                                sys.exit(9001)
                    os.rmdir(groot)
                else: # need use _inspect_tree to audit the number of total files
                    logger.info("Partly manipulating file tree requires auditing total number of files, please be patient ...")
                    deletelink = _traverse_tree(directory, 'link')
                    for l in deletelink:
                        os.unlink(l)
                    deletegen = _inspect_tree(directory, 'file')
                    for f in deletegen:
                        try:
                            os.remove(f)
                            gfilecount += 1
                        except Exception as e:
                            if re.search('No such file or directory', str(e)):
                                logger.warning("Failed to remove directory %s with exception: %s" % (f, str(e)))
                                pass
                            else:
                                logger.exception("Failed to remove file %s with exception: %s" \
                                    % (f, e))
                                sys.exit(9001)
                        _update_progress(gpermitted, gfilecount, 'deleted')
                sys.stdout.write('\n')
                logger.info("Total directories were deleted: %d" % dircount)
                logger.info("Total files were deleted: %d" % gfilecount)

            elif action == 'write' or action == 'create': 
                if gtreedepth * gnamelength + gnamelength > 4000:
                    sys.exit("ERROR: Given parameters --level and --name-length build the max path length exceeds 4000, which size is a problem to python to deal with, please give the moderate values to these 2 parameters")
                logger.info("File tree is under deploying ...")
                datacheck = False
                if action == 'create':
                    datacheck = True
                _create_tree(
                    tree_root=directory, 
                    tree_width=gtreewidth, 
                    tree_depth=gtreedepth-1, 
                    )
                _deploy_file(
                    tree_root=directory, 
                    file_size=filesize, 
                    file_number=gnumfile,
                    pattern_percent=patternpercent,
                    data_pattern = datapattern,
                    mode = gseektype,
                    data_check = datacheck,
                )
                sys.stdout.write('\n')
                logger.info("create link if specified create soft or hard link...")
                _create_link(path=directory)
                logger.info("Total created number of direcotry: %d" % gdircount)
                logger.info("Total created number of file: %d" % gfilecount)
                if os.name == 'nt' and datapattern == 'sparse':
                    logger.info("NOTE: On Windows Platform, created sparse files need to be set flag to reflect their real allocated size by command 'fsutil sparse setflag [file path]'")

            # action rewrite
            elif action == 'rewrite':
                datacheck = True
                grewrite = True
                _set_fixed_buffer(gblocksize, gfixeddata)
                if gnumfilepercent == 100:
                    for f in _traverse_tree(directory, 'file'):
                        filesize = getsize(f)
                        try:
                            if patternpercent > 0 and datapattern == 'sparse':
                                _punch_file(f, filesize, patternpercent, datacheck, grewrite, gseektype)
                            elif datapattern == 'compress':
                                _compress_file(f, filesize, gblocksize, \
                                        patternpercent, compresspattern, datacheck, grewrite, gseektype, gstartoffset, gendoffset)
                            elif datapattern == 'complex-compress':
                                _advance_compress_file(f, filesize, gblocksize, \
                                        gcompresspatternlen, gnumcompresspattern, datacheck, grewrite, gseektype, gstartoffset, gendoffset)
                            else:
                                _write_file(f, filesize, datapattern, datacheck, grewrite, gseektype, gstartoffset, gendoffset)
                            gfilecount += 1 
                        except IOError as e:
                            logger.error("Exception caught while rewriting file: %s (%s)" % (f, str(e)))
                            raise IOError(str(e))
                        # update progress
                        _update_progress(0, gfilecount, 'files have been re-written')
                    sys.stdout.write('\n')
                    logger.info("create link if specified create soft or hard link when rewrite...")
                    _create_link(path=directory)
                else: # need use _inspect_tree to audit the number of total files
                    logger.info("Partly manipulating file tree requires auditing total number of files, please be patient ...")
                    for f in _inspect_tree(directory, 'file'):
                        filesize = getsize(f)
                        try:
                            if patternpercent > 0 and datapattern == 'sparse':
                                _punch_file(f, filesize, patternpercent, datacheck, grewrite, seektype)
                            elif datapattern == 'compress':
                                _compress_file(f, filesize, gblocksize, \
                                        patternpercent, compresspattern, datacheck, grewrite, seektype, gstartoffset, gendoffset)
                            elif datapattern == 'complex-compress':
                                _advance_compress_file(f, filesize, gblocksize, \
                                        gcompresspatternlen, gnumcompresspattern, datacheck, grewrite, seektype, gstartoffset, gendoffset)
                            elif datapattern == 'fixed' \
                                    or datapattern == 'ZERO' \
                                    or datapattern == 'ONE' \
                                    or datapattern == 'random':
                                _write_file(f, filesize, datapattern, datacheck, grewrite, seektype, gstartoffset, gendoffset)
                            gfilecount += 1 
                        except IOError as e:
                            logger.error("Exception caught while rewriting file: %s (%s)" % (f, str(e)))
                            raise IOError(str(e))
                        _update_progress(gpermitted, gfilecount, 'files rewrote')
                    sys.stdout.write('\n')
                    logger.info("create link if specified create soft or hard link when rewrite...")
                    _create_link(path=directory)
                logger.info("Total files were rewrote: %d" % gfilecount)

            elif action == 'checksum':
                # create database for future verification
                logger.info("Creating database for verification")
                if checksumdb is None:
                    dbpath = join('cksum_db_' + time.strftime("%Y%m%d%H%M%S", time.localtime()) + '.txt')
                else:
                    dbpath = join(checksumdb)
                _create_checksum_db(dbpath)
                _checksum_tree(directory, dbpath) 
                logger.info("\nChecksum database: %s created" % dbpath)

            elif action == 'verify': 
                if verifydb is None: 
                    sys.exit("Parameter Missing: --verify-database= is required!")
                srcdb, destdb = verifydb.split(':')
                if not exists(srcdb) or not exists(destdb):
                    sys.exit("ERROR: Given database file(s) doesn't exist!")
                _compare_database(srcdb, destdb)
                logger.info("Given database: [%s]vs[%s] were verified" \
                        % (srcdb, destdb))

            elif action == 'append':
                _set_fixed_buffer(gblocksize, gfixeddata)
                appendmode = None
                if len(ainfo) == 2:
                    appendmode = '+'
                    delta = int(ainfo[1])
                elif len(ainfo) == 1:
                    delta = int(_convert_size(ainfo[0]))
                else:
                    sys.exit("Invalid value: %s of --append-delta" % numfile)
                if gnumfilepercent == 100:
                    for f in _traverse_tree(directory):
                        try: 
                            if isfile(f) and not _islink(file_path=f):
                                _append_file(file_path=f, mode=appendmode, \
                                        data_pattern=datapattern, delta=delta)
                                gfilecount += 1
                            # update progress
                            _update_progress(0, gfilecount, 'files appended')
                        except IOError as e:
                            logger.exception("Failed to append %s with exception:\
                                    %s"% (directory, e))
                            sys.exit(9004)
                    sys.stdout.write('\n')
                else: # need use _inspect_tree to audit the number of total files
                    logger.info("Partly manipulating file tree requires auditing total number of files, please be patient ...")
                    for f in _inspect_tree(directory, 'file'):
                        try: 
                            _append_file(file_path=f, mode=appendmode, \
                                    data_pattern=datapattern, delta=delta)
                            gfilecount += 1
                            _update_progress(gpermitted, gfilecount, \
                                    'files appended')
                        except IOError as e:
                            logger.exception("Failed to append %s with exception:\
                                    %s" % (directory, e))
                            sys.exit(9004)
                    sys.stdout.write('\n')
                logger.info("Total files were appended: %d" % gfilecount)

            elif action == 'read':
                greadcount = 0
                if gnumfilepercent == 100:
                    for f in _traverse_tree(directory, 'file'):
                        try: 
                            _read_file(f, gblocksize, gseektype, gstartoffset, gendoffset)
                            gfilecount += 1
                        except Exception as e:
                            logger.exception("Failed to read %s with exception:\
                                    %s"% (directory, e))
                            sys.exit(9005)
                    sys.stdout.write('\n')
                else: # need use _inspect_tree to audit the number of total files
                    logger.info("Partly manipulating file tree requires auditing total number of files, please be patient ...")
                    for f in _inspect_tree(directory, 'file'):
                        try: 
                            _read_file(f, gblocksize, gseektype, gstartoffset, gendoffset)
                            gfilecount += 1 
                        except Exception as e:
                            logger.exception("Failed to read %s with exception:\
                                    %s" % (directory, e))
                            sys.exit(9005)
                    sys.stdout.write('\n')


            elif action == 'truncate':
                mode = None
                if len(tinfo) == 2:
                    if tinfo[0] != '+' and tinfo[0] != '-':
                        raise ValueError("Truncate mode is either [+] or [-], ex: +.25")
                    else:
                        mode = tinfo[0]
                        delta = int(tinfo[1])
                if len(tinfo) == 1:
                        delta = int(_convert_size(tinfo[0]))
                if gnumfilepercent == 100:
                    for f in _traverse_tree(directory, 'file'):
                        try: 
                            _truncate_file(file_path=f, mode=mode, delta=delta)
                            gfilecount += 1
                            # update progress
                            _update_progress(0, gfilecount, 'files truncated')
                        except IOError as e:
                            logger.exception("Failed to truncate %s with exception:\
                                    %s"% (directory, e))
                            sys.exit(9005)
                    sys.stdout.write('\n')
                else: # need use _inspect_tree to audit the number of total files
                    logger.info("Partly manipulating file tree requires auditing total number of files, please be patient ...")
                    for f in _inspect_tree(directory, 'file'):
                        try: 
                            _truncate_file(file_path=f, mode=mode, delta=delta)
                            gfilecount += 1 
                            _update_progress(gpermitted, gfilecount, \
                                    'files truncated')
                        except IOError as e:
                            logger.exception("Failed to truncate %s with exception:\
                                    %s" % (directory, e))
                            sys.exit(9005)
                    sys.stdout.write('\n')
                logger.info("Total files were truncated: %d" % gfilecount)

            elif action == 'open':
                OPEN_MODE = {
                    'write' : 'EXCLUSIVE',
                    'read'  : 'SHARED',
                }

                if gopenlock == 'lock' and os.name == 'posix':
                    lockme = _get_posix_lock
                elif os.name == 'nt' and os.name == 'nt':
                    lockme = _get_nt_lock
                else:
                    lockme = None

                _massive_open(directory, OPEN_MODE[gopenmode], gopenduration, lockme)

            elif action == 'set-allowed-acl'  \
                    or action == 'set-denied-acl' \
                    or action == 'remove-acl' \
                    or action == 'dump-acl' \
                    or action == 'wipe-acl':
                sidlist = []
                if os.name == 'nt':
                    import win32security as ws
                    import ntsecuritycon as nsc
                    import win32api
                    # find SIDs
                    _set_dacl_ace = _set_ntfs_dacl_ace 
                    _del_dacl_ace = _del_ntfs_dacl_ace 
                    _dump_dacl_ace = _dump_ntfs_dacl_ace 
                    if aclusers != 'ALL':
                        sidlist = _find_sids(users=aclusers, info_type='sid', 
                                ignore_absent_user=True)
                    logger.info("Manipulating Windows(NTFS) ACL ACEs ...")
                elif os.name == 'posix':
                    import pwd
                    from subprocess import check_call as block_run
                    from subprocess import check_output as nonblock_run
                    _set_dacl_ace = _set_nfs4_ace 
                    _del_dacl_ace = _del_nfs4_ace 
                    _dump_dacl_ace = _dump_nfs4_ace 
                    if aclusers != 'ALL':
                        sidlist = [str(_user_to_uid(u)) for u in aclusers]
                        while '-1' in sidlist:
                            sidlist.remove('-1')
                    logger.info("Manipulating NFSv4 ACL ACEs ...")

                if action == 'set-allowed-acl': 
                    if len(sidlist) > 600:
                        sys.exit("Too much users to be able to hanlde, recommand less than 600 is moderate to NFSv4 ACL")
                    elif len(sidlist) == 0:
                        logger.exception("None of given users were found, no ACL manipulation will be executed")
                        sys.exit(9010)
                    for f in _traverse_tree(directory):
                        _set_dacl_ace(path=f, sids=sidlist, ace_type='allowed')
                        gfilecount += 1
                        _update_progress(0, gfilecount, 'Allowed ACL added')
                    sys.stdout.write('\n')
                    logger.info("Totally %d files were Allowed ACL added" % gfilecount)
                if action == 'set-denied-acl': 
                    for f in _traverse_tree(directory):
                        _set_dacl_ace(path=f, sids=sidlist, ace_type='denied')
                        gfilecount += 1
                        _update_progress(0, gfilecount, 'Denied ACL added')
                    sys.stdout.write('\n')
                    logger.info("Totally %d files were Denied ACL added" % gfilecount)
                if action == 'remove-acl': 
                    if len(sidlist) == 0:
                        sys.exit("ERROR: None ACL removed, please use parameter --acl-users= to specify the users")
                    for f in _traverse_tree(directory):
                        _del_dacl_ace(path=f, sids=sidlist)
                        gfilecount += 1
                        _update_progress(0, gfilecount, 'ACL ACEs removed')
                    sys.stdout.write('\n')
                    logger.info("Totally %d files were ACL removed" % gfilecount)
                if action == 'dump-acl': 
                    dumppath = 'acl-dump' + '_' + time.strftime("%Y%m%d%H%M%S", time.localtime()) + '.csv'
                    title = 'PATH' + ',' + 'TYPE' + ',' + 'FLAG' + ',' + \
                            'MASK/PERMISSIONs' + ',' + 'USER_NAME' + ',' + 'SID/UID' + '\n'
                    with open(dumppath, 'a') as f:
                        f.write(title)
                    for f in _traverse_tree(directory):
                        _dump_dacl_ace(path=f, users=aclusers, dump_path=dumppath)
                        gfilecount += 1
                        _update_progress(0, gfilecount, 'ACL ACEs dumped')
                    sys.stdout.write('\n')
                    logger.info("ACEs of all files were dumped to file: %s" % dumppath)
                if action == 'wipe-acl': 
                    if os.name == 'nt':
                        for f in _traverse_tree(directory, 'file'):
                            _set_dacl_ace(path=f, sids='ALL', ace_type='wipe')
                            gfilecount += 1
                            _update_progress(0, gfilecount, 'ACL wipped')
                    if os.name == 'posix':
                        for f in _traverse_tree(directory):
                            _del_nfs4_ace(path=f, sids='ALL')
                            gfilecount += 1
                            _update_progress(0, gfilecount, 'ACL wipped')
                    sys.stdout.write('\n')
                    logger.info("Totally %d files were ACL wipped" % gfilecount)
            # action ads 
            elif action == 'add-ads' \
                    or action == 'remove-ads' \
                    or action == 'read-ads' \
                    or action == 'update-ads':
                if os.name == 'posix':
                    logger.info("Here is POSIX platform, be sure you're manipulating a CIFS share")
                # streams 
                _set_fixed_buffer(gblocksize, gfixeddata)
                if gnumfilepercent == 100:
                    for f in _traverse_tree(directory, 'both'):
                        try: 
                            if action == 'add-ads':
                                _add_ads(f, adsstreams, filesize, datapattern, seektype)
                            elif action == 'update-ads':
                                _update_ads(f, adsstreams, filesize, datapattern, seektype)
                            elif action == 'read-ads':
                                greadcount = 0
                                _read_ads(f, adsstreams, gblocksize, seektype)
                                sys.stdout.write('\n')
                            elif action == 'remove-ads':
                                _remove_ads(f, adsstreams)
                            gfilecount += 1
                            # update progress
                            _update_progress(0, gfilecount, 'entries ADS manipulated')
                        except IOError as e:
                            logger.error("Exception caught while manipulating ADS on file: %s (%s)" % (f, str(e)))
                            raise IOError(str(e))
                    sys.stdout.write('\n')
                else: # need use _inspect_tree to audit the number of total files
                    logger.info("Partly manipulating file tree requires auditing total number of files, please be patient ...")
                    logger.info("Partly manipulating ADS on file tree only supports on files")
                    for f in _inspect_tree(directory, 'both'):
                        try: 
                            if action == 'add-ads':
                                _add_ads(f, adsstreams, filesize, datapattern, seektype)
                            elif action == 'update-ads':
                                _update_ads(f, adsstreams, filesize, datapattern, seektype)
                            elif action == 'remove-ads':
                                _remove_ads(f, adsstreams)
                            gfilecount += 1 
                            _update_progress(gpermitted, gfilecount, \
                                    'entries ADS manipulated')
                        except IOError as e:
                            logger.error("Exception caught while manipulating ADS on file: %s (%s)" % (f, str(e)))
                            raise IOError(str(e))
                    sys.stdout.write('\n')
                logger.info("Total files were performed action %s: %d" \
                        % (action, gfilecount))

            elif action == 'crawling-lock':
                if platform == 'posix':
                    _get_lock = _get_posix_lock
                elif platform == 'nt':
                    _get_lock = _get_nt_lock
                else:
                    sys.exit("%s is unsupported platform!" % os.name)

                allstrategydicts = _digest_locking_strategy(lockstrategy)
                allmodes = lockmodes.upper().split('+')
                # this is used for data verifiation.
                targetdata = None 
                datamodified = 0
                lockedbytes = dict()
                fileinfo = None
                openedfiles = []
                openedpaths = []
                if len(allstrategydicts) != len(allmodes):
                    sys.exit("Invalid format of --locking-mode or --locking-strategy")
                for f in _traverse_tree(directory, 'file'):
                    for lockmode, strategydict in zip(allmodes, allstrategydicts):
                        if f not in openedpaths:
                            fileinfo =  _get_fileinfo(file_path=f, open_mode=lockmode)
                            openedfiles.append(fileinfo[0])
                            openedpaths.append(f)
                        # prepare the data to be wrote to each byte-range
                        # then will be compared to the read back content 
                        lockcount = 0
                        if lockmode == 'EXCLUSIVE_IO' or lockmode == 'EXCLUSIVE_BLK_IO':
                            targetdata = _get_rand_buffer(int(strategydict['length']), \
                                    gdatabarn) 
                        else:
                            targetdata = None

                        if strategydict['length'] == 0:
                            length = 'whole-file'
                        else:
                            length = strategydict['length']
                        logger.info("Starting to lock file %s with locking strategy:  \
                                \nlocking mode      : %s \
                                \nstart offset      : %s \
                                \nbyte-range length : %s \
                                \ninterval length   : %s \
                                \nstop offset       : %s \
                                \nholing duration   : %s seconds"
                                % (fileinfo[2], lockmode, 
                                        strategydict['start'],
                                        length,
                                        strategydict['step'],
                                        strategydict['stop'],
                                        strategydict['duration']))
                        # byteinfo: (offest, length)
                        for byteinfo in _get_byte_range(fileinfo[1], 
                                strategydict['start'], 
                                strategydict['length'], 
                                strategydict['step'], 
                                strategydict['stop']):
                            try:
                                if lockmode == 'UNLOCK' \
                                        and (fileinfo[0], byteinfo[0], byteinfo[1]) \
                                        not in lockedbytes.keys():
                                    logger.debug("there isn't any lock on [%d, %d]" \
                                            % (byteinfo[0], byteinfo[1]))
                                    pass    
                                else:
                                    if (fileinfo[0], byteinfo[0], byteinfo[1]) \
                                            in lockedbytes.keys()\
                                            and platform == 'nt': 
                                        # nt lock doesn't support upgrade/downgrade
                                        _get_lock(fileinfo[0], 'UNLOCK', \
                                                byteinfo[0], byteinfo[1], None)

                                    _get_lock(fileinfo[0], lockmode, 
                                            byteinfo[0], byteinfo[1], targetdata)
                            except IOError as e:
                                if str(e) == "11":
                                    sys.stdout.write('\n')
                                    logger.error("byte-range [%d-%d]: Resource \
                                            temporary unavailable" % \
                                            (byteinfo[0], byteinfo[0]+byteinfo[1]))
                                    continue
                                elif str(e) == "ENOLCK":
                                    sys.stdout.write('\n')
                                    logger.info("Lock table full, will unlock " \
                                            + "after %s seconds ..." \
                                            % strategydict['duration'])
                                    time.sleep(int(strategydict['duration']))
                                    logger.info("Locks holding duration timeout...")
                                    unlockcount = 0
                                    totalsetlock = len(lockedbytes.keys())
                                    for lock in lockedbytes.keys():
                                        try:
                                            _get_lock(lock[0], 'UNLOCK', 
                                                        lock[1], lock[2], targetdata)
                                            unlockcount += 1
                                            _update_progress(totalsetlock, \
                                                    unlockcount, 'byte-range unlocked')
                                            del lockedbytes[lock]
                                        except IOError as e:
                                            sys.exit(str(e))

                                else:
                                    logger.error("Error happened while " \
                                            + "locking: %s" % str(e))
                            if lockmode != 'UNLOCK':
                                lockedbytes[(fileinfo[0], byteinfo[0], \
                                        byteinfo[1])] = lockmode
                                lockcount += 1
                                _update_progress(gnumlock, lockcount, \
                                    'byte-range locks created')
                            else:
                                if (fileinfo[0], byteinfo[0], byteinfo[1]) \
                                        not in lockedbytes.keys():
                                    logger.debug("there isn't any lock on [%d, %d]" \
                                            % (byteinfo[0], byteinfo[1]))
                                    pass    
                                else:
                                    lockcount += 1
                                    _update_progress(gnumlock, lockcount, \
                                        'byte-range locks unlocked')
                                    del lockedbytes[(fileinfo[0], byteinfo[0], \
                                            byteinfo[1])]  

                        gnumlock = 0 # rest for auditing next file
                        lockcount = 0 # rest for auditing next file
                        sys.stdout.write('\n')
                        logger.info("Target locks created and in holding, " \
                                + "will unlock after %s seconds ..." \
                                % strategydict['duration'])
                        time.sleep(int(strategydict['duration']))
                    logger.info("Locks holding duration timeout...")
                    logger.info("Start to verify and unlock byte-ranges")
                    totalsetlock = len(lockedbytes.keys())
                    if len(lockedbytes.keys()) > 0:
                        unlockcount = 0
                        for lock in lockedbytes.keys():
                            try:
                                data = targetdata
                                if lockedbytes[lock] == 'SHARED':
                                    data =None
                                _get_lock(lock[0], 'UNLOCK', lock[1], \
                                        lock[2], data)
                                unlockcount += 1
                                _update_progress(totalsetlock, \
                                        unlockcount, 'byte-range unlocked')
                                del lockedbytes[lock]
                            except IOError as e:
                                sys.exit(str(e))
                        sys.stdout.write('\n')
                    else:
                        logger.info("There's no existing lock")

                while len(openedfiles) > 0:
                    fh = openedfiles.pop()
                    fh.close()
                    openedpaths.pop()
                    logger.info("Closing file: %s" % fh.name)
        iteration -= 1
        count += 1

    logger.info("NOTE: Logs were stored in file: %s" % glogpath)
