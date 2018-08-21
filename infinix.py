import sys
import paramiko
import os
import time
import logging

from collections import defaultdict


class Client:
    """ client host
    A client object is able to support multiple remote processes
    """
    port = 22
    handler = logging.StreamHandler()
    logger = logging.getLogger()
    logger.setLevel(os.environ.get("LOG_LEVELS", "DEBUG"))
    logger.addHandler(handler)

    def __init__(self, ip=None, name='test', user='root', password='Password123!'):
        """ initialize client host
        """
        self.name = name
        self.user = user
        self.password = password
        self.ip = ip
        self.channel_status = dict() # a dict tracks the status of channels {channel: is_active}
        self.jobs = dict()
        self.client = paramiko.SSHClient()
        self.client.load_system_host_keys()
        self.client.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())
        self.client.connect(self.ip, self.port, self.user, self.password)

    def equip(self, target=None ):
        """ deploy the tool to be executed on the client
        """
        sftp = self.client.open_sftp()
        sftp.put(target, '/tmp/' + os.path.basename(target))
        sftp.close()

    def run_async(self, command):
        """ execute given command asynchronously
        """
        channel = self.client.get_transport().open_session()
        channel.exec_command(command)
        channel.shutdown_write()
        self.channel_status[channel] = True

    def is_running(self):
        """ indicates if there's command runing on client still
        """
        return (True in [status for status in self.channel_status.values()])

    def poll(self, timeout=5):
        """
        for chn in self.channel_status:
            stdout = chn
            stdout_chunks.append(stdout.channel.recv(len(stdout.channel.in_buffer)))
        """
        for ch in self.channel_status.keys():
            if self.channel_status[ch]:
                if ch.recv_ready():
                    for line in ch.recv(len(ch.in_buffer)).rstrip().split('\n'):
                        self.logger.info("%s [%s][%s][chn-%d][stdout]: %s %s" % \
                                (bcolors.OKGREEN, time.time(), self.ip, ch.get_id(), line, bcolors.ENDC))
                if ch.recv_stderr_ready() and len(ch.recv_stderr(len(ch.in_buffer))) > 0:
                    for line in ch.recv_stderr(len(ch.in_buffer)).rstrip().split('\n'):
                        self.logger.error("%s [%s][%s][chn-%d][stderr]: %s %s" % \
                                (bcolors.FAIL, time.time(), self.ip, ch.get_id(), line, bcolors.ENDC))
                if ch.exit_status_ready():
                    # channel was closed
                    self.channel_status[ch] = False


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

