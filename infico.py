import sys
import paramiko
import select
import os
import pdb

from collections import defaultdict

class Client:
    """ client host
    A client object is able to support multiple remote processes
    """
    port = 22

    def __init__(self, ip=None, name='test', user='root', password='Password123!'):
        """ initialize client host
        """
        self.name = name
        self.user = user
        self.password = password
        self.ip = ip
        self.channels = []
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
        self.fh = channel.makefile()
        channel.exec_command(command)
        channel.shutdown_write()
        self.channels.append(channel)

        print("this is indicating if blocing")


    def poll(self, timeout=5):
        stdout_chunks = []
        """
        for chn in self.channels:
            stdout = chn
            stdout_chunks.append(stdout.channel.recv(len(stdout.channel.in_buffer)))
        """
        
        readq, _, _ = select.select(self.channels, [], [], timeout)
        print("get %d fh in queue" % len(readq))
        for ch in readq:
            if ch.recv_ready():
                print(ch.recv(len(ch.in_buffer)))
                return True
            if ch.recv_stderr_ready():
                print(ch.recv_stderr(1024))
                return True
            if ch.exit_status_ready():
                return False
            else:
                print("Invalid status")
                return True 




