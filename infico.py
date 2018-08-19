import sys
import paramiko
import select
import os

from collections import defaultdict

class Client:
    """ client host
    A client object is able to support multiple remote processes
    """
    port = 22

    def __init__(self, ip=None, user='root', password='Password123!'):
        """ initialize client host
        """
        self.user = user
        self.password = password
        self.ip = ip
        self.jobs = dict()
        self.client = paramiko.SSHClient()
        self.client.load_system_host_keys()
        self.client.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())
        self.client.connect(self.ip, self.port, self.user, self.password)
        self.out_fhs = []
        self.err_fhs = []

    def equip(self, target=None ):
        """ deploy the tool to be executed on the client
        """
        sftp = self.client.open_sftp()
        sftp.put(target, '/tmp/' + os.path.basename(target))
        sftp.close()
    
    def run_async(self, command):
        """ execute given command asynchronously
        """
        ssh = self.client.get_transport().open_channel()
        std_in, std_out, std_err = ssh.exec_command(command)
        std_in.close()
        std_in.channel.shutdown_write()
        self.out_fhs.append(std_in)
        self.err_fhs.append(std_err)
        self.jobs[ssh] = (std_in, std_err)

    def poll(self, timeout=5):
        """ wait for remote command complete
        """
        stdout_chunks = []
        for job in self.jobs:
            stdout = job[1]
            stdout_chunks.append(stdout.channel.recv(len(stdout.channel.in_buffer)))

        channels = [job for job in self.jobs.keys()]
        readq, _, _ = select(channels, [], [], timeout)
        for ch in readq:
            if not ch.closed():
                if ch.recv_ready():
                    stdout_chunks.append(ch.stdout.recv(len(ch.stdout.in_buffer)))
                if ch.recv_stderr_ready():
                    stdout_chunks.append(ch.stderr.recv(len(ch.stderr.in_buffer)))
            else:
                del self.jobs[ch]





