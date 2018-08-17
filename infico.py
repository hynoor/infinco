# collaberative infinio
import sys
import paramiko
import select
import os

from collections import defaultdict

class Client:
    """ client host
    """
    port = 22
    def __init__(self, ip=None, user='root', password='Password123!'):
        """ initialize client host
        """
        self.user = user
        self.password = password
        self.ip = ip
        self.jobs = []
        self.running = []
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
    
    def run(self, command):
        """ execute given command sychronizely 
        """
        job = self.client.get_transport.open_session()
        job.exec_command(command)
        msg = job.recv()
        rc = job.recv_exit_status() # wait till job exit
        if rc == -1:
            raise Exception("Remotely process failed: %s" % msg)

    def run_async(self, command):
        """ execute given command asychronizely 
        """
        job = self.client.get_transport.open_session()
        job.exec_command(command)
        self.jobs.append(job)

        return self.job

    def poll(self):
        """ poll the status of the async job(s), respond with the output
        """
        stdout = []
        all_ready = True
        for j in self.jobs:
            if j.recv_exit_status()
                pass
            else j.recv_ready():
                all_ready = False
                stdout.append(j.recv(1024))
        return stdout 

    @property
    def running(self):
        return self.running

class Commander:
    """ Collaborative version of Infinio w/ parallelism embeded
    """
    output_size = 1024    
    partners = []
    ssh_clnts = []
    channels = []
    active_jobs = []
    complete_jobs = []
    status = defaultdict()
    def __init__(self, partner_info=dict(), target=None, num_job=1):
        self.num_job = num_job
        for pn, pc in partner_info.items():
            pu, pp = pc.split(':', 2)
            self.partners.append((pn, pu, pp))
            self.target = target

    def connect(self):
        """ connect the partner host(s)
        """
        for p in self.partners:
            clnt = paramiko.SSHClient()
            clnt.load_system_host_keys()
            clnt.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())
            clnt.connect(p[0], 22, p[1], p[2])
            self.ssh_clnts.append(clnt)

    def deploy(self):
        """ transfer and deploy infinio.py to partner host(s)
        """
        for clnt in self.ssh_clnts:
            sftp = clnt.open_sftp()
            sftp.put('./' + self.target, '/tmp/' + self.target)
            sftp.close()

    def open(self):
        """ open sessions for subsequent execution
        """
        for clnt in self.ssh_clnts:
            session = clnt.get_transport().open_session()
            self.channels.append(session)
        print("Number of Channels: {}".format(len(self.channels)))

    def run(self, **kwargs):
        """ start to execute infinio across partners
        """
        parameters = [self.target]
        for k, v in kwargs.items():
            parameters.append(k + '=' + v)
        command = ' '.join(parameters)
        print("command to execute: {}".format(command))
        for chn in self.channels:
            chn.exec_command(command)
            self.active_jobs.append(chn)

    def wait(self, timeout):
        """ wait for job done
        """
        for chn in self.active_jobs:
            print("Number of active jobs: {}".format(len(self.active_jobs)))
            while not chn.exit_status():
                if chn.recv_ready():
                    self.status[chn.get_id()] = 'stdout'
                elif chn.recv_stderr_ready():
                    self.status[chn.get_id()] = 'stderr'
            stdout_fhs = [job for job in self.active_jobs if self.status[job.get_id()] == 'stdout'],
            stderr_fhs = [job for job in self.active_jobs if self.status[job.get_id()] == 'stderr'],
            r, w, x = select.select(stdout_fhs, [], stderr_fhs, 3)
            if len(r) > 0:
                output = r.recv(self._output_size)
                if output != '':
                    print(output)
            if len(x) > 0:
                output = x.recv_stderr(self._output_size)
                if output != '':
                    print(output)


def test(**kwargs):
    """ test 
    """
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], 
                "h:", 
                [
                    "help",
                    "action=",
                    "directory=",
                ]
    except getopt.GetoptError as e:
        # print help information and exit:
        sys.exit("\n[LOOK HERE]: %s \n\nPlease check helper:\npython infinio.py --help" % str(e))
    """
    partners = {
        'localhost': "root:Password123!",
        }

    infinco = InfinCo(partner_info=partners, target='command.py')
    infinco.connect()
    infinco.deploy()
    infinco.open()
    infinco.run()
    infinco.wait(1000)


if __name__ == '__main__':
   
    test()

