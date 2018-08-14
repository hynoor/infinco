# collaberative infinio
import sys
import paramiko
import select

from collections import defaultdict


class InfinCo:
    """ Collaborative version of Infinio w/ parallelism embeded
    """
    output_size = 1024    
    partners = []
    ssh_clnts = []
    channels = []
    active_jobs = []
    complete_jobs = []
    status = defaultdict()
    def __init__(self, partner_info={}, num_job=1):
        self.num_job = num_job
        for pn, pc in partner_info.iterms():
            pu, pp = pc.split(' ')
            self.partners.append[(pn, pu, pp )]

    def connect(self)
        """ connect the partner host(s)
        """
        for p in self.partners:
            clnt = paramiko.SSHClient()
            clnt.load_system_host_keys(()
            clnt.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())
            clnt.connect(p[0], 22, p[1], p[2])
            ssh_clnts.append(clnt)

    def deploy(self):
        """ transfer and deploy infinio.py to partner host(s)
        """
        for c in ssh_clnts:
            sftp = c.open_sftp()
            sftp.put('./infinio.py', '/tmp/infinio.py')
            sftp.close()

    def open(self):
        """ open sessions for subsequent execution
        """
        for clnt in ssh_clnts:
            session = clnt.get_transport.open_session()
            channels.append(session)

    def run(self, **kwargs):
        """ start to execute infinio across partners
        """
        parameters = ''
        foreach k, v in kwargs:
            parameters.append(k + '=' + v)
        command = parameters.join(' ')

        for chn in channels:
            chn.exec_command(command)
            self.active_jobs.add(channel)

    def wait(self, timeout):
        """ wait for job done
        """
        for chn in self.active_jobs:
            while not chn.recv_exit_status():
                if chn.recv_ready():
                    status[chn] = 'stdout'
                elif chn.recv_stderr_ready():
                    status[chn] = 'stderr'

            r, w, x = select(
                        [job for job in status.keys() if status[job] == 'stdout'],
                        [], # no stdin
                        [job for job in status.keys() if status[job] == 'stderr'],
                        3,  # 3sec timeout
                    )
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
    partners = {
        'localhost': "root:hynoor",
        }

    infinco = InfinCo(partners)
    infinco.connect()
    infinco.deploy()
    infinco.run(kwargs)
    infinco.wait()



if __name__ == '__main__':
   
    test()

