# collaberative infinio
import paramiko

class InfinCo:
    """ Collaborative version of Infinio w/ parallelism embeded
    """
    partners = []
    ssh_clnts = []
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
            clnt.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())A
            clnt.connect(p[0], 22, p[1], p[2])
            ssh_clnts.append(clnt)

    def deploy_infinio(self):
        """ transfer and deploy infinio.py to partner host(s)
        """
        for c in ssh_clnts:
            sftp = c.open_sftp()
            sftp.put('./infinio.py', '/tmp/infinio.py')
            sftp.close()

    def start(self):
        """ start to execute infinio across partners
        """

