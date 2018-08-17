from infico import Client
import time

def test():
    clnt = Client(ip='10.207.84.35')
    clnt.equip(target='./command.py')
    clnt.run_async(command="python /tmp/command.py")
    while len(clnt.jobs):
        print("running ...")
        clnt.poll()
        time.sleep(1)

if __name__ == '__main__':
    test()
