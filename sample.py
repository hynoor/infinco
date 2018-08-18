from infico import Client
import time


def test():
    clnt = Client(ip='127.0.0.1', user='hynoor', password='hynoor')
    clnt.equip(target='./command.py')
    clnt.run_async(command="python /tmp/command.py")
    while len(clnt.jobs):
        print("running ...")
        output = clnt.poll()
        for line in output:
            print("%s" % line)
        time.sleep(1)


if __name__ == '__main__':
    test()
