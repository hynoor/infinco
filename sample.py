from infico import Client
import time


def test():
    clnt1 = Client(ip='127.0.0.1')
    clnt2 = Client(ip='10.207.84.35')
    clnt3 = Client(ip='10.207.80.31')
    clnt1.equip(target='./command.py')
    clnt2.equip(target='./command.py')
    clnt3.equip(target='./command.py')
    for clnt in [clnt1, clnt2, clnt3]:
        clnt.run_async(command="python /tmp/command.py")

    go = True
    while go:
        go = (not clnt1.poll()) and (not clnt2.poll()) and (not clnt3.poll())
        time.sleep(1)


if __name__ == '__main__':
    test()
