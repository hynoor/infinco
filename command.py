import os
import time
import random


def test():
    pid = os.getpid()
    for i in range(10):
        dur = random.randint(1, 10)
        print("%d: Sleeping for %d seconds" % (pid, dur))
        time.sleep(dur)


if __name__ == '__main__':
    test()
