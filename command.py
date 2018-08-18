import os
import time
import random


def test():
    pid = os.getpid()
    for i in range(3):
        dur = random.randint(1, 10)
        print("{}: Sleeping for {} seconds".format(pid, dur))
        time.sleep(dur)


if __name__ == '__main__':
    test()
