import threading
import concurrent.futures as cf
import time
import secrets


class AtomicCounter:
    def __init__(self, initial=0):
        self.value = initial
        self._lock = threading.Lock()

    def inc(self, num=1):
        with self._lock:
            self.value += num
            return self.value

    def get(self):
        return self.value


class Id64(object):
    epoch_bits = 41
    shard_bits = 10
    counter_bits = 13
    shard_mask = ~(-1 << shard_bits)
    counter_mask = ~(-1 << counter_bits)

    # epoch = 1534413665490 # Thu Aug 16 2018 17:01:05
    epoch = 1521910800000
    counter = AtomicCounter(secrets.randbelow(123456))

    @classmethod
    def generate(cls, shard=secrets.randbelow(1 << shard_bits)):
        _epoch = int(time.time() * 1000) - cls.epoch
        _shard = shard & cls.shard_mask
        _counter = cls.counter.inc() & cls.counter_mask
        return (_epoch << (64 - cls.epoch_bits)) | (_shard << (64 - cls.epoch_bits - cls.shard_bits)) | _counter
    

def generate_64bit_id(shard=100000000):
    return Id64.generate(shard)


def inc(index, _counter):
    now = time.time()
    for _ in range(0, 500000):
        counter.inc()
    print('Executor {} done, took {}'.format(index, time.time() - now))


if __name__ == '__main__':
    counter = AtomicCounter()
    futs = []
    with cf.ThreadPoolExecutor(max_workers=4) as executor:
        for i in range(0, 4):
            print('Submit job to executor', i)
            fut = executor.submit(inc, i, counter)
            futs.append(fut)

        last_val = counter.get()
        while True:
            all_futs_done = True
            for fut in futs:
                if not fut.done():
                    all_futs_done = False
                    new_val = counter.get()
                    print('Counter: {}, speed/s: {}'.format(new_val, new_val - last_val))
                    last_val = new_val
                    time.sleep(1)
                    break
            if all_futs_done:
                break
    print('All executors done')

    for i in range(5):
        print(generate_64bit_id())
        time.sleep(0.01)
