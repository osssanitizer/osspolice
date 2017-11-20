import sys
import time
from celery import Celery

app = Celery('tasks', backend='rpc',
             broker='amqp://celery_scaling:celery_scaling@127.0.0.1/celery_scaling')

@app.task
def add(x, y):
    return x + y

@app.task
def gen_prime(x):
    multiples = []
    results = []
    for i in xrange(2, x+1):
        if i not in multiples:
            results.append(i)
            for j in xrange(i*i, x+1, i):
                multiples.append(j)
    return results

@app.task
def sleep(sec):
    time.sleep(sec)
    return sec

def assign_task(end):
    from celery import group
    from remote import gen_prime  # This has to be imported
    job = group(gen_prime.s(2 ** i) for i in range(end))
    result = job.apply_async()
    result.get()

if __name__=="__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        raise Exception("Usage: python remote.py $task_name [$end]")
    task_name = sys.argv[1]
    if len(sys.argv) == 3:
        end = int(sys.argv[2])
    else:
        end = 100
    if task_name == 'gen_prime':
        assign_task()
    elif task_name == 'add':
        from remote import add
        res = []
        for i in range(end):
            res.append(add.delay(i, end-i))
        for r in res:
            r.get()
            print (r)
    elif task_name == 'sleep':
        from celery import group
        from remote import sleep
        job = group(sleep.s(i) for i in range(end))
        result = job.apply_async()
        result.get()
        print (result)
    else:
        raise Exception("Unknown task_name: %s" % task_name)

