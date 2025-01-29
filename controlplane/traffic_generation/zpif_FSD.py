import numpy as np
from matplotlib import pyplot as plt
import random
import math

def Zipf(a: np.float64, min: np.uint64, max: np.uint64, size=None):
    """
    Generate Zipf-like random variables,
    but in inclusive [min...max] interval
    """
    if min == 0:
        raise ZeroDivisionError("")

    v = np.arange(min, max+1) # values to sample
    p = 1.0 / np.power(v, a)  # probabilities
    p /= np.sum(p)            # normalized

    return np.random.choice(v, size=size, replace=True, p=p)

def choice(q,total,max_num):
    range_q = max_num/q.max()
    q = 1 + (q-1) * range_q
    print(q.max())
    sample_rate = total/q.sum()
    num_sample = round(sample_rate * len(q))
    q_list = random.sample(list(q),num_sample)
    return q_list

min_num = np.uint64(1)
max_num = np.uint64(100000)

#1:600
#1.5:20000
#2:600000
#2.5:2500000
#3:
q_list = Zipf(3, min_num, max_num, 4000000)
#q_list = choice(q,5000000,50000)

print(sum(q_list),min(q_list),max(q_list),len(q_list))

w = open('flows_3.txt','a+')
for f in q_list:
    w.write(f'{f}\n')
w.close()
