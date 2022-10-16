

def euclidean_extend(a,b):
    r0,r1=a,b
    s0,s1=1,0
    t0,t1=0,1
    r2=-1
    while r2!=0:
        q,r2=__div(r0,r1)
        s2=s0^__multi(q,s1)
        t2=t0^__multi(t1,q)
        r0,r1=r1,r2
        s0,s1=s1,s2
        t0,t1=t1,t2
    return s0

def __div(x,y):
    """
        Polynomial division
    """
    a=x#&0xff
    b=y#&0xff
    q=0
    while True:
        h_a=__get_MSB(a)
        h_b=__get_MSB(b)
        shift=h_a-h_b
        if shift<0 or a==0:
            return q,a

        q|=1<<shift
        a^=(b<<shift)
    


def __get_MSB(x):
    """
        get the most significant bit
    """
    for i in range(8,-1,-1):
        if x&(1<<i)>0:
            return i
    return 0


def __multi(a,b):
    """
        Polynomial multiplication
    """
    h_b=__get_MSB(b)
    q=0
    for i in range(h_b,-1,-1):
        if b&(1<<i)>0:
            q^=(a<<i)
    return q
# print(__div(0b100011011,0b1010011))
if __name__=='__main__':
    #x^8+x^4+x^3+x+1 上 2的逆元
    #计算与计算结果均取多项式系数
    res=euclidean_extend(0b10,0b100011011)
    print('{:08b}'.format(res))

