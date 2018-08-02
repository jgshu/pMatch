from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
#from Crypto.Hash import SHA256
import time
class SEMEKS:
    def __init__(self, groupObj):
        global group
        group = groupObj


    def setup(self):
        g = group.random(G1)
        h01=group.random(G1)
        h02= group.random(G1)
        h11= group.random(G1)
        h12=group.random(G1)

        a1 = group.random(ZR)
        a2 = group.random(ZR)
        b1 = group.random(ZR)
        b2 = group.random(ZR)


        h01a1 = h01 **a1
        h01b1 = h01 ** b1
        h02a2 = h02 ** a2
        h02b2 = h02 ** b2

        h11a1 = h11 ** a1
        h11b1 = h11 ** b1
        h12a2 = h12 ** a2
        h12b2 = h12 ** b2


        pk = {'g': g,'h01a1': h01a1, 'h01b1': h01b1,'h02a2': h02a2, 'h02b2': h02b2, 'h11a1': h11a1, 'h11b1': h11b1,'h12a2': h12a2, 'h12b2': h12b2}
        msk = {'a1':a1,'a2':a2, 'b1':b1,'b2':b2}
        #hash = SHA256.new()
        return (pk, msk)

    def keygen(self,pk,msk):
        x1 = group.random(ZR)
        x2 = group.random(ZR)
        x1_prime=group.random(ZR)
        x2_prime = group.random(ZR)

        d1=pk['g']**(msk['a1']*x1)
        d2 = pk['g'] ** (msk['a1'] * x1_prime)
        d3 = pk['g'] ** (msk['a2'] * x2)
        d4 = pk['g'] ** (msk['a2'] * x2_prime)

        d5 = pk['g'] ** (msk['b1'] * x1)
        d6 = pk['g'] ** (msk['b1'] * x1_prime)
        d7 = pk['g'] ** (msk['b2'] * x2)
        d8 = pk['g'] ** (msk['b2'] * x2_prime)

        d9=pk['h01a1']**(msk['b1']*x1)*pk['h02a2']**(msk['b2']*x2)
        d10 = pk['h01a1'] ** (msk['b1'] * x1_prime) * pk['h02a2'] ** (msk['b2'] * x2_prime)

        d11 = pk['h11a1'] ** (msk['b1'] * x1) * pk['h12a2'] ** (msk['b2'] * x2)
        d12 = pk['h11a1'] ** (msk['b1'] * x1_prime) * pk['h12a2'] ** (msk['b2'] * x2_prime)

        sk={'d1':d1,'d2':d2,'d3':d3,'d4':d4,'d5':d5,'d6':d6,'d7':d7,'d8':d8,'d9':d9,'d10':d10,'d11':d11,'d12':d12}

        return sk

    def enc(self,pk,w):
        t = group.random(ZR)
        t1 = group.random(ZR)
        t2 = group.random(ZR)
        sigma=group.hash(w,ZR)

        c1=(pk['h01a1']**t1)*pk['h11a1']**(sigma*t1)
        c2 = (pk['h01b1'] ** (t-t1)) * (pk['h11b1'] ** (sigma *(t-t1)))
        c3 = (pk['h02a2'] ** t2) * pk['h12a2'] ** (sigma * t2)
        c4 = (pk['h02b2'] ** (t-t2)) * pk['h12b2'] ** (sigma * (t-t2))
        c5 =pk['g']**t

        c={'c1':c1,'c2':c2,'c3':c3,'c4':c4,'c5':c5}
        return c



    def trap(self,sk,w):
        r=group.random(ZR)
        r_prime=group.random(ZR)
        sigma=group.hash(w,ZR)

        t1=(sk['d9']**r) *(sk['d10']**r_prime) *(sk['d11']**(r*sigma))*(sk['d12']**(r_prime*sigma))
        t2=(sk['d1']**r) *(sk['d2']**r_prime)
        t3 = (sk['d3'] ** r) * (sk['d4'] ** r_prime)
        t4 = (sk['d5'] ** r) * (sk['d6'] ** r_prime)
        t5 = (sk['d7'] ** r) * (sk['d8'] ** r_prime)
        t={'t1':t1,'t2':t2,'t3':t3,'t4':t4,'t5':t5}
        return t



    def match(self,c,t):
        flag=False

        left= pair(c['c1'],t['t4'])*pair(c['c2'],t['t2'])*pair(c['c3'],t['t5'])*pair(c['c4'],t['t3'])
        right=pair(c['c5'],t['t1'])

        if left==right:
            flag=True
        else:
            flag=False
        return flag

    def IndexGen(self, PK, fileName):
        I = list()
        with open(fileName) as f:
            data = f.readlines()
            for line in data:
                CC = list()
                keywords = line.strip('\n').split(':')[1].split(',')
                for keyword in keywords:
                    C = SEMEKS.enc(self, PK, keyword)
                    # print sys.getsizeof(C)
                    CC.append(C)
                I.append(CC)
        return I

    def MatchIndex(self, I, T):
        Res = list()
        for i in range(len(I)):
            CC = I[i]
            for j in range(len(CC)):
                C = CC[j]
                flag = SEMEKS.match(self, C, T)
                if (flag == True):
                    Res.append(i)
                    break
        return Res

def main():
    num = 10
    params = ('SS512', 'SS1024')
    keyword='survy'
    keyword1 = 'cityu'
    mgp=PairingGroup(params[0])
    semeks=SEMEKS(mgp)
    (pk, msk)=semeks.setup()
    sk=semeks.keygen(pk,msk)
    c=semeks.enc(pk,keyword1)
    t=semeks.trap(sk,keyword1)

    #flag=semeks.match(c,t)
    #print flag

    start_IndexGen = time.clock()
    I = semeks.IndexGen(pk, 'plainIndex.txt')
    elapsed_IndexGen = time.clock() - start_IndexGen
    print elapsed_IndexGen

    testNum = [100, 1000, 10000, 100000,1000000]
    for n in testNum:
        print n
        start_IndexMatch = time.clock()
        Res = semeks.MatchIndex(I[0:n], t)
        elapsed_IndexMatch = time.clock() - start_IndexMatch
        print 'Index Match:', elapsed_IndexMatch
        print Res



    userNum=10000

    elapsed_timeStart = '';
    for n in range(1000,userNum+1,1000):
        start_Setup = time.clock()
        (pk, msk) = semeks.setup()
        for i in range(n):
            sk = semeks.keygen(pk, msk)
        elapsed_Setup = time.clock() - start_Setup
        print(n, elapsed_Setup)
        elapsed_timeStart+=str(elapsed_Setup)+'\t'
    print elapsed_timeStart



    elapsed_time=''
    start = time.clock()
    for j in range(10):
        for i in range(100):
            sk = semeks.keygen(pk, msk)
            c = semeks.enc(pk,keyword1)

            t = semeks.trap(sk,keyword1)

            flag = semeks.match(c, t)
        elapsed_Alg=(time.clock()-start)/(100)
        elapsed_time += str(elapsed_Alg) + '\t'
    print 'time elapsed:'+elapsed_time


    #2 Enc

    elapsed_timeEnc=''
    start_Enc = time.clock()
    for j in range(10):
        for i in range(num*10):
            c = semeks.enc(pk, keyword1)
        elapsed_Enc=(time.clock()-start_Enc)/(num*10)
        elapsed_timeEnc += str(elapsed_Enc) + '\t'
    print 'Encryption time elapsed:'+elapsed_timeEnc



    #3 Trap

    elapsed_timeTrap = ''
    start_Trap = time.clock()
    for j in range(10):
        for i in range(num*10):
            t=semeks.trap(sk, keyword1)
        elapsed_Trap = (time.clock() - start_Trap)/(num*10)
        elapsed_timeTrap += str(elapsed_Trap) + '\t'
    print'Trapdoor time elapsed:', elapsed_timeTrap


    # 4 Test

    elapsed_MatchTotal = ''
    for i in range(10):
        elapsed_timeMatch = ''
        for j in range(10):
            start_Match = time.clock()
            for ii in range(i + 1):
                for jj in range(j + 1):
                    for k in range(num * 10):
                        flag = semeks.match(c, t)
            elapsed_Match = (time.clock() - start_Match) / (num * 10)
            # print ii,jj,elapsed_Match
            elapsed_timeMatch += str(elapsed_Match) + '\t'
        print elapsed_timeMatch
        # elapsed_MatchTotal+=elapsed_timeMatch+'\n'
    # print elapsed_MatchTotal



if __name__ == '__main__':
    main()