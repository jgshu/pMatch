from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from secretshare import SecretShare
import time
import sys
class pMatch:
    def __init__(self, groupObj):
        global group
        group = groupObj

    def setup(self,ss,k,n):
        g=group.random(G1)
        x1=group.random(ZR)
        x2=group.random(ZR)
        g1=g**x1
        g2=g**x2
        #print sys.getsizeof(x1),sys.getsizeof(x2)
        #print sys.getsizeof(g1), sys.getsizeof(g2)

        s = SecretShare(group, True)
        (q,shares) = s.genShares(x1, k, n+1)
        t=group.init(ZR,1)
        EK=g**(shares[1]/x1)

        PK={'g':g,'g1':g1,'g2':g2,'EK':EK}
        MSK={'x1':x1,'x2':x2,'f1':q[1],'t':t}

        SKSET=list()
        for i in range(2,n+2):
            SK=list()
            e1=group.init(ZR, 1)
            e2=group.init(ZR, i)
            result1 = (-e1) / (e2-e1)
            result2 = (-e2) / (e1-e2)
            D=g2**(shares[i]*result1)
            E=g2**(x1*result2)
            SK.append(i)
            SK.append(D)
            SK.append(E)
            SKSET.append(SK)
            #SK[i-2]=(i,D,E)
           # re_sec=shares[i]*result1+shares[1]*result2
            #print re_sec==x1

        return PK,MSK, SKSET


    def enc(self, PK, w):
        r1=group.random(ZR)
        r2=group.random(ZR)

        C1=(PK['g2']**r2)*(group.hash(w,G1)**r1)
        C2=PK['g1']**r1
        C3=PK['EK']**r2
        C4=PK['g']**r2
        #print sys.getsizeof(C1),sys.getsizeof(C2),sys.getsizeof(C3),sys.getsizeof(C4)
        C={'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4}
        return C

    def trap(self,PK,SK,w):
        D, E = SK[1], SK[2]
        s=group.random(ZR)
        T1=PK['g1']**s
        T2=group.hash(w,G1)**s
        T3=E**s
        T4=D**s
        T = {'T1': T1, 'T2': T2, 'T3': T3, 'T4': T4}
        return T

    def match(self,C,T):
        flag = False
        left = pair(C['C1'],T['T1'])
        right1 = pair(C['C2'],T['T2'])
        right2 = pair(C['C3'], T['T3'])
        right3 = pair(C['C4'], T['T4'])
        right=right1*right2*right3
        if left == right:
            flag=True
        return flag


    def cipherUpdate(self,C,CK):
        C3_Prime=C['C3']**CK
        C_Prime={'C1':C['C1'],'C2':C['C2'],'C3':C3_Prime,'C4':C['C4']}
        return C_Prime

    def re_Setup(self,k,n,PK,MSK,SKSET):
        s = SecretShare(group, True)
        (q, shares) = s.genShares(MSK['x1'], k, n+1 )
        t = group.init(ZR, 1)
        EK_Prime =PK['g'] ** (shares[1] / MSK['x1'])

        old_share1=MSK['x1']+MSK['f1']
        CK=shares[1]/old_share1
        PK_Prime = {'g': PK['g'], 'g1': PK['g1'], 'g2': PK['g2'], 'EK': EK_Prime}
        MSK_Prime = {'x1': MSK['x1'], 'x2': MSK['x2'], 'f1': q[1], 't': MSK['t']}

        SKSET_Prime= list()
        for i in range(0, n):
            e1 = group.init(ZR, 1)
            e2 = group.init(ZR, i)
            result1 = (-e1) / (e2 - e1)
            D = PK['g2'] ** (shares[i] * result1)
            SK=(SKSET[i][0], D, SKSET[i][2])
            SKSET_Prime.append(SK)
        # re_sec=shares[i]*result1+shares[1]*result2
        # print re_sec==x1


        return PK_Prime, MSK_Prime, SKSET_Prime,CK

    def RevTest(self,SK,T):
        tag=False
        if pair(T['T3'],SK[1])==pair(SK[2],T['T4']):
            tag=True
        return tag

    def IndexGen(self, PK, fileName):
        I = list()
        with open(fileName) as f:
            data = f.readlines()
            for line in data:
                CC = list()
                keywords = line.strip('\n').split(':')[1].split(',')
                for keyword in keywords:
                    C = pMatch.enc(self, PK, keyword)
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
                flag = pMatch.match(self, C, T)
                if (flag == True):
                    Res.append(i)
                    break
        return Res

    def UpdateIndex(self, I, CK):
        for i in range(len(I)):
            CC = I[i]
            for j in range(len(CC)):
                C = CC[j]
                I[i][j] = pMatch.cipherUpdate(self, C, CK)

        return I

    def RevCheck(self,SKSET,T):
        tag=False
        for i in range(len(SKSET)):
            tag = pMatch.RevTest(self,SKSET[i], T)
            if(tag==True):
                break
        return tag



def main():
    keyword = 'cityu'
    keyword1 = 'cityu1'

    k = 2
    userNum = 1001
    group = PairingGroup('SS512')
    ss = SecretShare(group, True)
    pMat = pMatch(group)
    (PK,MSK,SKSET) = pMat.setup(ss,k,userNum)



    T=pMat.trap(PK,SKSET[userNum-1],keyword)

    #print (pMat.match(C,T))
    #(PK_Prime, MSK_Prime, SKSET_Prime, CK)=pMat.re_Setup(k, n, PK, MSK, SK)
    # C_Prime=pMat.cipherUpdate(C,CK)
    # T_Prime=pMat.trap(PK,SKSET_Prime[1],keyword)
    # print (pMat.match(C_Prime,T_Prime))

    elapsed_timeRevTest = ''
    for n in range(100, 1001, 100):
        start_RevTest = time.clock()
        tag=pMat.RevCheck(SKSET[0:n],T)
        elapsed_RevTest = time.clock() - start_RevTest
        print(n, elapsed_RevTest)
        elapsed_timeRevTest += str(elapsed_RevTest) + '\t'
    print 'Revocation test time elapsed:' + elapsed_timeRevTest

    start_IndexGen = time.clock()
    I = pMat.IndexGen(PK, 'plainIndex.txt')
    elapsed_IndexGen = time.clock() - start_IndexGen
    print elapsed_IndexGen



    testNum = [100, 1000, 10000,100000,1000000]
    for n in testNum:
        print n
        start_IndexMatch = time.clock()
        Res = pMat.MatchIndex(I[0:n], T)
        elapsed_IndexMatch = time.clock() - start_IndexMatch
        print 'Index Match:', elapsed_IndexMatch
        print Res

        (PK_Prime, MSK_Prime, SKSET_Prime, CK) = pMat.re_Setup(k, userNum, PK, MSK, SKSET)
        start_Update = time.clock()
        newI = pMat.UpdateIndex(I[0:n], CK)
        elapsed_Update = time.clock() - start_Update
        print 'Index Update:', elapsed_Update



    '''
    #Setup & KeyGen
    print 'Setup & KeyGen'
    elapsed_timeStart = '';
    for n in range(1000, userNum + 1, 1000):
        start_Setup = time.clock()
        (PK, MSK, SK) = pMat.setup(ss, k, n)
        elapsed_Setup = time.clock() - start_Setup
        print(n, elapsed_Setup)
        elapsed_timeStart += str(elapsed_Setup) + '\t'
    print elapsed_timeStart



    #2 Enc
    print 'Encrytpion'
    elapsed_timeEnc=''
    start_Enc = time.clock()
    for j in range(10):
        for i in range(num*10):
            C= pMat.enc(PK,keyword)
        elapsed_Enc=(time.clock()-start_Enc)/(num*10)
        elapsed_timeEnc += str(elapsed_Enc) + '\t'
    print 'Encryption time elapsed:'+elapsed_timeEnc


    #3 Trap
    print 'Trapdoor'
    elapsed_timeTrap = ''
    start_Trap = time.clock()
    for j in range(10):
        for i in range(num*10):
            T=pMat.trap(PK,SKSET[1],keyword)
        elapsed_Trap = (time.clock() - start_Trap)/(num*10)
        elapsed_timeTrap += str(elapsed_Trap) + '\t'
    print'Trapdoor time elapsed:', elapsed_timeTrap
    '''
    '''
    # 4 Test
    C=pMat.enc(PK,keyword)
    print 'Match'
    elapsed_MatchTotal = ''
    for i in range(10):
        elapsed_timeMatch = ''
        for j in range(10):
            start_Match = time.clock()
            for ii in range(i + 1):
                for jj in range(j + 1):
                    for k in range(100):
                        flag = pMat.match(C,T)
            elapsed_Match = (time.clock() - start_Match) / (100)
            # print ii,jj,elapsed_Match
            elapsed_timeMatch += str(elapsed_Match) + '\t'
        print elapsed_timeMatch
        # elapsed_MatchTotal+=elapsed_timeMatch+'\n'
    # print elapsed_MatchTotal
    '''
    '''
    # RevTest
    print 'Revocation Test'
    elapsed_timeRevTest = ''
    for n in range(100, 1001, 100):
        start_RevTest = time.clock()
        for i in range(n):
            tag = pMat.RevTest(SKSET[1], T)
            #print tag
        elapsed_RevTest = time.clock() - start_RevTest
        print(n, elapsed_RevTest)
        elapsed_timeRevTest += str(elapsed_RevTest) + '\t'
    print 'Revocation test time elapsed:' + elapsed_timeRevTest


    #Re_Setup
    print 'Re-Setup'
    elapsed_timeReStart = '';
    for n in range(1000, userNum + 1, 1000):
        start_ReSetup = time.clock()
        (PK_Prime, MSK_Prime, SKSET_Prime, CK) = pMat.re_Setup(k, n, PK, MSK, SKSET)
        elapsed_ReSetup = time.clock() - start_ReSetup
        print(n, elapsed_ReSetup)
        elapsed_timeReStart += str(elapsed_Setup) + '\t'
    print elapsed_timeReStart

    #Cipher Update
    print 'Cipher Update'
    elapsed_timeCipUpd = ''
   # for n in range(1000, userNum + 1, 1000):
    start_CipUpd = time.clock()
    for i in range(5461):
        C_Prime = pMat.cipherUpdate(C, CK)
    elapsed_CipUpd  = time.clock() - start_CipUpd
    print(n, elapsed_CipUpd)
    elapsed_timeCipUpd += str(elapsed_CipUpd) + '\t'
    print 'Ciphertext Update time elapsed:' + elapsed_timeCipUpd
'''

if __name__ == '__main__':
        main()