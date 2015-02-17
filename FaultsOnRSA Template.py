### This is a template file for the first problem of Project 3.
##
##  Please implement the provided functions and assure that your code
##  works correctly. Please submit your code together with the 
##  requested answers through blackboard
##
##  Name: <your name>
##  Date: <submission date>
##


# public key
N = 27730078510352092658858212325571408120207969118062666872037805797782355036589533453003293447083711177430882706929364707450610077013654487640846293566352463525018201694824464397147698251460362447594889827410669951079919924224824750457815049999487816202453253535572464777829750048231607856900020205303665190429
e = 27404521666744140979061939395547584512542889949034373953101677990499512824827790947223768391661004838064530531198914476718023594662795504107114296506678212623735462515103245694247397841091949324665200311568086846244842117438974735096047550200711445736895933638318342096154913908455808196868575997827586823873

#Bellcore
cB = 11033111675066433599731775641403459367682767429252145183666066651763694306787318753142790521247382489593644686670452953962130752570818698457218071283604201524120029068958414126304912943929441040124280503981775612340628568978325303196490972820838294912455718067665864962022543396730467472360766384623334635574
cB0= 19796923688691225430248735892040254927061298751643763460570831567760930737921786154476112930124349156941099908577085885382354310573657815815512245845355911388356221782154077463829604014557207879046388327364744347021683968954605872488810214119452072890828110251254254907997651844998242785255936647330134950937

#Lenstra
mL = 5551127004224346732540041447130459612719964341547244614867081530681999098751857227135502353225820729573368011275461642270583332663127222657266851386364254519962447966984393184931527083142101967429051426762156299757064888960983539800249973792821565136744802664101720002728703324357123353301041293846831380875
cL0 = 5036183509973413547981847834925954085566645568302589152680203009173253304224466509911544317472481218449497635532224602888580345300841559828574785126853457

# xGCD:
def xgcd(a,b):
    """
    Returns g, x, y such that g = x*a + y*b = gcd(a,b).
    """
    old_x, x ,old_y, y= 1, 0, 0, 1
    while b!=0:
        r = a % b
        quotient = a // b
        x, old_x = old_x - quotient * x, x  
        y, old_y = old_y - quotient * y, y
        a, b = b, r
    return (a,old_x,old_y)

def BellcoreAttack(sig,sig_p,N):
    '''performs the Bellcore attack on a faulty RSA-CRT signature and returns factorization of N'''
    '''
    According to [BDL97] 
    q = gcd(sig - sig_p, N)
    '''
    q = xgcd(sig-sig_p, N)[0]
    p = N / q
    return p,q


def LenstraAttack(m,sig_p,N,e):
    '''performs Lenstra's attack on a faulty RSA-CRT signature and returns factorization of N'''
    '''
    According to [Len96]
    gcd(c'^e-m, N) = q
    '''
    q = xgcd(pow(sig_p, e) - m, N)[0]
    p = N / q
    return p,q

p,q = BellcoreAttack(cB, cB0, N)
print "Bellcore Attack:\np={0}\nq={1}\n".format(p, q)

p,q = LenstraAttack(mL, cL0, N, e)
print "Lenstra Attack:\np={0}\nq={1}\n".format(p,q)