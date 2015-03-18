'''
Created on Mar 12, 2015

@author: kehan_wang
'''

def readPowerTraceFromFile():
    rslt = []
    traceFile = open("PowerTrace.dat", 'rb')
    for i in range(500):
        longLine = traceFile.read(30000)
        longByteArray = bytearray()
        for oneByte in longLine:
            longByteArray.append(oneByte)
        rslt.append(longByteArray)
    return rslt


T = readPowerTraceFromFile()
print "Done reading..."
print T[0][0]
print T[499][29999]
print len(T[0])
print len(T[499])
summ=0
for i in range(500):
    summ+=T[i][0]
print summ