#!/usr/bin/env python
#Wordlist generator / Generates wordlist lin 12 combinations possible 
#Note: Make sure you have enough space on your disk before you run this script. 
# @psc4re
f=open('wordlist', 'w')

def xselections(items, n):
    if n==0: yield []
    else:
        for i in xrange(len(items)):
            for ss in xselections(items, n-1):
                yield [items[i]]+ss

# Numbers = 48 - 57
# Capital = 65 - 90
# Lower = 97 - 122
#Special Characters = 32 - 47
spcl = range(32,48)
numb = range(48,58)
cap = range(65,91)
low = range(97,123)
choice = 0
while int(choice) not in range(1,13):
    choice = raw_input('''
    1) Numbers
    2) Capital Letters
    3) Lowercase Letters
    4) Numbers + Capital Letters
    5) Numbers + Lowercase Letters
    6) Numbers + Capital Letters + Lowercase Letters
    7) Capital Letters + Lowercase Letters
    8) Numbers + Special Characters
    9) Lowercase Letters + Special Characters
    10) Numbers + Capital Letters + Special Characters
    11) Numbers + Lowercase Letters + Special Characters
    12) Numbers + Capital Letters + Lowercase Letters + Special Characters
    : ''') 

choice = int(choice)
poss = []
if choice == 1:
    poss += numb
elif choice == 2:
    poss += cap
elif choice == 3:
    poss += low
elif choice == 4:
    poss += numb
    poss += cap
elif choice == 5:
    poss += numb
    poss += low
elif choice == 6:
    poss += numb
    poss += cap
    poss += low
elif choice == 7:
    poss += cap
    poss += low
elif choice == 8:
    poss += numb
    poss += spcl
elif choice == 9:
    poss += low 
    poss += spcl
elif choice == 10:
    poss += numb
    poss += cap
    poss += spcl
elif choice == 11:
    poss += numb
    poss += low
    poss += spcl
elif choice == 12:
    poss += numb
    poss += cap
    poss += low
    poss += spcl

bigList = []
for i in poss:
    bigList.append(str(chr(i)))

MIN = raw_input("What is the min size of the word? ")
MIN = int(MIN)
MAX = raw_input("What is the max size of the word? ")
MAX = int(MAX)
for i in range(MIN,MAX+1):
    for s in xselections(bigList,i): f.write(''.join(s) + '\n')

