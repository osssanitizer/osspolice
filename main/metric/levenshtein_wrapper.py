#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'ruian'

import os
import sys
import time
from ctypes import *
package_directory = os.path.dirname(os.path.abspath(__file__))
lib = cdll.LoadLibrary(os.path.join(package_directory, 'liblevenshtein.so'))


def purify(s):
    if isinstance(s, unicode):
        return s.encode('utf-8')
    else:
        return s

def levenshtein(strA, strB, normalize=False):
    strA = purify(strA)
    strB = purify(strB)
    lenA = len(strA)
    lenB = len(strB)
    arrayA = (c_char*(lenA+1))()
    arrayB = (c_char*(lenB+1))()
    arrayA[:lenA] = strA[:lenA]
    arrayA[lenA] = '\0'
    arrayB[:lenB] = strB[:lenB]
    arrayB[lenB] = '\0'
    dist = lib.levenshtein(arrayA, arrayB)
    if normalize:
        return dist * 1.0 / max(lenA, lenB)
    else:
        return dist

def levenshtein_batch(sArr, strB, normalize=False):
    sArr = [purify(s) for s in sArr]
    strB = purify(strB)
    lenArr = len(sArr)
    lenB = len(strB)
    arrayArr = (c_char_p*lenArr)()
    arrayB = (c_char*(lenB+1))()
    arrayArr[:] = sArr
    arrayB[:lenB] = strB[:lenB]
    arrayB[lenB] = '\0'
    arrayR = (c_uint*lenArr)()
    lib.levenshtein_batch(arrayArr, c_uint(lenArr), arrayB, arrayR)
    for s, dist in zip(sArr, arrayR):
        if normalize:
            yield dist * 1.0 / max(len(s), lenB)
        else:
            yield dist

if __name__=="__main__":
    # test
    if len(sys.argv) == 1:
        # separate calls
        sArr = ['hello', 'hello world', 'hello, fine. thank you', '你好，世界']
        strB = 'hello world'
        start = time.time()
        result = []
        resultNorm = []
        for strA in sArr:
            result.append(levenshtein(strA, strB))
        print(result)
        for strA in sArr:
            resultNorm.append(levenshtein(strA, strB, True))
        print(resultNorm)
        print('separate calls took: %f' % (time.time() - start))

        # batch calls
        start = time.time()
        print(list(levenshtein_batch(sArr, strB)))
        print(list(levenshtein_batch(sArr, strB, True)))
        print('separate calls took: %f' % (time.time() - start))

    else:
        strA = sys.argv[1]
        strB = sys.argv[2]
        print('comparing %s and %s' % (strA, strB))
        print('distance: %s, normalized: %s' % (levenshtein(strA, strB), levenshtein(strA, strB, True)))
