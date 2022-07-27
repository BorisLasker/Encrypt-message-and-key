#!/usr/bin/env python
# coding=utf8
BLOCK_SIZE = 16



def to_bytearray(obj, obj_name='', encoding='utf-8', forcecopy=False):
        if obj is None:
            raise AttributeError("`%s` is None"%obj_name)
        if type(obj) == bytearray:
            if forcecopy:
                return bytearray(obj)
            return obj
        if type(obj) == str and str != bytes:
            return bytearray(obj,encoding)
        elif type(obj) in (int,float):
            raise AttributeError("`%s` must be a bytes-like object"%obj_name)
        else:
            return bytearray(obj)




def xorAr(lhsAr, rhsAr):
        bLen = min(len(lhsAr), BLOCK_SIZE)
        aLen = min(len(rhsAr), bLen)
        retVal = bytearray(BLOCK_SIZE)

        for i in range(aLen):
            retVal[i] = lhsAr[i] ^ rhsAr[i]
        for i in range(aLen, bLen):
            retVal[i] = lhsAr[i]

        return retVal



def pad(msg):
    size_block = BLOCK_SIZE
    text_length = len(msg)
    padding_byte = size_block - (text_length % size_block)
    if padding_byte == 0:
        padding_byte = size_block  
    pad = chr(padding_byte)
    ret = msg + (pad * padding_byte).encode()
    
    
    return ret


def unpad(msg):
    rm = msg[-1] #padding byte 저장
    
    return msg[:-rm] #padding 잘라서 리턴

