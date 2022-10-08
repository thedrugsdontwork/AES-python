
from ast import keyword
from enum import Enum

class KeyLengthError(Exception):...

S_BOX=[
    [0X63,0X7C,0X77,0X7B,0XF2,0X6B,0X6F,0XC5,0X30,0X01,0X67,0X2B,0XFE,0XD7,0XAB,0X76],
    [0XCA,0X82,0XC9,0X7D,0XFA,0X59,0X47,0XF0,0XAD,0XD4,0XA2,0XAF,0X9C,0XA4,0X72,0XC0],
    [0XB7,0XFD,0X93,0X26,0X36,0X3F,0XF7,0XCC,0X34,0XA5,0XE5,0XF1,0X71,0XD8,0X31,0X15],
    [0X04,0XC7,0X23,0XC3,0X18,0X96,0X05,0X9A,0X07,0X12,0X80,0XE2,0XEB,0X27,0XB2,0X75],
    [0X09,0X83,0X2C,0X1A,0X1B,0X6E,0X5A,0XA0,0X52,0X3B,0XD6,0XB3,0X29,0XE3,0X2F,0X84],
    [0X53,0XD1,0X00,0XED,0X20,0XFC,0XB1,0X5B,0X6A,0XCB,0XBE,0X39,0X4A,0X4C,0X58,0XCF],
    [0XD0,0XEF,0XAA,0XFB,0X43,0X4D,0X33,0X85,0X45,0XF9,0X02,0X7F,0X50,0X3C,0X9F,0XA8],
    [0X51,0XA3,0X40,0X8F,0X92,0X9D,0X38,0XF5,0XBC,0XB6,0XDA,0X21,0X10,0XFF,0XF3,0XD2],
    [0XCD,0X0C,0X13,0XEC,0X5F,0X97,0X44,0X17,0XC4,0XA7,0X7E,0X3D,0X64,0X5D,0X19,0X73],
    [0X60,0X81,0X4F,0XDC,0X22,0X2A,0X90,0X88,0X46,0XEE,0XB8,0X14,0XDE,0X5E,0X0B,0XDB],
    [0XE0,0X32,0X3A,0X0A,0X49,0X06,0X24,0X5C,0XC2,0XD3,0XAC,0X62,0X91,0X95,0XE4,0X79],
    [0XE7,0XC8,0X37,0X6D,0X8D,0XD5,0X4E,0XA9,0X6C,0X56,0XF4,0XEA,0X65,0X7A,0XAE,0X08],
    [0XBA,0X78,0X25,0X2E,0X1C,0XA6,0XB4,0XC6,0XE8,0XDD,0X74,0X1F,0X4B,0XBD,0X8B,0X8A],
    [0X70,0X3E,0XB5,0X66,0X48,0X03,0XF6,0X0E,0X61,0X35,0X57,0XB9,0X86,0XC1,0X1D,0X9E],
    [0XE1,0XF8,0X98,0X11,0X69,0XD9,0X8E,0X94,0X9B,0X1E,0X87,0XE9,0XCE,0X55,0X28,0XDF],
    [0X8C,0XA1,0X89,0X0D,0XBF,0XE6,0X42,0X68,0X41,0X99,0X2D,0X0F,0XB0,0X54,0XBB,0X16],
]

class _AES:
    AES128=dict(en_round=11,key_words=4)
    AES192=dict(en_round=13,key_words=6)
    AES256=dict(en_round=15,key_words=8)
    def get(key_len):
        if key_len==16:return _AES.AES128
        if key_len==24:return _AES.AES192
        if key_len==32:return _AES.AES256
        return None

def __xor(a:list,b:list):
    length=len(a)
    lis=[0]*length
    for i in range(length):
        lis[i]=a[i]^b[i]
    return lis

def __s_box(in_byte):
    """
        @note list_idndex(high_4bit),sub_list_index(low_4bit)
        @param  :in_byte(byte)
        @return :byte_arr(byte)
    """
    global S_BOX
    return S_BOX[(in_byte&0xF0)>>4][in_byte&0x0F]

def __get_rcon(num):
    if num==1:
        return 1
    else:
        pre_rci=__get_rcon(num-1)
        if pre_rci<0x80:
            return 2*pre_rci
        elif pre_rci>=0x80:
            return (2*pre_rci)^(0x11b)
        
def __gmix_column(r:list):
    """
        @param r    : column of matrix
    """
    a=[0,0,0,0]
    b=[0,0,0,0]
    for c in range(0,4):
        a[c] = r[c]
        #/* h is 0xff if the high bit of r[c] is set, 0 otherwise */
        h = (r[c] >> 7)&1 #/* arithmetic right shift, thus shifting in either zeros or ones */
        b[c] = (r[c]<<1)&0xff #/* implicitly removes high bit because b[c] is an 8-bit char, so we xor by 0x1b and not 0x11b in the next line */
        b[c] ^= (h * 0x1B) #/* Rijndael's Galois field */
    r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; #* 2 * a0 + a3 + a2 + 3 * a1 */
    r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]; #* 2 * a1 + a0 + a3 + 3 * a2 */
    r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]; #* 2 * a2 + a1 + a0 + 3 * a3 */
    r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]; #* 2 * a3 + a2 + a1 + 3 * a0 */

def sub_bytes(byte_arr:list):
    for i in range(len(byte_arr)):byte_arr[i]= __s_box(byte_arr[i])

def __shift_rows_core(byte_arr:list,start:int):
    """
        end-start>=16 
    """
    t1=byte_arr[start+1]
    byte_arr[start+1],byte_arr[start+5],byte_arr[start+9],byte_arr[start+13]=\
    byte_arr[start+5],byte_arr[start+9],byte_arr[start+13],t1

    t1,t2=byte_arr[start+2],byte_arr[start+6]
    byte_arr[start+2],byte_arr[start+6],byte_arr[start+10],byte_arr[start+14]=\
    byte_arr[start+10],byte_arr[start+14],t1,t2

    t1,t2,t3=byte_arr[start+3],byte_arr[start+7],byte_arr[start+11]
    byte_arr[start+3],byte_arr[start+7],byte_arr[start+11],byte_arr[start+15]=\
    byte_arr[start+15],t1,t2,t3

def shift_rows(byte_arr):
    for i in range(0,len(byte_arr),16):
        __shift_rows_core(byte_arr,i)

def mix_columns(byte_arr):
    for i in range(0,len(byte_arr),16):
        tmp=[byte_arr[i],byte_arr[i+1],byte_arr[i+2],byte_arr[i+3]]
        __gmix_column(tmp)
        byte_arr[i],byte_arr[i+1],byte_arr[i+2],byte_arr[i+3]=tmp

        tmp=[byte_arr[i+4],byte_arr[i+5],byte_arr[i+6],byte_arr[i+7]]
        __gmix_column(tmp)
        byte_arr[i+4],byte_arr[i+5],byte_arr[i+6],byte_arr[i+7]=tmp

        tmp=[byte_arr[i+8],byte_arr[i+9],byte_arr[i+10],byte_arr[i+11]]
        __gmix_column(tmp)
        byte_arr[i+8],byte_arr[i+9],byte_arr[i+10],byte_arr[i+11]=tmp

        tmp=[byte_arr[i+12],byte_arr[i+13],byte_arr[i+14],byte_arr[i+15]]
        __gmix_column(tmp)
        byte_arr[i+12],byte_arr[i+13],byte_arr[i+14],byte_arr[i+15]=tmp

def __rotword(byte_arr:list,start):
    t1=byte_arr[start]
    byte_arr[start],byte_arr[start+1],byte_arr[start+2],byte_arr[start+3]=\
    byte_arr[start+1],byte_arr[start+2],byte_arr[start+3],t1
    
def key_expansion(key:bytes,N:int,R:int):
    w=[*key]
    for i in range(4*N,16*R,4):
        tmp=w[i-4:i]
        key_exp=[]
        pre=i-N*4
        r_time=i//4
        if r_time>= N and r_time%N==0:
            rcon=[__get_rcon(r_time//N),0x00,0x00,0x00]
            __rotword(tmp,0)
            sub_bytes(tmp)
            tmp=__xor(w[pre:pre+4],tmp)
            key_exp=__xor(tmp,rcon)
        elif r_time>=N and N>6 and r_time%4==0:
            sub_bytes(tmp)
            key_exp=__xor(w[pre:pre+4],tmp)
        else:
            key_exp=__xor(w[pre:pre+4],tmp)

        w.extend(key_exp)

    return w

def add_round_key(byte_arr,key_arr,round):
    for i in range(0,len(byte_arr),16):
        for j in range(16):
            byte_arr[i+j]^=key_arr[round*16+j]

def encrypt_block(byte_arr,key_arr,en_round):
    add_round_key(byte_arr,key_arr,0)
    for i in range(1,en_round-1):
        sub_bytes(byte_arr)
        shift_rows(byte_arr)
        mix_columns(byte_arr)
        add_round_key(byte_arr,key_arr,i)
    sub_bytes(byte_arr)
    shift_rows(byte_arr)
    add_round_key(byte_arr,key_arr,en_round-1)
    return byte_arr

def encrypt_ECB(byte_arr,byte_key):
    key_len=len(byte_key)
    aes=_AES.get(key_len)
    if not aes:raise KeyLengthError(f"Key length dosent match:[{len(byte_key)}] except:[16,24,32]")
    en_round=aes['en_round']
    key_words=aes['key_words']
    byte_arr=list(byte_arr)
    key_arr=key_expansion(byte_key,key_words,en_round)
    res=encrypt_block(byte_arr,key_arr,en_round) 
    return bytes(res)
    
def encrypt_CBC(byte_arr,byte_key,byte_iv):
    key_len=len(byte_key)
    aes=_AES.get(key_len)
    if not aes:raise KeyLengthError(f"Key length dosent match:[{len(byte_key)}] except:[16,24,32]")
    en_round=aes['en_round']
    key_words=aes['key_words']
    byte_arr=list(byte_arr)
    key_arr=key_expansion(byte_key,key_words,en_round)
    tmp=[*byte_iv]
    res=[]
    for i in range(0,len(byte_arr),16):
        tmp=__xor(tmp,byte_arr[i:i+16])
        tmp=encrypt_block(tmp,key_arr,en_round) 
        res.extend(tmp)
    return bytes(res)

#For test
import base64
from Crypto.Cipher import AES  


if __name__=='__main__':
    iv=b"skajshsjshsgshsj"
    s=b"mpaosfnmsoiahjsdgfkaskjfhjsa;lfsfsdfkjsjsdsfjssdsbgsjgsssbjshgshdsadadsdaddhdhdhdhsdflsdhfskajijsssaksssassshsjd"
    key=b"46cc793c53dc451bshagshaj"
    #ECB MODE
    print("ECB encrypt:")
    res=encrypt_ECB(s,key)
    cipher = AES.new(b"46cc793c53dc451bshagshaj",AES.MODE_ECB)
    data = cipher.encrypt(s)
    print(base64.b64encode(res))
    print(base64.b64encode(data))
    
    #CBC MODE
    print("CBC encrypt:")
    cipher = AES.new(b"46cc793c53dc451bshagshaj",AES.MODE_CBC,iv=iv)
    data = cipher.encrypt(s)
    res=encrypt_CBC(s,key,iv)
    print(base64.b64encode(res))
    print(base64.b64encode(data))






    
