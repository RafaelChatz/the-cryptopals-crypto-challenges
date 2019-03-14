from math import ceil , inf , floor


def base64tobin(base64_string):
    base64_dict = {
        "000000": "A","000001": "B","000010": "C","000011": "D",
        "000100": "E","000101": "F","000110": "G","000111": "H",
        "001000": "I","001001": "J","001010": "K","001011": "L",
        "001100": "M","001101": "N","001110": "O","001111": "P",

        "010000": "Q","010001": "R","010010": "S","010011": "T",
        "010100": "U","010101": "V","010110": "W","010111": "X",
        "011000": "Y","011001": "Z","011010": "a","011011": "b",
        "011100": "c","011101": "d","011110": "e","011111": "f",

        "100000": "g","100001": "h","100010": "i","100011": "j",
        "100100": "k","100101": "l","100110": "m","100111": "n",
        "101000": "o","101001": "p","101010": "q","101011": "r",
        "101100": "s","101101": "t","101110": "u","101111": "v",

        "110000": "w","110001": "x","110010": "y","110011": "z",
        "110100": "0","110101": "1","110110": "2","110111": "3",
        "111000": "4","111001": "5","111010": "6","111011": "7",
        "111100": "8","111101": "9","111110": "+","111111": "/",
    }

    result=""
    for char in base64_string:
        #mydict.keys()[mydict.values().index(16)]
        if char=="=" :
            result=result+"="
        else:
            result=result + list(base64_dict.keys())[list(base64_dict.values()).index(char)]#get(char, "=")
    return result

def hextobase64(hex_string):

    base64_dict = {
        "000000": "A","000001": "B","000010": "C","000011": "D",
        "000100": "E","000101": "F","000110": "G","000111": "H",
        "001000": "I","001001": "J","001010": "K","001011": "L",
        "001100": "M","001101": "N","001110": "O","001111": "P",

        "010000": "Q","010001": "R","010010": "S","010011": "T",
        "010100": "U","010101": "V","010110": "W","010111": "X",
        "011000": "Y","011001": "Z","011010": "a","011011": "b",
        "011100": "c","011101": "d","011110": "e","011111": "f",

        "100000": "g","100001": "h","100010": "i","100011": "j",
        "100100": "k","100101": "l","100110": "m","100111": "n",
        "101000": "o","101001": "p","101010": "q","101011": "r",
        "101100": "s","101101": "t","101110": "u","101111": "v",

        "110000": "w","110001": "x","110010": "y","110011": "z",
        "110100": "0","110101": "1","110110": "2","110111": "3",
        "111000": "4","111001": "5","111010": "6","111011": "7",
        "111100": "8","111101": "9","111110": "+","111111": "/",
    }

    hex_string=hex_string.replace(" ", "")

    hex_list=[hex_string[i:i+2] for i in range(0, len(hex_string), 2)]
    bin_string=""

    for hex in hex_list:
        binary=bin(int(hex,16))[2:]
        bin_string=bin_string + (8-len(binary))*'0' + binary

    bin_list=[bin_string[i:i+6] for i in range(0, len(bin_string), 6)]

    result=""
    for binl in bin_list:
        result=result + base64_dict.get(binl, "=")


    return result


def fixedXor(hex_string1,hex_string2):
    if(len(hex_string1)==len(hex_string2)):
        return (hex(int(hex_string1,16) ^ int(hex_string2,16) )[2:]).zfill(len(hex_string2))
    else:
        return (hex(int(hex_string1,16) ^ int(hex_string2[0:len(hex_string1)],16) )[2:]).zfill(len(hex_string2))

def weight(str):
    weight=0;
    for ch in str:
        if ord(ch)<32:
            if ord(ch)!=10:
                weight=weight-50

    Cap=['E','T','A','O','I','N','S','H','R','D','L','U']
    Sml=['e','t','a','o','i','n','s','h','r','d','l','u']
    for l in range(11,0,-1):
        weight=weight+(14-l)*( str.count(Cap[l]) + str.count(Sml[l]) )

    Words=[" a "," about "," all " ," also "," and "," as "," at "," be "," because "," but "," by "]
    for w in range(9,0,-1):
        weight=weight+(20-w)*( str.count(Words[w]) )

    return weight + 4*str.count(' ')


def singlebyteXor(hex_string):
    if len(hex_string)%2==1:
        hex_string='0'+hex_string
    dicrypthexl=[]
    dicrypthex=""
    for key in range(0,256):
        for n in range(2,len(hex_string)+2,2):
            dicrypthex=dicrypthex + chr(int(hex_string[n-2:n],16) ^ key )
        dicrypthexl.append(dicrypthex)
        dicrypthex=""

    return(max(dicrypthexl, key=lambda l: weight(l)))

def singlebyteXorkey(hex_string):
    if len(hex_string)%2==1:
        hex_string='0'+hex_string
    dicrypthexl=[]
    dicrypthex=""
    for key in range(0,256):
        for n in range(2,len(hex_string)+2,2):
            dicrypthex=dicrypthex + chr(int(hex_string[n-2:n],16) ^ key )
        dicrypthexl.append(dicrypthex)
        dicrypthex=""

    decrypt_string0=sorted(dicrypthexl, key=lambda l: weight(l),reverse=True)[0]
    decrypt_string1=sorted(dicrypthexl, key=lambda l: weight(l),reverse=True)[1]
    if([i for i,x in enumerate(dicrypthexl) if x == decrypt_string0][0]>127):
        return([i for i,x in enumerate(dicrypthexl) if x == decrypt_string1][0])

    return([i for i,x in enumerate(dicrypthexl) if x == decrypt_string0][0])


def detectXor(data):
    decr_list=[]
    for line in data.splitlines():
        if len(line)!=60:
            continue
        decr_list.append(singlebyteXor(line))
    return max(decr_list, key=lambda l: weight(l))

def repeatingkeyXor(sentence,key):

    tkey=((ceil(len(sentence)/len(key)))*key)[0:len(sentence)]

    sent_enc="".join((hex((ord(st)))[2:]).zfill(2) for st in sentence)
    tkey_enc="".join((hex((ord(st)))[2:]).zfill(2) for st in tkey)
    return fixedXor(sent_enc,tkey_enc)

def repeatingkeyXor_decrypt(sentence_hex,key):


    tkey_enc="".join((hex((ord(st)))[2:]).zfill(2) for st in key)
    sent=sentence_hex[0:len(tkey_enc)]
    result=''
    for loc in range(0,len(sentence_hex),len(tkey_enc)):
        fixed=fixedXor(sentence_hex[loc:loc+len(tkey_enc)],tkey_enc)
        result=result+bytearray.fromhex(fixed).decode()


    #fixed=fixedXor(sent,tkey_enc)
    #print(bytearray.fromhex(fixed).decode())

    #print(fixed)
    return result

def hamming_distance_sent(sent1,sent2):
    sent1_enc="".join((hex((ord(st)))[2:]).zfill(2) for st in sent1)
    sent2_enc="".join((hex((ord(st)))[2:]).zfill(2) for st in sent2)
    return (bin(int(fixedXor(sent1_enc,sent2_enc),16))[2:]).count('1')

def hamming_distance_bin(bin1,bin2):
    return (bin(int(bin1,2)^int(bin2,2))).count('1')

def break_repeatingkeyXor(data):

    data_string=data.replace('\n', '').replace('=','')
    data_bin_string=base64tobin(data_string)
    key_sizes_values=[]
    for size in range(2,41):
        norm_ham_dist=0;
        blocknum=floor(len(data_bin_string)/(8*size))
        for strblock in range(0,blocknum ) :
            n0=size*strblock*8;n1=size*(strblock+1)*8;n2=size*(strblock+2)*8

            norm_ham_dist=norm_ham_dist+hamming_distance_bin(data_bin_string[n0:n1],data_bin_string[n1:n2])/size

        key_sizes_values.append( (norm_ham_dist/(blocknum),size) )


    min_key_size_values=sorted(key_sizes_values)[0:3]
    #print(min_key_size_values)
    keysize=min_key_size_values[0][1]
    blocklen=8*keysize
    block_num=floor(len(data_bin_string)/(blocklen))
    key=""
    block_list=[]

    key=""
    for  nbyte in range(0,keysize):
        block=""
        for strblock in range(0,block_num ) :
            block=block+data_bin_string[strblock*blocklen+nbyte*8:strblock*blocklen+(nbyte+1)*8]
        key=key+chr(singlebyteXorkey(hex(int(block,2))[2:]))

#    for line in data.replace('=','').splitlines():
#   base64.b64decode(data_string).hex()
    import base64
    line_hex=base64.b64decode(data).hex()
    #print(line_hex)
        #if len(line_hex)%2==1:
        #    line_hex='0'+line_hex

    return repeatingkeyXor_decrypt(line_hex,key)

def main():

    """
    print("Set1 Challenges")
    hex_string1="49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    print("Challenge 1: "+hextobase64(hex_string1)+"\n")

    hex_string2_1="1c0111001f010100061a024b53535009181c"
    hex_string2_2="686974207468652062756c6c277320657965"
    print("Challenge 2: "+fixedXor(hex_string2_1,hex_string2_2)+"\n")

    hex_string3="1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    print("Challenge 3: "+singlebyteXor(hex_string3)+"\n")
    file4data=""
    with open('4.txt', 'r') as myfile:
        file4data = myfile.read()
    print("Challenge 4: "+detectXor(file4data))


    str5_1="Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    str5_2="ICE"

    print("Challenge 5: "+repeatingkeyXor(str5_1,str5_2))"""

    #str5_1="Burning 'em, if you 't quick and nimbleI go when I hear bal"
    #str5_2="ICE"

    #print(repeatingkeyXor_decrypt(repeatingkeyXor(str5_1,str5_2),str5_2))

    file6data=""
    with open('6.txt', 'r') as myfile:
        file6data = myfile.read()

    print("Challenge 6: "+ break_repeatingkeyXor(file6data))

    #print(file6data)
    #print(data_string)
    #print(base64tobin(data_string))
    #print(hex(int(base64tobin(data_string)[:-1],2)))



if __name__ == '__main__': main()
