def hextobase64(hex_string):

    switcher = {
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
        result=result + switcher.get(binl, "=")


    return result


def fixedXor(hex_string1,hex_string2):
    if(len(hex_string1)==len(hex_string2)):
        return hex(int(hex_string1,16) ^ int(hex_string2,16) )[2:]
    else:
        return -1

def weight(str):
    weight=0;
    Cap=['E','T','A','O','I','N','S','H','R','D','L','U']
    Sml=['e','t','a','o','i','n','s','h','r','d','l','u']
    for l in range(11,0,-1):
        weight=weight+(12-l)*( str.count(Cap[l]) + str.count(Sml[l]) )

    Words=[" a "," about "," all " ," also "," and "," as "," at "," be "," because "," but "," by "]
    for w in range(9,0,-1):
        weight=weight+(12-w)*( str.count(Words[w]) )

    return weight + 6*str.count(' ')


def singlebyteXor(hex_string):
    dicrypthexl=[]
    dicrypthex=""
    for key in range(0,256):
        for n in range(2,len(hex_string)+2,2):
            dicrypthex=dicrypthex + chr(int(hex_string[n-2:n],16) ^ key )
        dicrypthexl.append(dicrypthex)
        dicrypthex=""

    return(max(dicrypthexl, key=lambda l: weight(l)))


def detectXor(filename):
    decr_list=[]
    file = open(filename, "r")
    for line in file:
        if len(line[:-1])!=60:
            continue
        decr_list.append(singlebyteXor(line[:-1]))
    return max(decr_list, key=lambda l: weight(l))

def main():
    print("Set1 Challenges")
    hex_string1="49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    print("Challenge 1: "+hextobase64(hex_string1)+"\n")

    hex_string2_1="1c0111001f010100061a024b53535009181c"
    hex_string2_2="686974207468652062756c6c277320657965"
    print("Challenge 2: "+fixedXor(hex_string2_1,hex_string2_2)+"\n")

    hex_string3="1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    print("Challenge 3: "+singlebyteXor(hex_string3)+"\n")

    print("Challenge 4: "+detectXor("4.txt"))


    print("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")

    for l in "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal":

        for l in "ICE":
            print(l)

if __name__ == '__main__': main()
