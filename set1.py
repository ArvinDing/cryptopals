import base64

def hexToBase64(hex_string):
    raw_bytes = bytes.fromhex(hex_string)
    base64_bytes=base64.b64encode(raw_bytes)
    base64_string = base64_bytes.decode('utf-8')
    return base64_string
assert("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"== hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))

"""
xor between two hex strings
"""
def xor(a,b):
    a_bytes = bytes.fromhex(a)
    b_bytes = bytes.fromhex(b)
    xor_result = bytes(x ^ y for x, y in zip(a_bytes, b_bytes))
    return xor_result.hex()

assert(xor("1c0111001f010100061a024b53535009181c","686974207468652062756c6c277320657965")=="746865206b696420646f6e277420706c6179")

def xor_repeat(a,b):
    a_bytes, b_bytes=a,b
    if isinstance(a, str):
        a_bytes = a.encode('utf-8')
    if isinstance(b, str):
        b_bytes = b.encode('utf-8')
    xor_result = bytes(x ^ b_bytes[i%len(b_bytes)] for i, x in enumerate(a_bytes))
    return xor_result
assert(xor_repeat("""Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal""", "ICE").hex()== """0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f""")

"""
xor between hex string and byte (0-255)
"""
def xor_byte(a,byte):
    a_bytes = bytes.fromhex(a)
    xor_result = bytes(x ^ byte for x in a_bytes)
    return xor_result.decode('latin-1')

"""
return string from hex_string decrypted
"""
def decrypt_single_xor_cypher(hex_string):
    best_key = 0 
    input = bytes.fromhex(hex_string)
    best_match = fitting_quotient(input.decode('latin-1'))
    for k in range(256):
        new_string = xor_byte(hex_string, k)
        match_rate = fitting_quotient(new_string)
        if(match_rate< best_match):
            best_match=match_rate
            best_key=k
    return xor_byte(hex_string, best_key), best_key

english_percents = {
    
    'a': 8.2389258,    'b': 1.5051398,    'c': 2.8065007,    'd': 4.2904556,
    'e': 12.813865,    'f': 2.2476217,    'g': 2.0327458,    'h': 6.1476691,
    'i': 6.1476691,    'j': 0.1543474,    'k': 0.7787989,    'l': 4.0604477,
    'm': 2.4271893,    'n': 6.8084376,    'o': 7.5731132,    'p': 1.9459884,
    'q': 0.0958366,    'r': 6.0397268,    's': 6.3827211,    't': 9.1357551,
    'u': 2.7822893,    'v': 0.9866131,    'w': 2.3807842,    'x': 0.1513210,
    'y': 1.9913847,    'z': 0.0746517,    ' ' : 20
}

def fitting_quotient(text: str) -> float:
    text = text.lower()
    letter_counts = {letter: text.count(letter) for letter in english_percents.keys()}
    text_length=len(text)
    observed_percents = {letter: (count / text_length * 100) for letter, count in letter_counts.items()}
    fitting_quotient = sum((observed_percents[letter] - expected_percent) ** 2
                           for letter, expected_percent in english_percents.items())
    return fitting_quotient

assert(decrypt_single_xor_cypher("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")[0]=="Cooking MC's like a pound of bacon")

def challenge4():
    file_path = "4.txt"
    best_match = 1e10
    ans = ""
    with open(file_path, "r") as file:
        for line in file:
            input = line.strip()
            decoded_string = decrypt_single_xor_cypher(input)
            match = fitting_quotient(decoded_string)
            if(match<best_match):
                ans = decoded_string
                best_match = match
    print(ans)

def hamming_distance(a, b):
    a_bytes, b_bytes = a,b
    if isinstance(a,str):
        a_bytes = a.encode("utf-8")
    if isinstance(b,str):
        b_bytes = b.encode("utf-8")
    distance = 0
    for byte1, byte2 in zip(a_bytes, b_bytes):
        xor_result = byte1 ^ byte2
        distance += bin(xor_result).count('1')
    return distance
assert(hamming_distance("this is a test","wokka wokka!!!")==37)

"""
break repeating xor on bytes object to the string
"""
def break_repeat_xor(input: bytes):
    PART_CNT = 5
    min_dist_sum=1e100
    best_key_size= 0
    for key_size in range(2,41):
        parts=[]
        for i in range(PART_CNT):
            parts.append(input[i*key_size:(i+1)*key_size])
        
        dist=0
        for i in range(PART_CNT):
            for j in range(i+1,PART_CNT):
                dist += hamming_distance(parts[i],parts[j])
        dist/= (PART_CNT)*(PART_CNT-1)/2
        dist/=key_size
        print(key_size, dist)
        if(dist<min_dist_sum):
            min_dist_sum = dist
            best_key_size = key_size
    print(best_key_size)
    parts=[]
    key = bytes()
    for start_idx in range(best_key_size):
        seg = ""
        for i in range(start_idx,len(input),best_key_size):
            seg += hex(input[i])[2:].zfill(2)
        decoded, best_guess = decrypt_single_xor_cypher(seg)
        print(decoded)
        key += best_guess.to_bytes(1,  byteorder='big')
    return str(xor_repeat(input,key))

def challenge6():
    input_64 = ""
    with open("6.txt", "r") as file:
        for line in file:
            input_64 += line.strip()

    input = base64.b64decode(input_64)
    print(break_repeat_xor(input))
"""
rijndael S-box, matches wikepedia
"""

class Sbox:
    def __init__(self):
        self.sbox=[0]*256
        self.inverse_sbox=[0]*256
        p = 1
        q = 1
        
        while True:
            p = p^((p<<1) & 0xFF) ^ (0x1B if (p&0x80!=0) else 0)
            q ^= ((q<<1)& 0xFF)
            q ^= ((q<<2)& 0xFF)
            q ^= ((q<<4)& 0xFF)
            q ^= (0x09 if (q& 0x80 !=0) else 0)
           
            val =q^circular_shift(q,1)^circular_shift(q,2)^circular_shift(q,3)^circular_shift(q,4)^0x63
            self.sbox[p] = val
            self.inverse_sbox[val] = p
            if(p==1):
                break
        
        self.sbox[0]=0x63
        self.inverse_sbox[0x63]=0
        
    def forward(self, byte):
        return self.sbox[byte]

    def inverse(self, byte):
        return self.inverse_sbox[byte]


"""
round constant in AES
"""
def round_constant(i):
    def rc(i):
        if(i==1):
            return 1
        ans = rc(i-1)<<1
        if ans>=(1<<8):
            ans^=0x11B
        return ans
    assert(0<=rc(i) and rc(i)<256)
    return int.from_bytes(bytes([rc(i), 0, 0, 0]), "big")

"""rotate left one byte"""
def rot_word(b):
    if not isinstance(b,bytes):
        b = b.to_bytes(4,"big")
    return bytes([b[1],b[2],b[3],b[0]])

def circular_shift(byte, left_bits):
    shifted_byte = ((byte << left_bits) | (byte >> (8 - left_bits))) & 0xFF
    return shifted_byte

s_box = Sbox()
def sub_word(b):
    return bytes([s_box.forward(b[0]),s_box.forward(b[1]),s_box.forward(b[2]),s_box.forward(b[3])])

"""
takes the original 128 bit key
key expansion for AES-128
"""
def key_expansion(key):
    N = 4
    #ans conatins 32 bits words of expanded key
    ans = []
    for i in range(0,4*11):
        if(i<N):
            val = int.from_bytes(key[i*4:(i+1)*4],"big")
            ans.append(val)
        else:           
            if(i % N == 0 ):
                ans.append(ans[i-N]^int.from_bytes(sub_word(rot_word(ans[i-1])),"big")^round_constant(i//N))
            else:
                ans.append(ans[i-N]^ans[i-1])
    keys=[]
    for i in range(0,4*11,4):
        keys.append((ans[i]<<96)+(ans[i+1]<<64)+(ans[i+2]<<32)+ans[i+3])
    return keys



def add_round_key(state, round_key:int):
    round_key= round_key.to_bytes(16,"big")
    for i in range (4):
        for j in range (4):
            state[i][j]^= round_key[4*j+i]

def cyclic_shift_right(array, spaces):
    n = len(array)
    ans=[0]*n
    for i in range(0,n):
        ans[i]=array[(i-spaces+n)%n]    
    return ans

def inv_shift_row(state):
    for i in range(0,4):
        state[i] = cyclic_shift_right(state[i],i)

def inv_sub_bytes(state):
    s_box = Sbox()
    for i in range(0,4):
        for j in range(0,4):
            state[i][j]= s_box.inverse(state[i][j])

#times 2 in GF(2)[x]/(x^8+x^4+x^3+x+1)
def times2(num):
    return (num<<1 & 0xFF)^ (0x1B if (num&0x80!=0) else 0)

def times9(num):
    return times2(times2(times2(num)))^num

def times11(num):
    return times2(times2(times2(num))^num)^num

def times13(num):
    return times2(times2(times2(num)^num))^num

def times14(num):
    return times2(times2(times2(num)^num)^num)
    

def inv_mix_columns(state):
    #[t0,t1,t2,t3]=[[0e,0b,0d,09],[09,0e,0b,0d],[0d,09,0e,0b],[0b,0d,09,0e]][s0,s1,s2,s3]
    assert(len(state)==4)
    assert(len(state[0])==4)
    op=[times14,times11,times13, times9 ]
    for col in range(0,4):
        #matrix multiply
        ans=[0]*4
        for mult_row in range(0,4):
            ans[mult_row]^=op[(4-mult_row)%4](state[0][col])
            ans[mult_row]^=op[(5-mult_row)%4](state[1][col])
            ans[mult_row]^=op[(6-mult_row)%4](state[2][col])
            ans[mult_row]^=op[(7-mult_row)%4](state[3][col]) 
            
        for row in range(4):
            state[row][col]=ans[row]
        
def decrypt_aes_128(encoded :bytes,key: bytes):
    round_keys= key_expansion(key)#array of 128 
    assert(len(round_keys)==11)
    ans=[]
    for block in range(len(encoded)//16):
        state=[]
        for i in range (4):
            state_row=[]
            for j in range (4):
                state_row.append(encoded[block*16+4*j+i])
            state.append(state_row)
        #round10
        add_round_key(state, round_keys[10])
        # #round 9- round 1
        for round in range(9,0,-1):
            inv_shift_row(state)
            inv_sub_bytes(state)
            add_round_key(state, round_keys[round])
            inv_mix_columns(state)
        
        # #round0
        inv_shift_row(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[0])
        
    
        for j in range(0,4):
            for i in range(0,4):
                ans.append(state[i][j])  
    return bytes(ans)
        
def challenge7():
    key = "YELLOW SUBMARINE".encode("utf-8")
    
    input64 = ""
    with open("7.txt", "r") as file:
        for line in file:
            input64 += line.strip()
        
    input = base64.b64decode(input64)
    output = decrypt_aes_128(input,key)
    ans= output.decode('utf-8')
    assert("Play that funky music" in ans)
    print(ans)

challenge7()