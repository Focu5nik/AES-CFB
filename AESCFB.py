import dataAES as data
import copy


def XOR_bytes(var, key):
    return bytes(a ^ b for a, b in zip(var, key))
    

def matrix_mult(A, B):
    C = [[0] * len(B[0]) for _ in range(len(A))]
    for i in range(len(A)):
        for j in range(len(B)):
            for k in range(len(B[0])):

                # print(A[i][j], B[j][k])
                # print(A[i][j] * B[j][k])


                index = int.from_bytes(B[j][k])

                if A[i][j] == 1:
                    temp =  index
                elif A[i][j] == 2:
                    temp =  data.multiply_by_2_mat[index]
                elif A[i][j] == 3:
                    temp = data.multiply_by_3_mat[index]
                elif A[i][j] == 9:
                    temp = data.multiply_by_9_mat[index]
                elif A[i][j] == 11:
                    temp = data.multiply_by_11_mat[index]
                elif A[i][j] == 13:
                    temp = data.multiply_by_13_mat[index]
                elif A[i][j] == 14:
                    temp = data.multiply_by_14_mat[index]


                temp = temp.to_bytes()

                if j == 0:
                    C[i][k] = temp
                else:
                    C[i][k] = XOR_bytes(C[i][k], temp)
    return C


def SubBytes(state_array):
    for i in range(len(state_array)):
        for j in range(len(state_array[0])):
            state_array[i][j] = data.Sbox[state_array[i][j][0]].to_bytes()


def ShiftRow(state_array, row):
    temp = state_array[row][0]
    for i in range(len(state_array[0]) - 1):
        state_array[row][i] = state_array[row][i + 1]
    state_array[row][len(state_array[0]) - 1] = temp


def ShiftRows(state_array):
    for row in range(len(state_array)):
        for _ in range(row):
            ShiftRow(state_array, row)
                

def MixColumns(state_array):    
    state_array = matrix_mult(data.mix_colums_matrix, state_array)


def AddRoundKey(state_array, W, round):
    for column in range(len(state_array[0])):
        for i in range(len(state_array)):
            state_array[i][column] = XOR_bytes(state_array[i][column], W[4 * round + column][i].to_bytes())


def SubWord(word):
    return bytes(data.Sbox[byte] for byte in word)


def RotWord(word):
    word = bytes(word[1:] + word[:1]) 
    return word


def keyExpansion(key):    
    Nk = 4
    W = [key[i] for i in range(len(key))]

    for i in range(4, 44):     
        T = W[i - 1]
        if i % Nk == 0:
            T = XOR_bytes( SubWord( RotWord(T) ), bytes(data.Rcon[i // Nk]) )
        W.append( XOR_bytes(W[i - Nk], T) )
    return W


def Cipher(state_array, W):
    rounds_number = 10

    AddRoundKey(state_array, W, 0)
    for round in range(1, rounds_number):
        SubBytes(state_array)
        ShiftRows(state_array)
        MixColumns(state_array)
        AddRoundKey(state_array, W, round)

    SubBytes(state_array)
    ShiftRows(state_array)
    AddRoundKey(state_array, W, rounds_number)


def InvShiftRow(state_array, row):
    new = state_array[row][0]
    for i in range(0, len(state_array[0]) - 1):
        t = state_array[row][i + 1]
        state_array[row][i + 1] = new
        new = t
    state_array[row][0] = new


def InvShiftRows(state_array):
    for row in range(len(state_array)):
        for _ in range(row):
            InvShiftRow(state_array, row)


def InvSubBytes(state_array):
    for i in range(len(state_array)):
        for j in range(len(state_array[0])):
            state_array[i][j] = data.InvSbox[state_array[i][j][0]].to_bytes()


def InvMixColumns(state_array):
    state_array = matrix_mult(data.inv_mix_colums_matrix, state_array)


def InvCipher(state_array, W):
    rounds_number = 10

    AddRoundKey(state_array, W, rounds_number)

    for round in range(rounds_number - 1, 0, -1):
        InvShiftRows(state_array)
        InvSubBytes(state_array)
        AddRoundKey(state_array,  W, round)
        InvMixColumns(state_array)


    InvShiftRows(state_array)
    InvSubBytes(state_array)
    AddRoundKey(state_array, W, 0)


def XOR_blocks(A, B):
    C = [[0] * 4 for _ in range(4)]
    for c in range(len(A[0])):
        for r in range(len(A)):
            C[r][c] = XOR_bytes(A[r][c], B[r][c])
    return C


def Encrypt_CFB(input_file_path, key_string, output_file_path):
    key = []
    for i in range(4):
        word = key_string[i : i + 4].encode('utf-8')
        key.append(word)

    W = keyExpansion(key)


    I_V = "qwertyqwertyqwer" 

    C = [[0] * 4 for _ in range(4)]

    for c in range(4):     
        for r in range(4):
            C[r][c] = I_V[4 * c + r].encode('utf-8')


    state_array = [[b''] * 4 for _ in range(4)]

    with open(input_file_path, 'rb') as input:
        with open(output_file_path, 'wb') as output:
            readable = True
            while readable:        
                bytes_block = input.read(16)
                bytes_len = len(bytes_block)
                if bytes_len == 0:
                    break
                elif bytes_len < 16:
                    readable = False
                    for c in range(4):     
                        for r in range(4):
                            if r + 4 * c < bytes_len:
                                state_array[r][c] = bytes_block[r + 4 * c].to_bytes()
                            else:
                                state_array[r][c] = bytes([0])
                else:
                    for c in range(4):     
                        for r in range(4):
                            state_array[r][c] = bytes_block[r + 4 * c].to_bytes()


                Cipher(C, W)

                C = XOR_blocks(C, state_array)


                for c in range(4):     
                    for r in range(4):
                        output.write(C[r][c])


def Decrypt_CFB(input_file_path, key_string, output_file_path):
    key = []
    for i in range(4):
        word = key_string[i : i + 4].encode('utf-8')
        key.append(word)

    W = keyExpansion(key)


    I_V = "qwertyqwertyqwer" 

    C = [[0] * 4 for _ in range(4)]

    for c in range(4):     
        for r in range(4):
            C[r][c] = I_V[4 * c + r].encode('utf-8')


    state_array = [[b''] * 4 for _ in range(4)]

    with open(input_file_path, 'rb') as input:
        with open(output_file_path, 'wb') as output:
            while True:
                bytes_block = input.read(16)

                if len(bytes_block) == 0:
                    break

                for c in range(4):     
                    for r in range(4):
                        state_array[r][c] = bytes_block[r + 4 * c].to_bytes()


                Cipher(C, W)

                decrypted_block = XOR_blocks(C, state_array)


                C = copy.deepcopy(state_array)


                for c in range(4):     
                    for r in range(4):
                        if decrypted_block[r][c] != bytes([0]):
                            output.write(decrypted_block[r][c])



def Encrypt_CFB_str(input_str, key_string):
    key = []
    for i in range(4):
        word = key_string[i : i + 4].encode('utf-8')
        key.append(word)

    W = keyExpansion(key)


    I_V = "qwertyqwertyqwer" 

    C = [[0] * 4 for _ in range(4)]

    for c in range(4):     
        for r in range(4):
            C[r][c] = I_V[4 * c + r].encode('utf-8')


    state_array = [[b''] * 4 for _ in range(4)]

    result = b''
    # with open(input_file_path, 'rb') as input:
    readable = True
    input_str = input_str.encode('utf-8')
    while readable:        
        # bytes_block = input.read(16)
        bytes_block = input_str[:16]
        input_str = input_str[16:]


        bytes_len = len(bytes_block)
        if bytes_len == 0:
            break
        elif bytes_len < 16:
            readable = False
            for c in range(4):     
                for r in range(4):
                    if r + 4 * c < bytes_len:
                        state_array[r][c] = bytes_block[r + 4 * c].to_bytes()
                    else:
                        state_array[r][c] = bytes([0])
        else:
            for c in range(4):     
                for r in range(4):
                    state_array[r][c] = bytes_block[r + 4 * c].to_bytes()


        Cipher(C, W)

        C = XOR_blocks(C, state_array)


        for c in range(4):     
            for r in range(4):
                # output.write(C[r][c])
                result += C[r][c]
    return result


def Decrypt_CFB_str(input_byte_str, key_string):
    key = []
    for i in range(4):
        word = key_string[i : i + 4].encode('utf-8')
        key.append(word)

    W = keyExpansion(key)


    I_V = "qwertyqwertyqwer" 

    C = [[0] * 4 for _ in range(4)]

    for c in range(4):     
        for r in range(4):
            C[r][c] = I_V[4 * c + r].encode('utf-8')


    state_array = [[b''] * 4 for _ in range(4)]

    result = ''
    # with open(input_file_path, 'rb') as input:
    #     with open(output_file_path, 'wb') as output:
    while True:
        # bytes_block = input.read(16)
        bytes_block = input_byte_str[:16]
        input_byte_str = input_byte_str[16:]

        if len(bytes_block) == 0:
            break

        for c in range(4):     
            for r in range(4):
                state_array[r][c] = bytes_block[r + 4 * c].to_bytes()


        Cipher(C, W)

        decrypted_block = XOR_blocks(C, state_array)


        C = copy.deepcopy(state_array)


        for c in range(4):     
            for r in range(4):
                if decrypted_block[r][c] != bytes([0]):
                    result += decrypted_block[r][c].decode('utf-8')
                    # output.write(decrypted_block[r][c])

    return result



def main():   
    input_file_path = "text/some_text_file.txt"

    output_file_path = "text/encrypted.txt"
    key_string = "dfgdfgsdfgsdfgsdfgsdfgsdgfsdfgsdfgdsfgsd"

    Encrypt_CFB(input_file_path, key_string, output_file_path)

    input_file_path = "text/encrypted.txt"
    output_file_path = "text/decrypted.txt"

    Decrypt_CFB(input_file_path, key_string, output_file_path)


if __name__ == "__main__":
    main()
