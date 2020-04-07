import numpy as np
import itertools
import string

def gcd(a, b):
    while a != 0:
        a, b = b % a, a
    return b
def findModReverse(a, m):  # 这个扩展欧几里得算法求模逆

    if gcd(a, m) != 1:
        return None
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m


# 表值
dic = {1: 'A', 2: 'B', 3: 'C', 4: 'D', 5: 'E', 6: 'F', 7: 'G', 8: 'H', 9: 'I', 10: 'J', 11: 'K', 12: 'L', 13: 'M',
       14: 'N', 15: 'O', 16: 'P', 17: 'Q', 18: 'R', 19: 'S', 20: 'T', 21: 'U', 22: 'V', 23: 'W', 24: 'X', 25: 'Y',
       0: 'Z'}
# dic = {0: 'A', 1: 'B', 2: 'C', 3: 'D', 4: 'E', 5: 'F', 6: 'G', 7: 'H', 8: 'I', 9: 'J', 10: 'K', 11: 'L', 12: 'M',
#        13: 'N', 14: 'O', 15: 'P', 16: 'Q', 17: 'R', 18: 'S', 19: 'T', 20: 'U', 21: 'V', 22: 'W', 23: 'X', 24: 'Y',
#        25: 'Z'}



def convert_to_number(plaintext):
    """
    将密文字符串转换为与表值对应的数字
    :param plaintext: 密码密文
    :return: 数字列表
    """
    """
    :param plaintext:
    :return:
    """
    # 判断字符产长度是奇是偶，若为奇数最后一位重复一次
    if len(plaintext) % 2 == 1:
        plaintext += plaintext[-1]
    plaintext = plaintext.upper()
    # 将字符串转换为与表值对应的数字
    plaintext_number = []
    for i in plaintext:
        for k, v in dic.items():
            if i == v:
                plaintext_number.append(k)
                break
    return (plaintext_number)


def convert_to_string(number):
    """
    将数字转换位表值对应的字符串
    :param number: 数字列表
    :return: 字符串
    """
    string = ''
    for i in number:
        # 取模运算
        i = i % 26
        for k, v in dic.items():
            if i == 0:
                string += 'A'
                break
            elif i == k:
                string += v
                break
    return string


def encrypt(plaintext, keys):
    plaintext_number = convert_to_number(plaintext)
    # 将数字明文两两一组创建为向量保存在临时字典之中
    vector = {}
    m = 0
    n = 0
    while (n < len(plaintext_number)):
        vector[m] = np.array([plaintext_number[n], plaintext_number[n + 1]]).reshape((2, 1))
        m += 1
        n += 2

    # 将向量字典中的value依次左乘加密矩阵
    for k, v in vector.items():
        vector[k] = np.dot(keys, v)
    # 将两两一组的矩阵转换为密文数字列表
    ciphertext_number = []
    for k, v in vector.items():
        v = list(v)
        ciphertext_number.append(round(v[0][0]))
        ciphertext_number.append(round(v[1][0]))
    # 将数字密文转换为字符串
    ciphertext = convert_to_string(ciphertext_number)
    return ciphertext


def decrypt(ciphertext, keys):
    """ 将数字密文进行解密 :param ciphertext: 数字密文 :param keys: 解密矩阵 :return: 明文字符串 """
    key_value = keys[0][0] * keys[1][1] - keys[0][1] * keys[1][0]#获取二维矩阵的密钥
    if gcd(key_value, 26) != 1:
        return None  #密钥不互质无法解密
    else:
        keys = get_inverse_key(keys)#获取密钥的逆
        print("密钥的逆")
        print(keys)
        return encrypt(ciphertext,keys)#密文乘以密钥的逆mod26为明文

def deciper(cipher, plain):
    """ 破解加密矩阵
    :param cipher: 密文
    :param plain: 明文
    :return: 加密矩阵的逆
    """
    # 先将密文以及明文转换为表值对应的数字
    cipher = convert_to_number(cipher)
    plain = convert_to_number(plain)
    # 两两一组构建向量
    vector_cipher = {}
    vector_plain = {}

    m = 0
    n = 0
    while (n < len(cipher)):
        vector_cipher[m] = np.array([cipher[n], cipher[n + 1]]).reshape((2, 1))
        m += 1
        n += 2

    m = 0
    n = 0
    while (n < len(plain)):
        vector_plain[m] = np.array([plain[n], plain[n + 1]]).reshape((2, 1))
        m += 1
        n += 2
    # 将明文密文重构成二阶行列式
    a, b, c, d = vector_plain[0][0][0], vector_plain[1][0][0], vector_plain[0][1][0], vector_plain[1][1][0]
    ls = ([a, b], [c, d])
    vector_plain = np.array(ls).reshape((2, 2))

    # 明文矩阵
    a, b, c, d = vector_cipher[0][0][0], vector_cipher[1][0][0], vector_cipher[0][1][0], vector_cipher[1][1][0]
    ls = ([a, b], [c, d])
    # 密文矩阵
    vector_cipher = np.array(ls).reshape((2, 2))
    # 计算加密矩阵的逆矩阵 (明文矩阵*密文矩阵的逆)
    # 行列式的值:inverse_value
    value = (a * d - b * c) % 26
    inverse_value = findModReverse(value, 26)
    if  inverse_value == None:
        a =([0.0],[0,0])

        return np.array(a)
    # 伴随矩阵
    ls = ([d, -b], [-c, a])
    vector_star = np.array(ls)
    # 逆矩阵
    inverse_vector_cipher = inverse_value * vector_star

    # 将矩阵中的数字元素模26
    for i in range(len(inverse_vector_cipher)):
        for j in range(len(inverse_vector_cipher[i])):
            inverse_vector_cipher[i][j] = int(inverse_vector_cipher[i][j]) % 26

    # 求加密矩阵的逆
    inverse_vector = np.dot(vector_plain, inverse_vector_cipher)
    #inverse_vector = np.dot(inverse_vector_cipher, vector_plain)
    # print("密文矩阵", vector_cipher)
    # print("密文逆矩阵", inverse_vector_cipher)
    # print("明文矩阵", vector_plain)
    print("结果", inverse_vector)
    for i in range(len(inverse_vector)):
        for j in range(len(inverse_vector[i])):
            t = int(inverse_vector[i][j]) % 26
            inverse_vector[i][j] = t
    return inverse_vector


def crack(know_cypher, know_plain, allcypher):
    inverse_key = deciper(know_cypher, know_plain)
    try:
        if inverse_key.all == None:#判断密钥为空返回None
            return None
        return decrypt(allcypher, inverse_key)
    except Exception as e:
        return None  #返回None说明已知明文和密文求不出模逆请更换

def returnkey(know_cypher, know_plain):
    inverse_key = deciper(know_cypher, know_plain)
    inverse_key = inverse_key.tolist()
    a = ','.join(str(i) for i in inverse_key)
    print(a)
    return a

def get_key(a, b, c, d):
    key = ([a, b], [c, d])
    return np.array(key)


def get_inverse_key(key):
    key_value = key[0][0] * key[1][1] - key[0][1] * key[1][0]  # 矩阵行列式的值为9
    inverse_key_value = findModReverse(key_value, 26)  # 行列式的值模逆
    # star = ([3, -2], [0, 1])  # 伴随矩阵[[3 -2]

    star = ([key[1][1], -key[0][1]], [-key[1][0], key[0][0]])

    key_star = np.array(star)  # [0 1]]
    inverse_key = inverse_key_value * key_star  # 逆矩阵[[1 8]

    # 将矩阵中的数字元素模26 [0 9]]
    for i in range(len(inverse_key)):
        for j in range(len(inverse_key[i])):
            inverse_key[i][j] = int(inverse_key[i][j]) % 26

    return inverse_key


if __name__ == "__main__":
    plain = "CLINTONISGOINGTOVISITACOUNTRYINMIDDLEEASTT"
    know_plain = "KPXS"#VCGS
    know_cypher = "INTO"#TACO
    a = 1
    b = 2
    c = 0
    d = 3

    key = get_key(a, b, c, d)

    cypher = encrypt(plain, key)

    plain = decrypt(cypher, key)

    crack_plain = crack(know_cypher, know_plain, cypher)
    returnkey(know_cypher, know_plain)
    print("明文：", plain)
    print("加密结果：", cypher)
    print("解密结果：", plain)
    print("破解结果：", crack_plain)
