# 字母频率表
probability = [0.082, 0.015, 0.028, 0.043, 0.127, 0.022, 0.02, 0.061, 0.07, 0.002, 0.008, 0.04, 0.024,
               0.067, 0.075, 0.019, 0.001, 0.06, 0.063, 0.091, 0.028, 0.01, 0.023, 0.001, 0.02, 0.001]


def cut(text, keyLength):  # 根据keyLength对text进行分组,分组后每组（按行看）变成凯撒密码，按列看是密文
    res = []
    for i in range(keyLength):
        j = 0
        subCipher = ""
        while (i + j * keyLength < len(text)):
            subCipher += (text[i + j * keyLength])
            j += 1
        res.append(subCipher)
    return res


def initFind():  # 初始化find字典，用于存储字母出现次数
    find = {}
    for j in range(26):
        find[chr(j + 65)] = 0
    return find


def initKey(keyLength):  # 用于暴力破解的密码初始化，初始为keyLength个'A'
    key = "A" * keyLength
    return key


def nextKey(key, keyLength):  # 用于暴力破解，得到下一个密钥，比如AAAZ下一个是AABA
    key = list(key)
    # finalKey = "Z" * keyLength
    # if key == list(finalKey) :
    #     return finalKey
    for i in range(keyLength - 1, -1, -1):
        if key[i] != "Z":
            key[i] = chr(ord(key[i]) + 1)
            break
        else:
            if key[i - 1] != "Z":
                key[i - 1] = chr(ord(key[i - 1]) + 1)
                for j in range(keyLength - 1, i - 1, -1):
                    key[j] = "A"
                break
            else:
                pass
    return "".join(key)


def countLetter(text):  # 统计26个字母各自 在参数text中 出现的次数
    # 初始化计数数组
    find = initFind()
    for j in range(len(text)):
        find[text[j]] += 1
    return find


def cutAndcount(text, keyLength):
    countPerGroup = []
    txtGroup = cut(text, keyLength)
    for i in range(keyLength):
        countPerGroup.append(countLetter(txtGroup[i]))
    return [txtGroup, countPerGroup]


def calcIC(text, occurrence):  # 在给定字母出现次数统计表的情况下计算重合指数
    IC = 0
    denominator = len(text) ** 2
    for j in range(26):
        Pj = occurrence[chr(j + 65)]
        IC += (Pj * Pj)
    IC /= denominator
    return IC


def getKey(keyLength, cipherGroup, find):  # 根据密钥长度猜测密钥
    # k = []
    global groupIC
    global probability
    key = ""
    for i in range(keyLength):  # 共keyLength组密文
        delta = 0  # 位移量
        while (delta <= 25):
            IC = 0
            flag = 65 + delta
            subCipher = cipherGroup[i]
            found = find[i]
            for j in range(26):  # 根据拟重合指数公式，此处flag所表示的字母是与英语的中第j个字母对应的
                p = probability[j]
                if flag == 91: flag = 65
                f = found[chr(flag)] / len(subCipher)
                IC += p * f
                flag += 1

            if IC >= groupIC:
                key += chr(65 + delta)
                break
            else:
                delta += 1
    # print("key = %s, IC = %f" %(key, IC))
    if keyLength == len(key):
        print("猜测密钥：" + key, end=', ')
    else:
        key = None
    return key


def decrypt(key, cipherText):  # key是str
    plainText = ""
    keyLength = len(key)
    n = len(cipherText)
    for i in range(n):
        k = key[i % keyLength]
        origin = ord(cipherText[i]) - ord(k)
        if origin < 0:  origin += 26
        origin += 65
        plainText += chr(origin)
    return plainText


# --------------------------以下是按keyLength暴力猜 # 因为排列组合太耗时间故取消
# def force(keyLength, cipherGroup, find):
#     key = initKey(keyLength)
#     global probability
#     for k in key:
#         IC = 0
#         flag = 65 + delta
#         subCipher = cipherGroup[i]
#         found = find[i]
#         for j in range(26):  # 根据拟重合指数公式，此处flag所表示的字母是与英语的中第j个字母对应的
#             p = probability[j]
#             if flag >= 91:  flag = flag - 91 + 65
#             f = found[chr(flag)] / len(subCipher)
#             IC += p * f
#             flag += 1


# --------------------------以下是按分组猜
def go(minKeyLength, maxKeyLength, text):
    global allAvgIC
    for keyLength in range(minKeyLength, maxKeyLength):  # 实际是到maxKeyLength-1
        IC = []  # 存每组的重合指数
        avgIC = 0  # 当前keyLength下的平均IC
        cutCount = cutAndcount(text, keyLength)
        # 得到分组
        res = cutCount[0]
        find = cutCount[1]
        # 计算重合指数
        for i in range(keyLength):
            IC.append(0)
            subCipher = res[i]
            found = find[i]
            IC[i] = calcIC(subCipher, found)
            avgIC += IC[i]
        avgIC /= keyLength
        if avgIC >= allAvgIC:
            key = getKey(keyLength, res, find)
            if key != None:
                plainText = decrypt(key, text)
                print('猜测密钥长度 %d 可能存在' % keyLength, end=', ')
                print('密钥是 %s\n解密得到明文: %s\n\n' % (key, plainText))
            else:
                print('猜测密钥长度 %d 无符合条件' % keyLength)
        else:
            print('猜测密钥长度 %d 无符合条件' % keyLength)


# 分组密钥的拟重合指数阈值 fi*pi/n（n是密文长度）
groupIC = 0.055
# 整体的平均重合指数阈值
allAvgIC = 0.06
# go(minKeyLength, maxKeyLength, text):
go(4, 7,
   r"KCCPKBGUFDPHQTYAVINRRTMVGRKDNBVFDETDGILTXRGUDDKOTFMBPVGEGLTGCKQRACQCWDNAWCRXIZAKFTLEWRPTYCQKYVXCHKFTPONCQQRHJVAJUWETMCMSPKQDYHJVDAHCTRLSVSKCGCZQQDZXGSFRLSWCWSJTBHAFSIASPRJAHKJRJUMVGKMITZHFPDISPZLVLGWTFPLKKEBDPGCEBSHCTJRWXBAFSPEZQNRWXCVYCGAONWDDKACKAWBBIKFTIOVKCGGHJVLNHIFFSQESVYCLACNVRWBBIREPBBVFEXOSCDYGZWPFDTKFQIYCWHJVLNHIQIBTKHJVNPIST")
