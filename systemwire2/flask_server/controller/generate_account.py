import linecache
import random
import re
import string

import numpy as np
from xpinyin import Pinyin


# 分析用户名字符模式
def find_pattern(name):  # name = name + " "
    l = 0  # 字母个数
    d = 0  # 数字个数
    m = 0  # 特殊字符个数
    fmt = ""  # 字符模式
    charList = []  # 字符列表
    ch = []
    num = []
    mark = []
    for i in range(len(name)):
        # 类型判断
        if charList == []:
            pre_tp = ""
        if name[i].isdigit():
            tp = "d"
            d += 1
        elif name[i].isalpha():
            tp = "l"
            l += 1
        else:
            tp = "m"
            m += 1

        if pre_tp == "":
            charList.append(name[i])
            pre_tp = tp
        elif tp == pre_tp:
            charList.append(name[i])
        elif tp != pre_tp and charList != []:
            fmt = fmt + pre_tp + str(len(charList)) + " "  # "".join([c for c in charList])
            if pre_tp == "d":
                num.append("".join([c for c in charList]))
                d = 0
            elif pre_tp == "l":
                ch.append("".join([c for c in charList]))
                l = 0
            elif pre_tp == "m":
                mark.append("".join([c for c in charList]))
                m = 0
            charList.clear()
            pre_tp = tp
            charList.append(name[i])

        if i == len(name) - 1:
            fmt += pre_tp + str(len(charList))
            if pre_tp == "d":
                num.append("".join([c for c in charList]))
            elif pre_tp == "l":
                ch.append("".join([c for c in charList]))
            elif pre_tp == "m":
                mark.append("".join([c for c in charList]))
            charList.clear()
    return fmt, ch, num, mark


def is_chinese(check_str):
    for ch in check_str:
        if not re.match(u'[\u4e00-\u9fa5]+', ch):
            return False
    return True


def username_generate(seed, num) -> list:
    years = [1985, 1986, 1987, 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001, 2002]
    spec_chars = ["+", "-", "_"]

    p = Pinyin()
    account_list = []
    if is_chinese(seed):
        py = p.get_pinyin(seed, "")  # zhangsan
        form1 = p.get_initials(seed, "").lower()  # zs
        form2 = p.get_initials(seed[0], "").lower() + p.get_pinyin(seed[1:], "")  # zsan
        form3 = p.get_pinyin(seed[0], "") + p.get_initials(seed[1:], "").lower()  # zhangs
        if num < 4:
            num1 = 1
            num2 = 1
        else:
            num1 = int(num/2)
            num2 = int(num/4)
        while len(account_list)<num1:
            account = py + str(years[random.randint(0,len(years)-1)])
            account_list.append(account)
        while len(account_list)<num1+num2:
            account = form1 + str(years[random.randint(0,len(years)-1)])
            account_list.append(account)
        while len(account_list)<num1+2*num2:
            account = form2 + str(years[random.randint(0,len(years)-1)])
            account_list.append(account)
        while len(account_list)<num:
            account = form3 + str(years[random.randint(0,len(years)-1)])
            account_list.append(account)
        # 账号去重
        unique_account_list = set(account_list)
        while len(unique_account_list)<num:
            account = form3 + str(years[random.randint(0,len(years)-1)])
            unique_account_list.add(account)
        account_list = list(unique_account_list)
    else:
        username = seed.split("@")[0]
        fmt,ch,digit,mark=find_pattern(username)
        num_list = []
        num_list.append(int(num/2))
        num_list.append(num-int(num/2))
            
        while len(account_list)<num_list[0]:
            if ch != []:
                letter = "".join(ch) + "".join(random.choice(string.ascii_lowercase) for i in range(random.randint(1,2))) 
            if digit != []:
                if random.randint(0,1) == 0:
                    number = "".join(digit) + "".join(random.choice(string.digits) for i in range(random.randint(1,3)))
                else:
                    number = int("".join(digit)) + random.randint(1,9)
            else:
                number = random.randint(1,9)
            if fmt[0] == "l": # 用户名有字母
                account = letter + str(number)
            else:
                account = str(number) + letter
            if account not in account_list: # 账号去重
                account_list.append(account)
        while len(account_list)<num_list[0]:
            account = "".join(random.choice(string.ascii_lowercase) for i in range(random.randint(3,5)))
            account_list.append(account)
        while len(account_list)<num:
            account = "".join(ch) + "".join(str(years[random.randint(0,len(years)-1)]))
            if account not in account_list: # 账号去重
                account_list.append(account)
        # for account in generate_by_dic(num_list[1]):  # 字典生成一部分账号
        #     account_list.append(account)
        # for account in generate_by_markov(seed,num_list[2]): # 马尔科夫链生成一部分账号
        #     account_list.append(account)
    return account_list


def generate_by_dic(num) -> list:
    username = set()
    while len(username)<num:
        username.add(linecache.getline("./template/user500.txt",random.randint(1,512)).strip())
    username = list(set(username))
    while len(username)<num:
        username.add(linecache.getline("./template/user1000.txt",random.randint(1,1024)).strip())
    return list(username)

# 生成密码
def password_genaerate(num, length=12) -> list:
    password_list = []

    # 生成更真实的弱密码模式
    common_words = ["Password", "Welcome", "Admin", "qwerty", "abc123", "hello",
                    "iloveyou", "monkey", "dragon", "master", "login", "trustno1",
                    "sunshine", "princess", "football", "shadow", "superman", "michael"]

    spec_chars = ["!", "@", "#", "$", "_"]
    recent_years = [str(y) for y in range(2020, 2025)]

    for _ in range(num):
        if random.random() < 0.35:
            # 模式1: 常见词+年份+特殊字符 (如 Welcome2024!)
            password = random.choice(common_words) + random.choice(recent_years) + random.choice(spec_chars)
        elif random.random() < 0.55:
            # 模式2: 常见词+3位随机数字+特殊字符 (如 Admin582@)
            password = random.choice(common_words) + ''.join(random.choice(string.digits) for _ in range(3)) + random.choice(spec_chars)
        elif random.random() < 0.75:
            # 模式3: 拼音+年份+特殊字符 (如 zhangsan1990!)
            p = Pinyin()
            chinese_names = ["张三", "李四", "王五", "赵六", "刘七", "陈八"]
            password = p.get_pinyin(random.choice(chinese_names), "") + random.choice(recent_years) + random.choice(spec_chars)
        else:
            # 模式4: 随机字母数字混合 (保底)
            password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

        password_list.append(password)

    return password_list


def getTransitionTable(data, k=4):  # if X is the sequence of 'k = 3' and Y is predicted character or k+1 the character
    T = {}  # making an empty dictionary

    for i in range(len(data) - k):
        X = data[i:i + k]
        Y = data[i + k]
        # making dictornary for each after word and new that are not in dict of x(transition dict)
        if T.get(X) is None:
            T[X] = {}
            T[X][Y] = 1
        else:
            if T[X].get(Y) is None:  # checking is y is not present or notin Transition Dictonary(x)!!
                T[X][Y] = 1
            else:
                T[X][Y] += 1

    return T


def convertFreqIntoProb(T):
    for kx in T.keys():
        s = float(sum(T[kx].values()))
        for k in T[kx].keys():
            T[kx][k] = T[kx][k] / s
    return T


def MarkovChain(Text, k=4):
    T = getTransitionTable(Text, k)
    T = convertFreqIntoProb(T)
    return T


def sample_next(ctx, model, k):
    ctx = ctx[-k:]
    if model.get(ctx) is None:
        return " "
    possible_Chars = list(model[ctx].keys())
    possible_values = list(model[ctx].values())
    return np.random.choice(possible_Chars, p=possible_values)


def generateText(starting_sent, model, k=4, maxLen=10):
    sentence = starting_sent
    ctx = starting_sent[-k:]
    for ix in range(maxLen):
        next_prediction = sample_next(ctx, model, k)
        sentence += next_prediction
        ctx = sentence[-k:]
    return sentence


def generate_by_markov(seed, num):
    text = open("../../config/corpus_py.txt", "r", encoding="utf-8").read()

    model_1 = MarkovChain(text, k=1)
    model_2 = MarkovChain(text, k=2)
    model_3 = MarkovChain(text, k=3)
    model_4 = MarkovChain(text, k=4)
    model_list = [model_1, model_2, model_3, model_4]
    # print(model_1)
    gen_list = []
    for i in range(num):
        length = random.randint(1, 4)
        textGenerated = generateText(seed, model_list[length - 1], maxLen=1, k=length)
        gen_list.append(textGenerated)
    print(gen_list)
    return gen_list


if __name__ == "__main__":
    # 提取中文文本数据
    # f = open("corpus.txt","w+",encoding="utf-8")
    # with open("E:\ChromeDownload\part-000036-a894b46e.jsonl\part-000036-a894b46e.jsonl","r",encoding="utf-8") as reader:
    #     for i in range(100):
    #         data = reader.readline()
    #         data = data.replace("\n","")
    #         data_dict  = json.loads(data)
    #         f.write(data_dict["content"] + "\n\n")
    # f.close()

    # 汉字转化为拼音数据
    # with open("corpus.txt","r",encoding="utf-8") as f:
    #     data = f.read()
    #     p = Pinyin()
    #     py = p.get_pinyin(data,"")
    #     print(py)
    # f = open("corpus_py.txt","w+",encoding="utf-8")
    # f.write(py)
    # f.close()

    # text = open("corpus_py.txt","r",encoding="utf-8").read()
    # model_1 = MarkovChain(text,k=1)
    # model_2 = MarkovChain(text,k=2)
    # model_3 = MarkovChain(text,k=3)
    # model_4 = MarkovChain(text,k=4)
    # # print(model_1)
    # textGenerated = generateText("z",model_1,maxLen=10,k=1) 
    # print(textGenerated)

    # fmt,ch,digit,mark=find_pattern("123")
    # print(fmt)

    val = username_generate("zhangsan", 5)
    print(val)
