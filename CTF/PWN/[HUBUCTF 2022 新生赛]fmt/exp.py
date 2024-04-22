flag = ['637b46544353534e', '2d62336432386337', '3936342d31323439', '352d373861392d65', '3133396434386232', 'a7d336238']
for str in flag:
    for i in range(len(str) - 2,-1,-2):
        byte = str[i:i+2]
        print(chr(int(byte,16)),end="")