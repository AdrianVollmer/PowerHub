import string
import random


symbol_list = {None: None}


def symbol_name(name):
    global symbol_list
    if name not in symbol_list:
        symbol_list[name] = choose_obfuscated_name()
    return symbol_list[name]


def choose_obfuscated_name():
    result = None
    while not result and result in list(symbol_list.values()):
        result = ''.join([random.choice(string.ascii_lowercase)
                          for i in range(4)])
        result = random.choice(string.ascii_uppercase) + result
    return result
