import string
import random


symbol_list = {None: None}


def symbol_name(name):
    global symbol_list
    if name not in symbol_list:
        symbol_list[name] = choose_obfuscated_name()
    return symbol_list[name]


def choose_obfuscated_name():
    # TODO choose better names
    # the names should not contain too much entropy, or it will be
    # detectable. they should also not be too common or we will risk
    # collisions. they should just blend in perfectly.
    result = None
    while not result and result in list(symbol_list.values()):
        result = ''.join([random.choice(string.ascii_lowercase)
                          for i in range(4)])
        result = random.choice(string.ascii_uppercase) + result
    return result
