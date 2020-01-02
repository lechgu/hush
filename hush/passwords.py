import random
import secrets
import string


def generate(length, character_classes):
    alphabet = ""
    pwd = []
    if "a" in character_classes:
        alphabet += string.ascii_lowercase
        pwd += secrets.choice(string.ascii_lowercase)
    if "A" in character_classes:
        alphabet += string.ascii_uppercase
        pwd += secrets.choice(string.ascii_uppercase)
    if "8" in character_classes:
        alphabet += string.digits
        pwd += secrets.choice(string.digits)
    if "#" in character_classes:
        non_alphahumerical = r"~!@#$%^&*_-+=|\(){}[]:;<>,.?/"
        alphabet += non_alphahumerical
        pwd += secrets.choice(non_alphahumerical)
    random.shuffle(pwd)
    pwd += [secrets.choice(alphabet) for x in range(length - len(pwd))]
    return "".join(pwd)
