import random as _random
import secrets as _secrets
import string as _string


def generate(length, character_classes):
    alphabet = ""
    pwd = []
    if "a" in character_classes:
        alphabet += _string.ascii_lowercase
        pwd += _secrets.choice(_string.ascii_lowercase)
    if "A" in character_classes:
        alphabet += _string.ascii_uppercase
        pwd += _secrets.choice(_string.ascii_uppercase)
    if "8" in character_classes:
        alphabet += _string.digits
        pwd += _secrets.choice(_string.digits)
    if "#" in character_classes:
        non_alphahumerical = r"~!@#$%^&*_-+=|(){}[]:;<>,.?/"
        alphabet += non_alphahumerical
        pwd += _secrets.choice(non_alphahumerical)
    _random.shuffle(pwd)
    pwd += [_secrets.choice(alphabet) for x in range(length - len(pwd))]
    return "".join(pwd)
