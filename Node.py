"""
Node in the blockchain network
"""

from Cryptodome.PublicKey import RSA


class Node(object):

    def __init__(self, address, public_key):
        self.address = address
        self.public_key = public_key
        #set initial balance to 10
        self.balance = 10

    def __str__(self):
        rep = self.address + '\n' + str(self.public_key.exportKey()) + '\n' + self.balance

