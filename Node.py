"""
Node in the blockchain network
"""

class Node(object):

    def __init__(self, address, public_key):
        self.address = address
        self.public_key = public_key
        #set initial balance to 10
        self.balance = 10


