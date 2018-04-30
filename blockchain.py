"""
Learn Blockchain by Building One.
https://hackernoon.com/learn-blockchains-by-building-one-117428612f46
"""
import hashlib
import json
import os
import jsonpickle
import random
import base64
import ast
from time import time
from uuid import uuid4
from urllib.parse import urlparse
from flask import Flask, jsonify, request
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP



import requests

"""
The blockchain object contains a list of blocks (the chain), a list of transactions to be added to
the next block, and a set of all nodes in the network. Instantiating a new blockchain creates a
genesis block, from which all blocks are cryptographically linked to.
"""

class Blockchain(object):

    random_words = ['eternal', 'sample', 'egg', 'roar', 'different', 'bee', 'care', 'crevice', 'compartment',
                    'collar', 'seminar', 'harbor', 'slow', 'past', 'repetition', 'welcome', 'seller', 'population',
                    'inch', 'colorblind', 'ball', 'quiet', 'cheek', 'implication', 'elect', 'breeze']

    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.nodes = dict()
        self.private_keys = dict()
        self.public_keys = dict()

        #initial block
        self.new_block(proof=100, previous_hash=1)
        #initial node which handles payment of miners and distributes currency to the network
        node = Node("", 'master_node', 1000000)
        self.nodes['master_node'] = node


    """
    Adds a new node to the list of nodes. A node is a participant on the blockchain
    network. Each node can view the state of the blockhain, verify transactions through mining, and add
    new blocks to the chain
    """
    def register_node(self, parsed_url, public_key_str):
        node = Node(parsed_url, public_key_str)
        self.nodes[public_key_str] = node
        self.new_transaction('master_node', public_key_str, 10)

    def register_keys(self, private_key_str, private_key, public_key_str, public_key):
        self.public_keys[public_key_str] = public_key
        self.private_keys[private_key_str] = private_key


    """
    Determines if a given blockchain is valid. It iterates through the chain starting at the first block.
    If the next block's "previous hash" is different from the current block's hash, then the
    blockchain is incorrect. If the proof-of-work is invalid (not meeting the requisite number of zeroes),
    then the chain is invalid. Else, the chain is valid
    """
    def valid_chain(self , chain):

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")

            if block['previous_hash'] is not self.hash(last_block):
                return False

            if not self.valid_proof(last_block['proof'] , block['proof']):
                return False

            last_block = block
            current_index += 1

        return True


    """
    Consenus Algorithm. This algorithm goes through each node in the network and downloads each
    node's copy of the blockchain. For each node, it checks whether the node's chain is valid and whether
    another node's blockchain is longer. If some node's chains are longer, the node switches its chain to   
    the longest chain. This ensures that each node will eventually pick the longest chain and all nodes
    will eventually agree on the correct chain.
    """
    def resolve_conflicts(self, address):

        neighbours = self.nodes
        new_chain = None

        max_length = len(self.chain)
        for key, node in neighbours.items():
            print(address)
            if key != 'master_node' and node.address != address:
                print(node.address)
                response = requests.get(f'http://{node.address}/chain')

                if response.status_code == 200:
                    length = response.json()['length']
                    if length > max_length:
                        max_length = length
                        new_chain = blockchain.from_json(response.json()['chain'])
        if new_chain:
            self.chain = new_chain
            return True

        return False


    """
    After the proof-of-work is obtained, a node creates a block with the following data: index,
    the timestamp, the list of transactions, the proof, and the hash of the previous block. The timestamp
    is useful for users who want to look at transaction history or when considering the history of the
    blockchain. The proof is necessary for block validation and the hash of the previous block links the
    blocks together into the chain.
    """
    def new_block(self, proof, previous_hash=None,):

        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
            'current_state': self.nodes
        }

        # Reset the current list of transactions
        self.current_transactions = []
        self.chain.append(block)

        return block


    """
    Users can make requests to the network to make transactions.
    """
    def new_transaction(self, sender, recipient, amount, message=None):
        if message is not None:
            message = self.encrypt_message(recipient, message)

        transaction = Transaction(sender, recipient, amount, message)

        self.current_transactions.append(transaction)

    def execute_transactions(self):
        valid = []
        invalid = []
        for transaction in self.current_transactions:
            if self.is_valid_transaction(transaction):
                self.execute_transaction(transaction)
                valid.append(transaction)
            else:
                invalid.append(transaction)
        return valid, invalid

    def execute_transaction(self, transaction):
        self.nodes[transaction.sender].balance = self.nodes[transaction.sender].balance - transaction.amount
        self.nodes[transaction.recipient].balance = self.nodes[transaction.recipient].balance + transaction.amount
        if transaction.message is not None:
            self.nodes[transaction.recipient].messages.append(transaction.message)


    def is_valid_transaction(self, transaction):
        if self.nodes[transaction.sender].balance - transaction.amount < 0:
            return False
        else:
            return True

    """
    This algorithm creates a pseudo-random string from the data in the block and then hashes
    it using SHA-256 (secure hashing algorithm)
    """
    @staticmethod
    def hash(block):
        #I used jsonpickle in an attempt to serialize some of the objects, but worked similarly to dumps()
        jsonpickle.set_encoder_options('json', sort_keys=True)
        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = jsonpickle.encode(block).encode()
        return hashlib.sha256(block_string).hexdigest()

    # Returns the last Block in the chain
    @property
    def last_block(self):
        return self.chain[-1]

    """
    A simple proof of work algorithm. Basically, this algorithm tries every number from 0 to infinity
    to see if it produces the correct hash.
    """
    def proof_of_work(self, last_proof):
        proof = 0
        while self.valid_proof(last_proof, proof) is False:
            proof += 1
        return proof

    """
    Validates the Proof: Does hash(last_proof, proof) contain 4 leading zeroes? According to the
    Bitcoin whitepaper, changing the number of zeroes required exponentially changes the amount
    of mining time.
    """
    @staticmethod
    def valid_proof(last_proof, proof):
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:5] == "00000"

    #generator
    def blocks(self):
        current_index = len(self.chain) - 1
        while True:
            current_block = self.chain[current_index]
            yield(current_block)
            current_index -= 1


    @staticmethod
    def generate_keypair(bits=2048):
        random_generator = Random.new().read
        rsa_key = RSA.generate(bits, random_generator)
        return rsa_key, rsa_key.publickey()


    def get_random_word(self):
        word_index = random.randint(0, len(self.random_words) - 1)
        word = self.random_words[word_index]
        self.random_words.remove(word)
        return word

    def encrypt_message(self, recipient, message):
        unencrypted_message = message.encode()
        recipient = blockchain.nodes[recipient]
        recipient_key = blockchain.public_keys[recipient.public_key_id]
        cipher = PKCS1_OAEP.new(recipient_key)
        cipher_text = base64.b64encode(cipher.encrypt(unencrypted_message))
        return cipher_text.decode()

    def check_transaction_values(self, values):
        if values['sender'] is None or values['recipient'] is None or values['amount'] is None or values['message'] is None:
            return True
        sender = self.nodes[values['sender']]
        recipient = self.nodes[values['recipient']]
        if sender is None or recipient is None:
            return True
        return False

    def to_json(self):
        json_chain = []
        for block in self.chain:
            json_chain.append(self.block_to_json(block))
        return json_chain

    def from_json(self, json_chain):
        new_chain = []
        for block in json_chain:
            new_block = {
                'index': block['index'],
                'timestamp': block['time'],
                'transactions': block['transactions'],
                'proof': block['proof'],
                'previous_hash': block['previous_hash'],
                'current_state': block['current_state']
            }
            new_chain.append(new_block)
        return new_chain

    def block_to_json(self, block):
        json_block = dict()
        json_block['index'] = block['index']
        json_block['timestamp'] = block['timestamp']
        json_block['proof'] = block['proof']
        json_block['transactions'] = self.transactions_to_json(block['transactions'])
        json_block['previous_hash'] = block['previous_hash']
        json_block['current_state'] = self.nodes_to_json()
        return json_block

    def transactions_to_json(self, transactions):
        json_transactions = []
        for tr in transactions:
            json_transactions.append(tr.to_json())
        return json_transactions

    def nodes_to_json(self):
        json_nodes = []
        for key, value in self.nodes.items():
            json_nodes.append(value.to_json())
        return json_nodes

class Node(object):

    def __init__(self, address, public_key_id, balance=0):
        self.address = address
        self.public_key_id = public_key_id
        self.balance = balance
        self.messages = []

    def to_json(self):
        rep = dict()
        rep['address'] = self.address
        rep['public_key_identifier'] = self.public_key_id
        rep['balance'] = str(self.balance)
        rep['messages'] = self.messages
        return rep



class Transaction(object):

    def __init__(self, sender, recipient, amount, message=None):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.message = message
        self.timestamp = str(time())

    def __str__(self):
        rep = self.sender + '\n' + self.recipient + '\n' + self.amount
        return rep

    def to_json(self):
        rep = dict()
        rep['sender'] = self.sender
        rep['recipient'] = self.recipient
        rep['amount'] = self.amount
        if self.message is not None:
            rep['message'] = self.message
        rep['timestamp'] = self.timestamp
        return rep


"""
Flask Instantiation. I used Postman to interact with the blockchain over local servers
"""


app = Flask(__name__)

# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')

# Create the Blockchain
blockchain = Blockchain()


"""
This method has multiple steps. First, it obtains the proof-of-work from the above algorithm. Then,
it receives one coin from the network as a reward. This incentive encourages nodes to mine, which verifies
transactions and allows the system to run. This also allows for the introduction of new coins into
circulation. Next, it creates a new block using the proof-of-work and the hash from the last
block in the chain. Finally, it appends the block to the end of the current chain.
"""

@app.route('/mine', methods=['GET'])
def mine():
    miner = request.args.get('node')
    if miner is None:
        return "Error: Please supply a valid node", 400
    if blockchain.nodes[miner] is None:
        return "Error: Please supply a valid node", 400

    last_block = blockchain.last_block
    last_proof = last_block['proof']
    proof = blockchain.proof_of_work(last_proof)

    #check whether transactions are valid and then update the list of current transactions to the valid ones


    #pay the miner from the source of currency
    blockchain.new_transaction("master_node", miner, 1, "Reward for mining: 1")
    #execute  transactions
    transactions = blockchain.execute_transactions()
    valid_transactions = transactions[0]
    invalid_transactions = transactions[1]
    blockchain.current_transactions = valid_transactions

    # Add the new block to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)
    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'valid_transactions': blockchain.transactions_to_json(valid_transactions),
        'invalid_transactions': blockchain.transactions_to_json(invalid_transactions),
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
        'current_state': blockchain.nodes_to_json()
    }

    return jsonify(response) , 20


"""
This method takes in a server request (formatted in JSON) and adds a new transaction to the list of current
transactions. These transactions will be included in a new block and will eventually be verified and
added to the blockchain. Currently, this implementation does not prevent faulty transactions such
as spending without having enough balance.
"""
@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()
    if blockchain.check_transaction_values(values):
        return "Error: Invalid Nodes", 400

    #create a new transaction
    blockchain.new_transaction(values['sender'], values['recipient'], values['amount'], values['message'])
    response = {'message': f'Transaction will be processed when the next block is mined'}
    return jsonify(response), 201

#either get full blockchain or last n blocks
@app.route('/chain', methods=['GET'])
def display_chain():
    num_blocks = len(blockchain.chain)
    if request.args.get('blocks') is not None:
        try:
            num_blocks = int(request.args.get('blocks'))
        except:
            num_blocks = len(blockchain.chain)

    block_generator = blockchain.blocks()
    blocks_to_return = []
    while num_blocks > 0:
          blocks_to_return.append(blockchain.block_to_json(next(block_generator)))
          num_blocks = num_blocks - 1

    response = {
        'length': len(blockchain.chain),
        'chain': blocks_to_return,
    }
    return jsonify(response), 200


"""
This method registers nodes to the network. 
"""


@app.route('/nodes/register', methods=['POST'])
def register_nodes():

    values = request.get_json()
    address = values.get('address')

    if address is None:
        return "Error: Please supply a valid node" , 400

    key_pair = blockchain.generate_keypair(1024)
    private_key = key_pair[0]
    public_key = key_pair[1]

    public_key_word = blockchain.get_random_word()
    private_key_word = blockchain.get_random_word()

    parsed_url = urlparse(address).netloc
    blockchain.register_node(parsed_url, public_key_word)
    blockchain.register_keys(private_key_word, private_key, public_key_word, public_key)

    response = {
        'message': 'You have been registered on the blockchain. WRITE DOWN YOUR PRIVATE KEY AS IT WILL NOT BE SAVED',
        'public_key': public_key_word,
        'private_key': private_key_word,
    }

    return jsonify(response), 201

@app.route('/nodes/query_balance' , methods=['GET'])
def query_balance():
    if request.args.get('key') is None:
        return "Error: Please supply a valid node", 400
    balance_to_check = blockchain.nodes[request.args.get('key')]
    if balance_to_check is None:
        return "Error: Please supply a valid node", 400

    response = {
        'user': balance_to_check.public_key_id,
        'balance': str(balance_to_check.balance)
    }

    return jsonify(response), 200


@app.route('/nodes/decode_messages' , methods=['POST'])
def decode_messages():

    values = request.get_json()
    if values is None:
        return "Error: Please supply valid keys", 400
    if values['public_key'] is None or values['private_key'] is None:
        return "Error: Please supply valid keys", 400


    current_user = blockchain.nodes[values['public_key']]
    private_key = blockchain.private_keys[values['private_key']]
    if current_user is None or private_key is None:
        return "Error: Please supply valid keys", 400

    decoded_messages = []
    decryptor = PKCS1_OAEP.new(private_key)
    for message in current_user.messages:
        if message is not None:
            cipher_text = base64.b64decode(message.encode())
            decoded_messages.append(decryptor.decrypt(cipher_text).decode())

    response = {
        "messages": decoded_messages
    }

    return jsonify(response), 201


@app.route('/nodes/display_current_state' , methods=['GET'])
def display_state():

    json_keys = []
    for key, value in blockchain.private_keys.items():
        json_keys.append(key)

    json_nodes = []
    for key,value in blockchain.nodes.items():
        json_nodes.append(value.to_json())

    json_transactions = []
    for transaction in blockchain.current_transactions:
        json_transactions.append(transaction.to_json())

    response = {
        'nodes': json_nodes,
        'current_transactions': json_transactions
    }

    return jsonify(response), 200



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)


'''
REDUNDANT METHODS ---- thought I'd leave them just for show


"""
@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    if request.args.get('node') is None:
        return "Error: Please supply a valid node", 400
    address = blockchain.nodes[request.args.get('node')].address
    if address is None:
        return "Error: Please supply a valid node", 400

    replaced = blockchain.resolve_conflicts(address)
    print("hello")
    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.to_json()
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.to_json()
        }
    return jsonify(response), 200
    
    
        @staticmethod
    def parse_public_key(public_key):
        public_key_str = str(public_key.exportKey())
        return public_key_str[28:-25].replace('\\n', '')

    @staticmethod
    def parse_private_key(private_key):
        private_key_str = str(private_key.exportKey())
        return private_key_str[33:-30].replace('\\n', '')
"""

'''