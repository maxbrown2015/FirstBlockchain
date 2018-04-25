"""
Learn Blockchain by Building One.
https://hackernoon.com/learn-blockchains-by-building-one-117428612f46
"""
import hashlib
import json
from time import time
from uuid import uuid4
from urllib.parse import urlparse
from flask import Flask, jsonify, request
import requests

"""
The blockchain object contains a list of blocks (the chain), a list of transactions to be added to
the next block, and a set of all nodes in the network. Instantiating a new blockchain creates a
genesis block, from which all blocks are cryptographically linked to.
"""


class Blockchain(object):

    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.nodes = set()

        #initial block
        self.new_block(proof=100, previous_hash=1)


    """
    Adds a new node to the list of nodes. A node is a participant on the blockchain
    network. Each node can view the state of the blockhain, verify transactions through mining, and add
    new blocks to the chain
    """
    def register_node(self, address):

        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)


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
    def resolve_conflicts(self):

        neighbours = self.nodes
        new_chain = None

        max_length = len(self.chain)

        for node in neighbours:
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

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
            'previous_hash': previous_hash or self.hash(self.chain[-1])
        }

        # Reset the current list of transactions
        self.current_transactions = []
        self.chain.append(block)

        return block


    """
    Users can make requests to the network to make transactions.
    """
    def new_transaction(self, sender, recipient, amount):


        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount
        })

        return self.last_block['index'] + 1


    """
    This algorithm creates a pseudo-random string from the data in the block and then hashes
    it using SHA-256 (secure hashing algorithm)
    """
    @staticmethod
    def hash(block):

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
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
        return guess_hash[:4] == "0000"


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

    last_block = blockchain.last_block
    last_proof = last_block['proof']
    proof = blockchain.proof_of_work(last_proof)

    # Pay the miner by sending them a transaction

    blockchain.new_transaction(sender="0", recipient=node_identifier, amount=1)

    # Add the new block to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)

    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],

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

    #create a new transaction
    index = blockchain.new_transaction(values['sender'], values['recipient'], values['amount'])

    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


"""
This method registers nodes to the network. 
"""
@app.route('/nodes/register' , methods=['POST'])
def register_nodes():

    values = request.get_json()

    nodes = values.get('nodes')

    if nodes is None:
        return "Error: Please supply a valid list of nodes" , 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes)
    }

    return jsonify(response) , 201


"""
This method resolves any conflicts by making all the nodes in the network have the same
chain.
"""
@app.route('/nodes/resolve', methods=['GET'])
def consensus():

    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
