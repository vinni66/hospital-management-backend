import json
import hashlib
from datetime import datetime

class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp or datetime.utcnow().isoformat()
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = f"{self.index}{self.timestamp}{json.dumps(self.data, sort_keys=True)}{self.previous_hash}"
        return hashlib.sha256(block_string.encode()).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = []
        self.load_chain()

    def create_genesis_block(self):
        genesis_block = Block(0, datetime.utcnow().isoformat(), {"info": "Genesis Block"}, "0")
        self.chain.append(genesis_block)
        self.save_chain()

    def get_last_block(self):
        return self.chain[-1]

    def add_block(self, data):
        last_block = self.get_last_block()
        new_block = Block(len(self.chain), datetime.utcnow().isoformat(), data, last_block.hash)
        self.chain.append(new_block)
        self.save_chain()
        return new_block

    def save_chain(self):
        chain_data = [block.__dict__ for block in self.chain]
        with open("data/blockchain_data.json", "w") as f:
            json.dump(chain_data, f, indent=4)

    def load_chain(self):
        try:
            with open("data/blockchain_data.json", "r") as f:
                chain_data = json.load(f)
                # --- MODIFICATION START ---
                # Validate the loaded chain. If any hash is incorrect, discard and create a new one.
                for block_data in chain_data:
                    block = Block(block_data['index'], block_data['timestamp'], block_data['data'], block_data['previous_hash'])
                    if block.hash != block_data['hash']:
                        print("Blockchain data corrupted. Regenerating...")
                        self.chain = [] # Clear the invalid chain
                        raise FileNotFoundError # Treat as if file doesn't exist to trigger genesis
                    self.chain.append(block)
                # --- MODIFICATION END ---
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            self.create_genesis_block()