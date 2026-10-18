import hashlib
import datetime
import json
import os
import uuid
import requests
import threading

# Import Ethereum anchor module
try:
    import ethereum_anchor
except ImportError:
    ethereum_anchor = None

BLOCKCHAIN_FILE = 'blockchain_data.json'


def _peer_headers():
    """Shared secret that peers must present to /receive_block."""
    token = os.getenv('PEER_TOKEN', '')
    return {'X-Peer-Token': token} if token else {}

# Debug logging configuration
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Block:
    def __init__(self, index, timestamp, record_hash, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.record_hash = record_hash
        self.previous_hash = previous_hash
        self.current_hash = self.calculate_hash()
        self.ethereum_tx_hash = None

    def calculate_hash(self):
        block_string = (
            str(self.index) +
            str(self.timestamp.isoformat()) +
            str(self.record_hash) +
            str(self.previous_hash)
        )
        return hashlib.sha256(block_string.encode()).hexdigest()

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp.isoformat(),
            "record_hash": self.record_hash,
            "previous_hash": self.previous_hash,
            "current_hash": self.current_hash,
            "ethereum_tx_hash": self.ethereum_tx_hash
        }

    @staticmethod
    def from_dict(data):
        timestamp = datetime.datetime.fromisoformat(data["timestamp"])
        block = Block(
            data["index"],
            timestamp,
            data["record_hash"],
            data["previous_hash"]
        )
        block.current_hash = data["current_hash"]
        block.ethereum_tx_hash = data.get("ethereum_tx_hash")
        return block


class Blockchain:

    def __init__(self):
        self.chain = []
        self.peer_nodes = set()
        self.node_id = str(uuid.uuid4())
        self.load_or_create()

    def load_or_create(self):
        if os.path.exists(BLOCKCHAIN_FILE):
            self.load()
        else:
            self.create_genesis_block()
            self.save()

    def create_genesis_block(self):
        genesis = Block(
            0,
            datetime.datetime.now(),
            "genesis_record_hash",
            "0"
        )
        self.chain.append(genesis)
        logger.info("Genesis block created")

    def add_block(self, record_hash, broadcast=True):
        previous_block = self.chain[-1]

        new_block = Block(
            len(self.chain),
            datetime.datetime.now(),
            record_hash,
            previous_block.current_hash
        )

        self.chain.append(new_block)
        self.save()
        
        logger.info(f"Block {new_block.index} added locally with hash {new_block.current_hash[:16]}...")

        # Ethereum anchoring - store block hash on Ethereum
        if ethereum_anchor is not None:
            try:
                tx_hash = ethereum_anchor.store_block_hash(new_block.current_hash)
                if tx_hash:
                    new_block.ethereum_tx_hash = tx_hash
                    self.save()
                    logger.info(f"Block hash anchored to Ethereum. Tx: {tx_hash[:16]}...")
                else:
                    logger.warning("Failed to anchor block hash to Ethereum")
            except Exception as e:
                logger.error(f"Ethereum anchoring error: {str(e)}")

        if broadcast:
            self.broadcast_block(new_block)

        return new_block

    def add_received_block(self, block_data):

        # Validate required fields
        required = ['index', 'timestamp', 'record_hash', 'previous_hash', 'current_hash']
        for field in required:
            if field not in block_data:
                logger.warning(f"Block validation failed: missing field '{field}'")
                return False

        # Check for duplicate block (block already exists in chain)
        for existing_block in self.chain:
            if existing_block.current_hash == block_data["current_hash"]:
                logger.info(f"Block {block_data['index']} already exists in chain - ignoring duplicate")
                return True  # Return True to indicate block is handled (already exists)

        # Convert timestamp properly
        try:
            timestamp = datetime.datetime.fromisoformat(block_data["timestamp"])
        except ValueError as e:
            logger.warning(f"Block validation failed: invalid timestamp format - {e}")
            return False

        # Create block and validate hash
        new_block = Block(
            block_data["index"],
            timestamp,
            block_data["record_hash"],
            block_data["previous_hash"]
        )

        # FIXED: Validate hash by recalculating
        expected_hash = new_block.calculate_hash()
        if expected_hash != block_data["current_hash"]:
            logger.warning(f"Block {block_data['index']} validation failed: hash mismatch (expected {expected_hash[:16]}..., got {block_data['current_hash'][:16]}...)")
            return False

        # FIXED: Validate index against last block's index + 1
        last_block = self.chain[-1]
        
        if new_block.index != last_block.index + 1:
            logger.warning(f"Block {block_data['index']} validation failed: incorrect index (expected {last_block.index + 1}, got {new_block.index})")
            # Chain gap detected - trigger conflict resolution instead of silently failing
            logger.info("Chain gap detected - triggering conflict resolution")
            return False

        # Validate previous hash matches last block's current hash
        if new_block.previous_hash != last_block.current_hash:
            logger.warning(f"Block {block_data['index']} validation failed: previous_hash mismatch (expected {last_block.current_hash[:16]}..., got {new_block.previous_hash[:16]}...)")
            return False

        # All validations passed - add block
        new_block.current_hash = block_data["current_hash"]  # Keep the verified hash from peer
        new_block.ethereum_tx_hash = block_data.get("ethereum_tx_hash")
        self.chain.append(new_block)
        self.save()
        
        logger.info(f"Block {new_block.index} successfully added to chain from peer. Hash: {new_block.current_hash[:16]}...")
        return True

    def broadcast_block(self, block):
        logger.info(f"Starting broadcast for block {block.index} to {len(self.peer_nodes)} peers")
        
        if not self.peer_nodes:
            logger.warning("No peer nodes configured - broadcast skipped")
            return

        def send(peer):
            try:
                logger.debug(f"Broadcasting block {block.index} to {peer}")
                response = requests.post(
                    f"{peer}/receive_block",
                    json=block.to_dict(),
                    headers=_peer_headers(),
                    timeout=5
                )
                if response.status_code == 200:
                    logger.info(f"✓ Block {block.index} successfully broadcast to {peer}")
                else:
                    logger.warning(f"✗ Block {block.index} broadcast to {peer} returned status {response.status_code}")
            except requests.exceptions.Timeout:
                logger.error(f"✗ Block {block.index} broadcast to {peer} timed out")
            except requests.exceptions.ConnectionError:
                logger.error(f"✗ Block {block.index} broadcast to {peer} - connection failed")
            except Exception as e:
                logger.error(f"✗ Block {block.index} broadcast to {peer} failed: {str(e)}")

        threads = []
        for peer in self.peer_nodes:
            t = threading.Thread(target=send, args=(peer,))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()
        
        logger.info(f"Broadcast complete for block {block.index}")

    def replace_chain(self, new_chain_data):
        logger.info(f"Attempting to replace chain. Current length: {len(self.chain)}, New length: {len(new_chain_data)}")

        if len(new_chain_data) <= len(self.chain):
            logger.info("Chain replacement rejected: new chain is not longer")
            return False

        new_chain = []
        for data in new_chain_data:
            block = Block.from_dict(data)
            new_chain.append(block)

        # Validate full chain
        for i in range(1, len(new_chain)):
            if new_chain[i].previous_hash != new_chain[i - 1].current_hash:
                logger.warning(f"Chain replacement failed: invalid link at block {i}")
                return False
            if new_chain[i].current_hash != new_chain[i].calculate_hash():
                logger.warning(f"Chain replacement failed: invalid hash at block {i}")
                return False

        old_length = len(self.chain)
        self.chain = new_chain
        self.save()
        
        logger.info(f"Chain replaced successfully. Old length: {old_length}, New length: {len(self.chain)}")
        return True

    def resolve_conflicts(self):
        logger.info("Starting conflict resolution - querying peer nodes for longest chain")
        
        longest_chain = None
        max_length = len(self.chain)
        source_peer = None

        for peer in self.peer_nodes:
            try:
                logger.debug(f"Querying chain from peer: {peer}")
                response = requests.get(f"{peer}/get_chain", timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    chain_length = data.get("length", 0)
                    logger.debug(f"Peer {peer} has chain length: {chain_length}")
                    
                    if chain_length > max_length:
                        longest_chain = data.get("chain")
                        max_length = chain_length
                        source_peer = peer
            except requests.exceptions.Timeout:
                logger.warning(f"Timeout while querying peer {peer}")
            except requests.exceptions.ConnectionError:
                logger.warning(f"Connection failed while querying peer {peer}")
            except Exception as e:
                logger.error(f"Error querying peer {peer}: {str(e)}")

        if longest_chain:
            logger.info(f"Longest chain found from peer {source_peer} with length {max_length}")
            return self.replace_chain(longest_chain)
        
        logger.info("Conflict resolution complete - no longer chain found")
        return False

    def is_chain_valid(self):
        """
        Validate the entire blockchain integrity.
        Returns (is_valid, corrupted_index) where:
        - is_valid: True if chain is valid, False otherwise
        - corrupted_index: Index of first invalid block, or None if valid
        
        Genesis block (index 0) is always treated as valid.
        Validation starts from index 1.
        """
        if len(self.chain) == 0:
            return True, None
        
        # Genesis block (index 0) is always treated as valid
        # Validation loop starts from index 1
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # Verify hash calculation (recalculate current_hash properly)
            expected_hash = current_block.calculate_hash()
            if current_block.current_hash != expected_hash:
                logger.warning(f"Block {i} validation failed: hash mismatch")
                return False, i
            
            # Verify previous hash linkage (compare with previous block's current_hash)
            if current_block.previous_hash != previous_block.current_hash:
                logger.warning(f"Block {i} validation failed: previous hash mismatch")
                return False, i
            
            # Verify index continuity
            if current_block.index != i:
                logger.warning(f"Block {i} validation failed: incorrect index")
                return False, i
        
        logger.info(f"Chain validation passed - {len(self.chain)} blocks verified")
        return True, None

    def save(self):
        with open(BLOCKCHAIN_FILE, "w") as f:
            json.dump([b.to_dict() for b in self.chain], f, indent=2)
        logger.debug(f"Chain saved to {BLOCKCHAIN_FILE}")

    def load(self):
        with open(BLOCKCHAIN_FILE, "r") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = []
            self.chain = [Block.from_dict(b) for b in data]
        if not self.chain:  # empty/corrupt file -> start with a genesis block
            self.create_genesis_block()
            self.save()
        logger.info(f"Chain loaded from {BLOCKCHAIN_FILE}: {len(self.chain)} blocks")

    def get_chain_data(self):
        return [b.to_dict() for b in self.chain]

    def get_chain_length(self):
        return len(self.chain)

    def add_peer(self, url):
        self.peer_nodes.add(url)
        logger.info(f"Peer node added: {url}")

    def get_latest_hash(self):
        return self.chain[-1].current_hash

    def sync_with_peers_on_startup(self):
        """
        Automatically synchronize chain with peers on node startup.
        Queries all registered peers and replaces local chain if a longer valid chain is found.
        This runs asynchronously to avoid blocking Flask startup.
        """
        import time
        # Give the server a moment to start before syncing
        time.sleep(2)
        
        logger.info("="*60)
        logger.info("Starting automatic chain synchronization on startup")
        logger.info(f"Current chain length: {len(self.chain)}")
        logger.info(f"Registered peers: {len(self.peer_nodes)}")
        
        if not self.peer_nodes:
            logger.info("No peers registered - skipping startup sync")
            logger.info("="*60)
            return
        
        # Track sync status
        sync_attempted = False
        longest_chain = None
        max_length = len(self.chain)
        source_peer = None
        
        # Query each peer for their chain
        for peer in self.peer_nodes:
            try:
                logger.info(f"Querying peer {peer} for chain...")
                response = requests.get(f"{peer}/get_chain", timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    chain_length = data.get("length", 0)
                    chain_data = data.get("chain", [])
                    
                    logger.info(f"Peer {peer} has chain length: {chain_length}")
                    
                    # Validate the chain before considering it
                    if chain_length > max_length and self._validate_chain_data(chain_data):
                        logger.info(f"Peer {peer} has longer valid chain! (length: {chain_length})")
                        longest_chain = chain_data
                        max_length = chain_length
                        source_peer = peer
                        sync_attempted = True
                    else:
                        logger.info(f"Peer {peer} chain is not longer or invalid - skipping")
                else:
                    logger.warning(f"Failed to get chain from {peer}: HTTP {response.status_code}")
                    
            except requests.exceptions.Timeout:
                logger.warning(f"Timeout while querying peer {peer}")
            except requests.exceptions.ConnectionError:
                logger.warning(f"Connection failed to peer {peer}")
            except Exception as e:
                logger.error(f"Error querying peer {peer}: {str(e)}")
        
        # Replace chain if a longer valid one was found
        if longest_chain:
            logger.info(f"Replacing local chain with longer chain from {source_peer}")
            success = self.replace_chain(longest_chain)
            if success:
                logger.info(f"✅ Startup sync complete! Chain updated from {source_peer}")
                logger.info(f"   New chain length: {self.get_chain_length()}")
            else:
                logger.error(f"❌ Failed to replace chain from {source_peer}")
        else:
            if sync_attempted:
                logger.info("No longer valid chain found among peers")
            else:
                logger.info("No sync attempted - all peers unreachable or shorter chains")
        
        logger.info("="*60)
    
    def _validate_chain_data(self, chain_data):
        """
        Validate chain data structure before accepting it for sync.
        Returns True if chain is valid, False otherwise.
        """
        if not chain_data or len(chain_data) == 0:
            logger.warning("Chain validation failed: empty chain data")
            return False
        
        # Check genesis block
        if chain_data[0].get("index") != 0 or chain_data[0].get("previous_hash") != "0":
            logger.warning("Chain validation failed: invalid genesis block")
            return False
        
        # Validate each block's hash and links
        try:
            for i in range(1, len(chain_data)):
                current = chain_data[i]
                previous = chain_data[i - 1]
                
                # Verify previous hash link
                if current.get("previous_hash") != previous.get("current_hash"):
                    logger.warning(f"Chain validation failed: invalid link at block {i}")
                    return False
                
                # Verify hash calculation
                temp_block = Block(
                    current.get("index"),
                    datetime.datetime.fromisoformat(current.get("timestamp")),
                    current.get("record_hash"),
                    current.get("previous_hash")
                )
                expected_hash = temp_block.calculate_hash()
                if expected_hash != current.get("current_hash"):
                    logger.warning(f"Chain validation failed: invalid hash at block {i}")
                    return False
            
            return True
        except Exception as e:
            logger.warning(f"Chain validation failed: {str(e)}")
            return False


healthchain_blockchain = Blockchain()
