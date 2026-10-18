"""
Ethereum Anchor Module
Phase 20: Ethereum integration for blockchain healthcare system
"""

from web3 import Web3
import logging

# -------------------------------
# CONFIGURATION
# -------------------------------

import os
GANACHE_URL = os.getenv("GANACHE_URL", "http://127.0.0.1:7545")

# 🔥 Replace with your deployed contract address
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS", "0xBCe6062C8785909e0555c59fdF059D45a364625B")

# ABI from Remix
CONTRACT_ABI = [
    {
        "inputs": [
            {
                "internalType": "string",
                "name": "_hash",
                "type": "string"
            }
        ],
        "name": "storeHash",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "getHash",
        "outputs": [
            {
                "internalType": "string",
                "name": "",
                "type": "string"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    }
]

# -------------------------------
# LOGGING
# -------------------------------

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# -------------------------------
# GLOBAL VARIABLES
# -------------------------------

web3 = None
contract = None


# -------------------------------
# INITIALIZE ETHEREUM CONNECTION
# -------------------------------

def initialize_ethereum():
    global web3, contract

    try:
        web3 = Web3(Web3.HTTPProvider(GANACHE_URL))

        if not web3.is_connected():
            logger.error("❌ Failed to connect to Ganache")
            return False

        contract = web3.eth.contract(
            address=Web3.to_checksum_address(CONTRACT_ADDRESS),
            abi=CONTRACT_ABI
        )

        logger.info(f"✅ Connected to Ethereum. Chain ID: {web3.eth.chain_id}")
        return True

    except Exception as e:
        logger.error(f"Error initializing Ethereum: {str(e)}")
        return False


# -------------------------------
# GET ETHEREUM NETWORK STATUS
# -------------------------------
def get_network_info():
    global web3

    if web3 is None:
        if not initialize_ethereum():
            return {
                "connected": False,
                "network": None,
                "latest_block": None
            }

    try:
        return {
            "connected": True,
            "network": web3.eth.chain_id,
            "latest_block": web3.eth.block_number
        }
    except Exception as e:
        return {
            "connected": False,
            "error": str(e),
            "network": None,
            "latest_block": None
        }
# -------------------------------
# STORE BLOCK HASH ON ETHEREUM
# -------------------------------

def store_block_hash(block_hash):
    global web3, contract

    if web3 is None or contract is None:
        if not initialize_ethereum():
            return None

    try:
        sender = web3.eth.accounts[0]

        tx_hash = contract.functions.storeHash(block_hash).transact({
            'from': sender
        })

        receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

        logger.info(f"✅ Block hash stored on Ethereum")
        logger.info(f"Transaction Hash: {receipt.transactionHash.hex()}")

        return receipt.transactionHash.hex()

    except Exception as e:
        logger.error(f"Error storing block hash: {str(e)}")
        return None


# -------------------------------
# GET LAST HASH FROM ETHEREUM
# -------------------------------

def get_latest_hash():
    global web3, contract

    if web3 is None or contract is None:
        if not initialize_ethereum():
            return None

    try:
        return contract.functions.getHash().call()
    except Exception as e:
        logger.error(f"Error reading from contract: {str(e)}")
        return None


# -------------------------------
# VERIFY ETHEREUM TRANSACTION
# -------------------------------

def verify_transaction(tx_hash):
    global web3

    if web3 is None:
        if not initialize_ethereum():
            return {"verified": False, "error": "Ethereum not connected"}

    try:
        receipt = web3.eth.get_transaction_receipt(tx_hash)
        if receipt and receipt.status == 1:
            return {
                "verified": True,
                "blockNumber": receipt.blockNumber,
                "gasUsed": receipt.gasUsed
            }
        else:
            return {"verified": False}
    except Exception as e:
        return {"verified": False, "error": str(e)}


# Initialize on import
initialize_ethereum()
