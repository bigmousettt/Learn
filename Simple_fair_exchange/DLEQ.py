from web3 import Web3

w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545'))
from solcx import compile_standard, install_solc

install_solc("0.8.0")
import json  
import random
import util
import secrets
import sympy  # Needed for mod_inverse
from py_ecc.bn128 import G1, G2
from py_ecc.bn128 import add, multiply, neg, pairing, is_on_curve
from py_ecc.bn128 import curve_order as CURVE_ORDER
from py_ecc.bn128 import field_modulus as FIELD_MODULUS
from typing import Tuple, Dict, List, Iterable, Union

with open("Contracts/Exchange.sol", "r") as file:
    contact_list_file = file.read()

compiled_sol = compile_standard(
    {
        "language": "Solidity",
        "sources": {"Exchange.sol": {"content": contact_list_file}},
        "settings": {
            "outputSelection": {
                "*": {
                    "*": ["abi", "metadata", "evm.bytecode", "evm.bytecode.sourceMap"]
                    # output needed to interact with and deploy contract
                }
            }
        },
    },
    solc_version="0.8.0",
)

# print(compiled_sol)
with open("compiled_code.json", "w") as file:
    json.dump(compiled_sol, file)
# get bytecode
bytecode = compiled_sol["contracts"]["Exchange.sol"]["Exchange"]["evm"]["bytecode"]["object"]
# get abi
abi = json.loads(compiled_sol["contracts"]["Exchange.sol"]["Exchange"]["metadata"])["output"]["abi"]
# Create the contract in Python
contract = w3.eth.contract(abi=abi, bytecode=bytecode)

chain_id = 5777
accounts0 = w3.eth.accounts[0]
transaction_hash = contract.constructor().transact({'from': accounts0})
# Wait for the contract to be deployed
transaction_receipt = w3.eth.wait_for_transaction_receipt(transaction_hash)
# Get the deployed contract address
contract_address = transaction_receipt['contractAddress']
# print(" contract deployed, address: ", contract_address)
Contract = w3.eth.contract(address=contract_address, abi=abi)

keccak_256 = Web3.solidity_keccak

H1 = multiply(G1, 9868996996480530350723936346388037348513707152826932716320380442065450531909)  # Generator H1


def random_scalar() -> int:  # Generate random numbers
    """ Returns a random exponent for the BN128 curve, i.e. a random element from Zq.
    """
    return secrets.randbelow(CURVE_ORDER)


# Generate DLEQ commitment alpha as the value of the zero-knowledge proof that requires commitment
def DLEQ(x1, y1, x2, y2, alpha: int) -> Tuple[int, int]:
    """ DLEQ... discrete logarithm equality
        Proofs that the caller knows alpha such that y1 = x1**alpha and y2 = x2**alpha
        without revealing alpha.
    """
    w = random_scalar()
    a1 = multiply(x1, w)
    a2 = multiply(x2, w)
    c = keccak_256(
        abi_types=["uint256"] * 12,
        values=[
            int(v)
            for v in (a1)
                     + (a2)
                     + (x1)
                     + (y1)
                     + (x2)
                     + (y2)
        ],
    )
    c = int.from_bytes(c, "big")
    r = (w - alpha * c) % CURVE_ORDER
    return c, r


# DLEQ_Verify off-chain validator function for testing
def DLEQ_verify(x1, y1, x2, y2, challenge: int, response: int) -> bool:
    a1 = add(multiply(x1, response), multiply(y1, challenge))
    a2 = add(multiply(x2, response), multiply(y2, challenge))
    c = keccak_256(  # pylint: disable=E1120
        abi_types=["uint256"] * 12,  # 12,
        values=[
            int(v)
            for v in (a1)
                     + (a2)
                     + (x1)
                     + (y1)
                     + (x2)
                     + (y2)
        ],
    )
    c = int.from_bytes(c, "big")
    return c == challenge



def Decrypt(c_ji, sk_i):  # Decrypt C_ji
    sh1_ji = multiply(c_ji, sympy.mod_inverse((sk_i) % CURVE_ORDER, CURVE_ORDER))
    return sh1_ji


