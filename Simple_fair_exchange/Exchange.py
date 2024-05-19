from web3 import Web3

w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545'))
from solcx import compile_standard, install_solc

install_solc("0.8.0")
import json  
import random
import secrets
import sympy  # Needed for mod_inverse
import DLEQ
import util
import AES 
import sys
import time
import subprocess
from py_ecc.bn128 import G1, G2
from py_ecc.bn128 import add, multiply, neg, pairing, is_on_curve
from py_ecc.bn128 import curve_order as CURVE_ORDER
from py_ecc.bn128 import field_modulus as FIELD_MODULUS
from typing import Tuple, Dict, List, Iterable, Union
from py_ecc.fields import bn128_FQ as FQ


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


"""
# 128位的AES密钥
key = b'0123456789abcdef0123456789abcdef'
print(type(key))
message = b'Hello, AESDJAKJDKLAJDALKJDALKJDAOID789765456AOIJA,DAKJDLKAJDAKNDM,ANDAKHDJKASHDJKADAM encryption!1564987564654564897987894545645623'

encrypted_data = AES.Encrypt(key, message)
print("Encrypted data:", encrypted_data)
decrypted_data = AES.Decrypt(key,encrypted_data)
print("Decrypted data:", decrypted_data.decode('utf-8'))

print(type(decrypted_data.decode('utf-8')))
"""
H1 = multiply(G1, 9868996996480530350723936346388037348513707152826932716320380442065450531909)  # Generator H1

# def seller_commit_data(seller_address, n: int, t: int, secret:bytes):
def seller_commit_data(seller_address,  secret:bytes):
    #此值作为seller保密的秘密值
    s = DLEQ.random_scalar()
    #print("anwser:",multiply(G1,s))
    binary_str=bin(int(multiply(G1,s)[0]))[2:130]
    # 将二进制字符串转换为整数
    decimal_num = int(binary_str, 2)
    # 将整数转换为bytes类型
    # 128位的AES密钥
    key = decimal_num.to_bytes((len(binary_str) + 7) // 8, 'big')

    
    encrypted_data = AES.Encrypt(key, secret)

    Contract.functions.SellerUpload(encrypted_data,seller_address).transact({'from': seller_address})
    #print(type(decrypted_data.decode('utf-8')))
    zkSNARKs_Hash=str(key)+str(encrypted_data)+str(secret)
    #print(zkSNARKs_Hash)
    #print(type(zkSNARKs_Hash))
    with open('zkSNARKs_Hash.txt', 'w') as file:
    # 要写入的字符串
    # 将字符串写入文件
        file.write(zkSNARKs_Hash)

    return key,s


def NormalExchange(key):
    encrypted_data=Contract.functions.DownloadCiphertext().call()
    decrypted_data = AES.Decrypt(key,encrypted_data)
    print("Decrypted data:", decrypted_data.decode('utf-8'))
    

def zkSNARKs_groth_verify():
    cmd = ["/usr/bin/python3", "./verify.py"]  # 调用Python verify.py脚本
    stdout = subprocess.check_output(cmd)  # 执行命令并获取输出
    output = stdout.strip().decode('utf-8')  # 去除首尾空白并转换为字符串
    if output == "True":
        return True
    else:
        return False


def SmartContract_Verify():
    # 编译Go文件
    cmd = ['go', 'build', 'main.go']
    subprocess.run(cmd)
    # 执行可执行文件
    cmd = ['./main']
    subprocess.run(cmd)
    
    #验证证明
    result = zkSNARKs_groth_verify()

    return result

if __name__ == '__main__':
    print("...........................................Initialization...................................................")
    #生成公私钥对
    sk_buyer = DLEQ.random_scalar()
    pk_buyer = multiply(G1,sk_buyer)

    print("............................................Commit_data.....................................................")
    
    #print( Contract.functions.show(w3.eth.accounts[0]).call())

    secret = b'Hello, AESDJAKJDKLAJDALKJDALKJDAOID444444889sfsdfsdf789765456AOIJA,DAKJDLKAJDAKNDM,ANDAKHDJKASHDJKADAM encryption!1564987564654564897987894545645623'

    key_aes = seller_commit_data(w3.eth.accounts[2],secret)
    #print( Contract.functions.show(w3.eth.accounts[0]).call())
    #zk-SNARKs onchanin verify
    result = SmartContract_Verify()
    print("zkSNARKs verify result:", result)

    print("............................................Lock_asset......................................................")
    
    if(result==True):
        #send data.secret and eth to smart contract
        Contract.functions.BuyerUpload(w3.eth.accounts[3],30000000000000000).transact({'from': w3.eth.accounts[3],'value': 30000000000000000})
        print("Buyer had lock asset")
        print("............................................Reveal_key......................................................")
        #print(key_aes[1])
    
        #对密钥进行加密
        c_e = multiply(pk_buyer,key_aes[1])
        pub=multiply(H1,key_aes[1])
        #print(int(key_aes))
    
        #生成证明
        proof=DLEQ.DLEQ(H1,pub,pk_buyer,c_e,key_aes[1])

        #合约验证证明
        res=Contract.functions.DLEQ_verify(util.Point2IntArr(H1),util.Point2IntArr(pub),util.Point2IntArr(pk_buyer),util.Point2IntArr(c_e),util.Point2IntArr(proof)).call()
        print("DLEQ NIZK verify result: ",res)
    

        if(res==True):
            print("..........................................Transfer_asset....................................................")
            #smart contract sends eth to seller
            Contract.functions.ETHtransfer(w3.eth.accounts[2]).transact({'from': w3.eth.accounts[2]})
            print("Buyer had transfer asset to Seller")

            re=DLEQ.Decrypt(c_e,sk_buyer) 

            #print("anwser:",multiply(G1,s))
            binary_str=bin(int(re[0]))[2:130]
            # 将二进制字符串转换为整数
            decimal_num = int(binary_str, 2)
            # 将整数转换为bytes类型
            #  128位的AES密钥
            key2 = decimal_num.to_bytes((len(binary_str) + 7) // 8, 'big')

            encrypted_data=Contract.functions.DownloadCiphertext().call()
            decrypted_data = AES.Decrypt(key2,encrypted_data)  
            print("Decrypted data:", decrypted_data.decode('utf-8'))
            #print(re)
            #print(multiply(G1,key_aes[1]))
        else:#The ciphertext concering key is invalid
            Contract.functions.refund(w3.eth.accounts[3]).transact({'from': w3.eth.accounts[3]})
            print("The seller is malicious !")
            print("The eth has been returned to the buyer.")
            print("Exchange terminates with fail !")
    else:# The ciphertext concering data is invalid
        print("The seller is malicious !")
        print("Exchange terminates with fail !")
    
    
    
    
    




    
    
    





