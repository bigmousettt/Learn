import os
#使用方法替换gnark-tests-main/solidity/contract文件夹下运行
#先运行main.go之后再运行verify.py
import web3
from solcx import set_solc_version, install_solc
from solcx import compile_source
install_solc('0.8.19')
set_solc_version('v0.8.19')
import json,base64
  
        
#编译合约
def compile_source_file(file_path):
   with open(file_path, 'r') as f:
      source = f.read()
   return compile_source(source)
#部署合约
def deploy_contract(w3, contract_interface):
    contract = w3.eth.contract(
        abi=contract_interface['abi'],
        bytecode=contract_interface['bin'])
    accounts0 = w3.eth.accounts[0]
    transaction_hash = contract.constructor().transact({'from': accounts0})
    # 等待合约部署完成
    transaction_receipt = w3.eth.wait_for_transaction_receipt(transaction_hash)
    # 获取部署后的合约地址
    contract_address = transaction_receipt['contractAddress']
    return contract_address
#编译部署合约（返回调用对象）
def compile_deploy_file(w3, file_path):
    compiled_sol = compile_source_file(file_path)
    contract_id, contract_interface= compiled_sol.popitem()
    address1 = deploy_contract(w3, contract_interface)
    abi1 = contract_interface['abi']
    Contract = w3.eth.contract(address=address1, abi=abi1)    
    return Contract

#与服务器连接
w3=web3.Web3(web3.HTTPProvider('http://127.0.0.1:7545', request_kwargs={'timeout': 60 * 10}))

#编译部署contract_g16.sol
groth_Contract=compile_deploy_file(w3,"contract_g16.sol")
#编译部署contract_plonk.sol
#plonk_Contract=compile_deploy_file(w3,"contract_plonk.sol")

# 读取JSON文件
with open('gorth16_output.json', 'r') as file:
    data = json.load(file)
#调用groth合约
result = groth_Contract.functions.verifyProof(data["G_proof"],data["G_input"]).call({'from':w3.eth.accounts[0]})
#评估消耗的gas值
estimate_gas = groth_Contract.functions.verifyProof(data["G_proof"],data["G_input"]).estimate_gas({'from':w3.eth.accounts[0]})
#print(f"groth_verify的结果:{not bool(result)}, groth_verify预计的gas值消耗: {estimate_gas}")
print(not bool(result))

"""
# 读取JSON文件
with open('plonk_output.json', 'r') as file:
    data = json.load(file)
encoded_data = data['P_proof']
decoded_bytes = base64.b64decode(encoded_data)
#调用plonk合约
result1 = plonk_Contract.functions.Verify(decoded_bytes, data["P_input"]).call({'from':w3.eth.accounts[0]})
#评估消耗的gas值
estimate_gas1 = plonk_Contract.functions.Verify(decoded_bytes, data["P_input"]).estimate_gas({'from':w3.eth.accounts[0]})
#print(f"plonk_verify的结果:{result1}, plonk_verify预计的gas值消耗: {estimate_gas1}")
print(result1)
"""

