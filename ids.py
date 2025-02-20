from scapy.all import sniff, IP
from collections import defaultdict
from web3 import Web3
import json
import time

w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545"))
contract_address = "0x0363523595035Ef7C8739afA76C51fb799c22419" 
with open('build/contracts/IDSStorage.json') as f:
    contract_data = json.load(f)
    abi = contract_data['abi']

contract = w3.eth.contract(address=contract_address, abi=abi)
account = w3.eth.accounts[0]

ip_requests = defaultdict(list)

def log_to_blockchain(ip):
    try:
        tx_hash = contract.functions.addLog(ip).transact({'from': account})
        w3.eth.wait_for_transaction_receipt(tx_hash)
        print(f" Logged {ip} to blockchain")
    except Exception as e:
        print(f"Blockchain logging failed: {e}")

def detect_attack(packet):
    if packet.haslayer(IP): 
        ip_src = packet[IP].src
        ip_requests[ip_src].append(time.time())

        ip_requests[ip_src] = [t for t in ip_requests[ip_src] if time.time() - t < 10]

        if len(ip_requests[ip_src]) > 5:
            print(f"⚠️ Potential attack detected from {ip_src}")
            log_to_blockchain(ip_src)

print("IDS Started")
sniff(prn=detect_attack, store=False, iface="Wi-Fi")
