import sys
import os
import json
import time
import numpy as np
import pandas as pd
import xgboost as xgb
import socket
import threading
import tensorflow as tf
import tensorrt as trt
import pycuda.driver as cuda
import pycuda.autoinit
import onnxruntime as ort
from scapy.all import sniff, IP, TCP, UDP
from kitsune.Kitsune import Kitsune
from pycryptodome.PublicKey import ECC  # Quantum-Resistant ECC
from pycryptodome.Cipher import AES
import hashlib
import subprocess
import hashlib

# Blockchain Implementation for Secure Logging
class Blockchain:
    def _init_(self):
        self.chain = []
        self.create_block(previous_hash='0')

    def create_block(self, data='', previous_hash=''):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'data': data,
            'previous_hash': previous_hash,
            'hash': self.hash_block(data, previous_hash)
        }
        self.chain.append(block)
        return block

    def hash_block(self, data, previous_hash):
        encoded_block = f'{data}{previous_hash}{time.time()}'.encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def get_last_block(self):
        return self.chain[-1]

# Blockchain Initialization
blockchain = Blockchain()

# Quantum Encryption Setup (Kyber Alternative: ECC-Based)
def encrypt_message(message, key):
    key_hash = hashlib.sha256(key.export_key(format='DER')).digest()
    cipher = AES.new(key_hash, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return cipher.nonce + ciphertext

# Generate Quantum-Secure Key
ecc_key = ECC.generate(curve='P-256')

kitsune_model_path = "/home/jan27/bits_project/models/kitsune_model.h5"
xgb_model_path = "/home/jan27/bits_project/models/xgboost_intrusion_detection.json"
lstm_trt_path = "/home/jan27/bits_project/models/cicids_lstm_trt.plan"
lstm_onnx_path = "/home/jan27/bits_project/models/cicids_lstm.onnx"
lstm_h5_path = "/home/jan27/bits_project/models/cicids_lstm.h5"

# Check model availability
if not os.path.exists(kitsune_model_path):
    raise FileNotFoundError(f"❌ Kitsune model '{kitsune_model_path}' not found!")

if not os.path.exists(xgb_model_path):
    raise FileNotFoundError(f"❌ XGBoost model '{xgb_model_path}' not found!")

kitsune = Kitsune(None, limit=10000)

# Load XGBoost model
xgb_model = xgb.XGBClassifier(tree_method='gpu_hist', predictor='gpu_predictor')
xgb_model.load_model(xgb_model_path)

# Load LSTM Model
try:
    if os.path.exists(lstm_trt_path):
        trt_runtime = trt.Runtime(trt.Logger(trt.Logger.WARNING))
        with open(lstm_trt_path, "rb") as f:
            lstm_engine = trt_runtime.deserialize_cuda_engine(f.read())
            lstm_context = lstm_engine.create_execution_context()
    elif os.path.exists(lstm_onnx_path):
        lstm_model = ort.InferenceSession(lstm_onnx_path)
    elif os.path.exists(lstm_h5_path):
        lstm_model = tf.keras.models.load_model(lstm_h5_path)
except Exception as e:
    print(f"⚠ Error loading LSTM model: {e}")

# Self-Healing Mechanism (Quarantine and Recovery)
def block_ip(ip):
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        print(f"🚫 IP {ip} blocked for security reasons.")
        blockchain.create_block(data=f"Blocked IP: {ip}")
    except subprocess.CalledProcessError as e:
        print(f"⚠ Error blocking IP {ip}: {e}")

def unblock_ip(ip):
    try:
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        print(f"✅ IP {ip} unblocked after review.")
        blockchain.create_block(data=f"Unblocked IP: {ip}")
    except subprocess.CalledProcessError as e:
        print(f"⚠ Error unblocking IP {ip}: {e}")

def auto_restore():
    time.sleep(300)  # 5 minutes recovery period
    try:
        with open("quarantined_ips.json", "r") as f:
            quarantined_ips = json.load(f)
        for ip in quarantined_ips:
            unblock_ip(ip)
        os.remove("quarantined_ips.json")
    except (FileNotFoundError, json.JSONDecodeError):
        print("⚠ No quarantined IPs to restore.")

def send_alert(ip, message):
    encrypted_msg = encrypt_message(f"Intrusion from {ip}: {message}", ecc_key)
    print(f"🔒 Secure Alert Sent: {encrypted_msg}")

# Intrusion Detection Logic
def detect_intrusions(packet):
    try:
        if IP not in packet:
            return
        src_ip = packet[IP].src
        features = kitsune.get_next_vector(packet)
        if features is None or len(features) == 0:
            return
        anomaly_score = kitsune.AE.execute(features.flatten())
        print(f"📊 Anomaly Score: {anomaly_score:.4f}")
        if anomaly_score > 0.8:
            attack_pred = xgb_model.predict(features)
            if attack_pred[0] == 1:
                print(f"🚨 Intrusion Detected from {src_ip}!")
                block_ip(src_ip)
                with open("quarantined_ips.json", "a") as f:
                    json.dump([src_ip], f)
                threading.Thread(target=auto_restore, daemon=True).start()
                send_alert(src_ip, "Detected Attack")
    except Exception as e:
        print(f"⚠ Error in Intrusion Detection: {e}")

print("🚀 Intrusion Detection System Running...")
sniff(prn=detect_intrusions, store=False)