# -*- coding: utf-8 -*-

import json

import requests

import datetime
from math import atan
import hashlib
from ed25519.ed25519 import *
import sha3
import sys
from binascii import hexlify, unhexlify


def get_args():
    argv = sys.argv
    argc = len(argv)
    if (argc != 3):
        print ('Usage: python {0} sender.json receiver_address'.format(argv[0]))
        quit()
    return argv


def get_config():
    config_file = open('config.json')
    config = json.load(config_file)
    config_file.close()
    return config


def get_sender(sender_file_name):
    sender_file = open(sender_file_name)
    sender = json.load(sender_file)
    sender_file.close()
    return sender


def get_last_block(config):
    url = 'http://' + config['ip'] + ':' + config['port'] + '/chain/last-block'
    response = requests.get(url)
    return response.json()



def str_to_byte(data, num):
    result = ''
    for data_i in data:
        result += hex(ord(data_i)).replace('0x', '')

    for var in range(num*2 - len(result)):
        result += '0'

    return result


def get_timestamp(hours, timestamp):
    u"""
    自分で計算する場合は
    NEM標準時?からタイムスタンプを生成
    hoursに現時刻からずらしたい時間を入れる
    """
    #nem_epoch = datetime.datetime(2015, 3, 29, 0, 6, 25, 0, None)
    #urrent_datetime = datetime.datetime.utcnow()
    #timestamp = int((current_datetime - nem_epoch).total_seconds())
    t = timestamp
    t += hours * 60 * 60
    timestamp_hex = hexlify(t.to_bytes(4, byteorder='little')).decode('utf-8')
    return timestamp_hex


def get_amount(xem):
    amount_hex = hexlify(xem.to_bytes(8, byteorder='little')).decode('utf-8')
    return amount_hex



def get_recipient_length():
    l = 40
    return hexlify(l.to_bytes(4, byteorder='little')).decode('utf-8')



def get_recipient(address):
    return str_to_byte(address, 40)


def get_type(type):
    type_hex = hex(type).replace('0x', '')
    for var in range(4-len(type_hex)):
        type_hex = '0' + type_hex
    type_hex += '0000'
    return type_hex


def get_message(type, payload):
    if len(payload) == 0:
        return '00000000'
    type_hex = get_type(type)
    payload_hex = str_to_byte(payload, len(payload))
    payload_length_hex = hexlify(len(payload).to_bytes(4, byteorder='little')).decode('utf-8')
    message_hex = type_hex + payload_length_hex + payload_hex
    message_length_hex = hexlify((len(message_hex)//2).to_bytes(4, byteorder='little')).decode('utf-8')
    return message_length_hex + message_hex


def get_version(version):
    if version < 0:
        version_hex = hex(int('0xffffffff', 16) + 1 + version).replace('0x', '')
    else:
        version_hex = hex(version).replace('0x', '')

    ret = ''
    for fst, scd in zip(version_hex[::2], version_hex[1::2]):
        ret = fst + scd + ret

    for var in range(4-len(ret)):
        ret = '0' + ret
    return ret


def get_signer(public_key):
    return public_key


def get_public_key_length():
    l = 32
    return hexlify(l.to_bytes(4, byteorder='little')).decode('utf-8')

def serialize_data(sender, receiver_address, last_block):
    serialize = ''
    serialize += get_type(257)
    serialize += get_version(last_block['version'])
    serialize += get_timestamp(0, last_block['timeStamp'])
    serialize += get_public_key_length()
    serialize += get_signer(sender['publicKey'])
    serialize += get_amount(2000000)
    serialize += get_timestamp(1, last_block['timeStamp'])

    # v1
    serialize += get_recipient_length()
    serialize += get_recipient(receiver_address)
    serialize += get_amount(10000000)
    serialize += get_message(1, '')
    return serialize


def make_signature(data, pk, sk):
    bytes_data = unhexlify(data)
    bytes_sk = int('0x' + sk, 16).to_bytes(32, byteorder='little')
    bytes_pk = int('0x' + pk, 16).to_bytes(32, byteorder='big')
    signature = signature_hash_unsafe(bytes_data, bytes_sk, bytes_pk, hashlib.sha3_512)
    return hexlify(signature).decode('utf-8')


if __name__ == '__main__':
    args = get_args()
    sender_file_name = args[1]
    receiver_address = args[2]
    sender = get_sender(sender_file_name)
    config = get_config()
    last_block = get_last_block(config)
    print(last_block)
    print(last_block['timeStamp'])
    print(last_block['version'])

    # 共通部分
    serialize = serialize_data(sender, receiver_address, last_block)



    signature = make_signature(serialize, sender['publicKey'], sender['privateKey'])

    data = {'data': serialize,
            'signature': signature
            }

    #POST
    config = get_config()
    headers = {'Content-type': 'application/json'}
    url = 'http://' + config['ip'] + ':' + config['port'] + '/transaction/announce'
    ret = requests.post(url, data=json.dumps(data), headers=headers, timeout=10)
    print(ret.text)
