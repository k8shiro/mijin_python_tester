# -*- coding: utf-8 -*-

import json
import requests

def get_account_info(config):
    url = 'http://' + config['ip'] + ':' + config['port'] + '/account/get'
    params = {'address': config['account'][0]['address']}
    response = requests.get(url, params=params)
    return response.text

def get_config():
    config_file = open('config.json')
    config = json.load(config_file)
    config_file.close()
    return config

if __name__ == '__main__':
    config = get_config()
    account_info = get_account_info(config)
    print(account_info)
