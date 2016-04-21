

# -*- coding: utf-8 -*-

import json
import requests
import datetime

def generate_new_account(config):
    url = 'http://' + config['ip'] + ':' + config['port'] + '/account/generate'
    response = requests.get(url)
    return response.json()

def get_config():
    config_file = open('config.json')
    config = json.load(config_file)
    config_file.close()
    return config


def generate_new_account_file(account_info):
    account_file = open('generated_account/account' + datetime.datetime.now().strftime('%Y_%m_%d_%H%M%S') + '.json', 'w')
    with account_file as f:
        json.dump(account_info, f, sort_keys=True, indent=4)
    account_file.close()


if __name__ == '__main__':
    config = get_config()
    account_info = generate_new_account(config)
    print(account_info)
    generate_new_account_file(account_info)