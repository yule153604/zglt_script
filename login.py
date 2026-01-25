# -*- coding: utf-8 -*-
import base64
import random
import string
import time
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

Mobile = "填入手机号"
SMS_code = "填入验证码"

# RSA 公钥 (keyVersion=2)
PUBLIC_KEY_PEM = '''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDc+CZK9bBA9IU+gZUOc6FUGu7y
O9WpTNB0PzmgFBh96Mg1WrovD1oqZ+eIF4LjvxKXGOdI79JRdve9NPhQo07+uqGQ
gE4imwNnRx7PFtCRryiIEcUoavuNtuRVoBAm6qdB0SrctgaqGfLgKvZHOnwTjyNq
jBUxzMeQlEC2czEMSwIDAQAB
-----END PUBLIC KEY-----'''

APP_ID = "44fd964cef7a8ced082d577f9b8d6b2e3daf2d185b29d748dd8791c26c546acaca04979638b8d4176617563d84612af8af76e84f1178a8b314fa281074bae2e90cdec16ddbfb5067d088cfbf97d9e18f48f109fc30feb6fb2399bc25aef9b644"


def rsa_encrypt(content):
    """RSA加密: 原文 + 6位随机盐 -> PKCS1加密 -> Base64"""
    try:
        salt = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
        text = str(content) + salt
        rsa_key = RSA.importKey(PUBLIC_KEY_PEM)
        cipher = PKCS1_v1_5.new(rsa_key)
        ciphertext = cipher.encrypt(text.encode('utf-8'))
        return base64.b64encode(ciphertext).decode('utf-8')
    except Exception:
        return None


def login_unicom(mobile, sms_code):
    """登录联通，成功返回 token_online"""
    url = "https://loginxhm.10010.com/mobileService/radomLogin.htm"

    encrypted_mobile = rsa_encrypt(mobile)
    encrypted_password = rsa_encrypt(sms_code)

    if not encrypted_mobile or not encrypted_password:
        print("加密失败")
        return None

    data = {
        "mobile": encrypted_mobile,
        "password": encrypted_password,  # 验证码
        "keyVersion": "2",
        "reqtime": time.strftime("%Y-%m-%d %H:%M:%S"),
        "loginStyle": "0",  # 验证码登录
        "isFirstInstall": "0",
        "appId": APP_ID,
        "deviceOS": "16.6",
        "deviceCode": "F2D25EE0-DEAD-483F-ADF6-E6434DF72F5F",
        "pip": "192.168.1.101",
        "version": "iphone_c@12.0801",
        "netWay": "wifi",
        "deviceModel": "iPhone14,6",
        "deviceBrand": "iPhone",
        "simCount": "1"
    }

    headers = {
        "Host": "loginxhm.10010.com",
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded",
        "Connection": "keep-alive",
        "User-Agent": "ChinaUnicom4.x/12.8.1 (com.chinaunicom.mobilebusiness; build:11; iOS 16.6.0) Alamofire/4.7.3 unicom{version:iphone_c@12.0801}",
        "Accept-Language": "zh-Hans-US;q=1.0, en-US;q=0.9",
        "Accept-Encoding": "gzip;q=1.0, compress;q=0.5"
    }

    try:
        response = requests.post(url, data=data, headers=headers, timeout=10)
        result = response.json()
        if result.get("code") == "0":
            token = result.get("token_online")
            if token:
                print(token)
                return token
        else:
            print(f"登录失败: {result}")
    except Exception as e:
        print(e)
    return None


if __name__ == "__main__":
    mobile = Mobile
    sms_code = SMS_code
    login_unicom(mobile, sms_code)
