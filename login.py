# -*- coding: utf-8 -*-
import base64, random, string, time
import requests
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

Mobile, SMS_code = "填入手机号", "填入验证码"
PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDc+CZK9bBA9IU+gZUOc6FUGu7y
O9WpTNB0PzmgFBh96Mg1WrovD1oqZ+eIF4LjvxKXGOdI79JRdve9NPhQo07+uqGQ
gE4imwNnRx7PFtCRryiIEcUoavuNtuRVoBAm6qdB0SrctgaqGfLgKvZHOnwTjyNq
jBUxzMeQlEC2czEMSwIDAQAB
-----END PUBLIC KEY-----"""
APP_ID = "44fd964cef7a8ced082d577f9b8d6b2e3daf2d185b29d748dd8791c26c546acaca04979638b8d4176617563d84612af8af76e84f1178a8b314fa281074bae2e90cdec16ddbfb5067d088cfbf97d9e18f48f109fc30feb6fb2399bc25aef9b644"

def rsa_encrypt(content):
    try:
        text = str(content) + "".join(random.choices(string.ascii_letters + string.digits, k=6))
        return base64.b64encode(PKCS1_v1_5.new(RSA.importKey(PUBLIC_KEY_PEM)).encrypt(text.encode("utf-8"))).decode("utf-8")
    except: return None

def login_unicom(mobile, sms_code):
    if not (enc_mobile := rsa_encrypt(mobile)) or not (enc_pwd := rsa_encrypt(sms_code)): return print("加密失败")
    headers = {"Host": "loginxhm.10010.com", "Accept": "*/*", "Content-Type": "application/x-www-form-urlencoded", "Connection": "keep-alive", "User-Agent": "ChinaUnicom4.x/12.8.1 (com.chinaunicom.mobilebusiness; build:11; iOS 16.6.0) Alamofire/4.7.3 unicom{version:iphone_c@12.0801}", "Accept-Language": "zh-Hans-US;q=1.0, en-US;q=0.9", "Accept-Encoding": "gzip;q=1.0, compress;q=0.5"}
    try:
        result = requests.post("https://loginxhm.10010.com/mobileService/radomLogin.htm", data={"mobile": enc_mobile, "password": enc_pwd, "keyVersion": "2", "reqtime": time.strftime("%Y-%m-%d %H:%M:%S"), "loginStyle": "0", "isFirstInstall": "0", "appId": APP_ID, "deviceOS": "16.6", "deviceCode": "F2D25EE0-DEAD-483F-ADF6-E6434DF72F5F", "pip": "192.168.1.101", "version": "iphone_c@12.0801", "netWay": "wifi", "deviceModel": "iPhone14,6", "deviceBrand": "iPhone", "simCount": "1"}, headers=headers, timeout=10).json()
        if result.get("code") == "0" and (token := result.get("token_online")): print(token); return token
        print(f"登录失败: {result}")
    except Exception as e: print(e)
    return None

if __name__ == "__main__": login_unicom(Mobile, SMS_code)
