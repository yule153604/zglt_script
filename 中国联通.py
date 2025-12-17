# -*- coding: utf-8 -*-
"""
仅供学习交流：本项目仅供编程学习和技术交流使用，请勿用于任何商业用途。
合法使用：请勿将本脚本用于任何非法目的，包括但不限于恶意攻击、刷单等行为。
风险自担：使用本脚本产生的任何后果（包括但不限于账号封禁、财产损失等）由使用者自行承担，开发者不承担任何责任。
隐私保护：本项目不会收集用户的任何敏感信息，所有数据均保存在用户本地。
侵权联系：如果本项目侵犯了您的权益，请及时联系开发者进行处理。
"""
import asyncio
import hashlib
import json
import time
import random
import string
import base64
import os
import sys
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode
import httpx

# 可选依赖：账密登录需要 pycryptodome
try:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# ====================  Constants  ====================
APP_VERSION = "iphone_c@11.0503"
SHOW_PRIZE_POOL = False  # 是否显示权益超市奖品池信息，默认关闭
USER_AGENT = f"Mozilla/5.0 (iPhone; CPU iPhone OS 16_1_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 unicom{{version:{APP_VERSION}}}"
APP_ID = "86b8be06f56ba55e9fa7dff134c6b16c62ca7f319da4a958dd0afa0bf9f36f1daa9922869a8d2313b6f2f9f3b57f2901f0021c4575e4b6949ae18b7f6761d465c12321788dcd980aa1a641789d1188bb"
CLIENT_ID = "73b138fd-250c-4126-94e2-48cbcc8b9cbe"
CLIENT_ID_2 = "1001000003"
ANOTHER_API_KEY = "beea1c7edf7c4989b2d3621c4255132f"
ANOTHER_ENCRYPTION_KEY = "f4cd4ffeb5554586acf65ba7110534f5"
SERVICE_LIFE = "wocareMBHServiceLife1"
MIN_RETRIES = "1"

# ====================  青龙API操作  ====================
def ql_get_env(name):
    """获取青龙环境变量"""
    try:
        res = QLAPI.getEnvs({"searchValue": name})
        for env in res.get("data", []):
            if env.get("name") == name:
                return env
        return None
    except:
        return None

def ql_update_env(env_data):
    """更新青龙环境变量"""
    try:
        QLAPI.updateEnv({"env": env_data})
        return True
    except:
        return False

def ql_update_cookie_to_token(phone, token_online, appid):
    """
    将 chinaUnicomCookie 中对应手机号的账密格式更新为 token_online#appid 格式
    账密格式: 手机号#密码
    Token格式: token_online#appid
    """
    try:
        env = ql_get_env("chinaUnicomCookie")
        if not env:
            print(f"[QL] 未找到 chinaUnicomCookie 环境变量")
            return False

        old_value = env.get("value", "")
        if not old_value:
            return False

        # 分割多账号（@分隔）
        accounts = old_value.split("@")
        updated = False
        new_accounts = []

        for account in accounts:
            account = account.strip()
            if not account:
                continue

            # 检查是否是当前手机号的账密格式
            if account.startswith(phone + "#"):
                parts = account.split("#")
                # 账密格式：手机号#密码（密码长度通常<50）
                if len(parts) >= 2 and len(parts[1]) < 50:
                    # 替换为 token_online#appid 格式
                    new_accounts.append(f"{token_online}#{appid}")
                    updated = True
                    print(f"[QL] 账号 {phone} 已从账密格式更新为Token格式")
                else:
                    new_accounts.append(account)
            else:
                new_accounts.append(account)

        if updated:
            env["value"] = "@".join(new_accounts)
            if ql_update_env(env):
                print(f"[QL] chinaUnicomCookie 环境变量更新成功")
                return True
            else:
                print(f"[QL] chinaUnicomCookie 环境变量更新失败")
                return False

        return False
    except Exception as e:
        print(f"[QL] 更新环境变量异常: {str(e)}")
        return False

# ====================  Global Market Raffle State  ====================
# 全局奖池状态，多账号共享，只查询一次
class MarketRaffleState:
    def __init__(self):
        self.checked = False       # 是否已检查
        self.has_prizes = False    # 是否有奖品可抽
        self.prizes = []           # 奖品列表
        self.lock = asyncio.Lock() # 异步锁

    async def check_prizes(self, http_client, market_token):
        """检查奖池状态，只执行一次"""
        async with self.lock:
            if self.checked:
                return self.has_prizes

            print("\n" + "="*60)
            print("权益超市奖品池查询")
            print("="*60)

            try:
                res = await http_client.request(
                    'POST',
                    'https://backward.bol.wo.cn/prod-api/promotion/home/raffleActivity/prizeList?id=12',
                    headers={'Authorization': f'Bearer {market_token}'},
                    data=''
                )

                result = res['result']
                if result and result.get('code') == 200 and isinstance(result.get('data'), list):
                    self.prizes = result['data']

                    # 筛选今日奖池（概率>0的奖品）
                    today_prizes = [p for p in self.prizes if float(p.get('probability', 0)) > 0]
                    total = len(today_prizes)
                    print(f"今日奖池共 {total} 个奖品:\n")

                    # 有效奖品关键词
                    include_keywords = ['月卡', '周卡', '月度', '季卡']
                    exclude_keywords = ['5G宽视界', '沃视频']

                    valid_count = 0
                    for i, prize in enumerate(today_prizes, 1):
                        name = prize.get('name', '未知')
                        try:
                            daily_limit = int(prize.get('dailyPrizeLimit', 0))
                            quantity = int(prize.get('quantity', 0))
                            prob = float(prize.get('probability', 0))
                        except:
                            daily_limit = 0
                            quantity = 0
                            prob = 0.0

                        # 判断奖品是否有效：包含指定关键词、不含排除关键词、概率>0
                        has_include = any(kw in name for kw in include_keywords)
                        has_exclude = any(kw in name for kw in exclude_keywords)
                        is_valid = has_include and not has_exclude and prob > 0

                        status = "✅" if is_valid else "❌"
                        if is_valid:
                            valid_count += 1

                        print(f"  {status} [{i:02d}] {name}")
                        print(f"       今日投放: {daily_limit} | 总库存: {quantity} | 概率: {prob*100:.2f}%")

                    print(f"\n{'='*60}")
                    if valid_count > 0:
                        self.has_prizes = True
                        print(f"结论: 当前已放水！有效奖品 {valid_count}/{total} 个，可以抽奖")
                    else:
                        self.has_prizes = False
                        print(f"结论: 当前未放水！无有效奖品，跳过抽奖")
                    print("="*60 + "\n")
                else:
                    print(f"奖品池查询失败: {result}")
                    self.has_prizes = False
            except Exception as e:
                print(f"奖品池查询异常: {str(e)}")
                self.has_prizes = False

            self.checked = True
            return self.has_prizes

# 全局奖池状态实例
market_raffle_state = MarketRaffleState()

# ====================  Utils  ====================
class Logger:
    def __init__(self, prefix=""):
        self.prefix = prefix

    def log(self, message, notify=False):
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix_str = f"[{self.prefix}] " if self.prefix else ""
        print(f"[{timestamp}] {prefix_str}{message}")

class HttpClient:
    def __init__(self, logger_instance):
        self.logger = logger_instance
        self.headers = {
            "User-Agent": USER_AGENT,
            "Connection": "keep-alive"
        }
        self.cookies = httpx.Cookies()
        self.timeout = 50.0
        self.retries = 3

    async def request(self, method, url, **kwargs):
        # Merge headers
        headers = self.headers.copy()
        if 'headers' in kwargs:
            headers.update(kwargs.pop('headers'))
        
        # Handle cookies
        cookies = kwargs.pop('cookies', self.cookies)

        for attempt in range(self.retries):
            try:
                async with httpx.AsyncClient(cookies=cookies, http2=False, follow_redirects=False, timeout=self.timeout, verify=False) as client:
                    response = await client.request(method, url, headers=headers, **kwargs)
                    
                    # Update cookies
                    self.cookies.update(response.cookies)
                    
                    # Handle response
                    try:
                        result = response.json()
                    except:
                        result = response.text
                    
                    return {
                        'statusCode': response.status_code,
                        'headers': response.headers,
                        'result': result
                    }
            except Exception as e:
                if attempt == self.retries - 1:
                    self.logger.log(f"Request failed: {method} {url} - {str(e)}")
                    return {'statusCode': -1, 'headers': {}, 'result': None}
                await asyncio.sleep(1 + attempt * 2)

# ====================  RSA Encrypt (账密登录)  ====================
class RSAEncrypt:
    """RSA加密类，用于账号密码登录"""
    def __init__(self):
        self.public_key = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDc+CZK9bBA9IU+gZUOc6FUGu7y
O9WpTNB0PzmgFBh96Mg1WrovD1oqZ+eIF4LjvxKXGOdI79JRdve9NPhQo07+uqGQ
gE4imwNnRx7PFtCRryiIEcUoavuNtuRVoBAm6qdB0SrctgaqGfLgKvZHOnwTjyNq
jBUxzMeQlEC2czEMSwIDAQAB
-----END PUBLIC KEY-----"""
        self.max_block_size = 117

    def encrypt(self, plaintext, is_password=False):
        """RSA加密"""
        if not HAS_CRYPTO:
            return ""
        try:
            if is_password:
                plaintext = plaintext + "000000"

            raw = plaintext.encode('utf-8')
            pubkey = RSA.import_key(self.public_key)
            cipher = PKCS1_v1_5.new(pubkey)

            result = []
            for i in range(0, len(raw), self.max_block_size):
                block = raw[i:i + self.max_block_size]
                encrypted_block = cipher.encrypt(block)
                result.append(encrypted_block)

            encrypted = b"".join(result)
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            return ""

class CustomUserService:
    def __init__(self, cookie, index=1):
        self.cookie = cookie
        self.index = index
        self.logger = Logger(prefix=f"账号{index}")
        self.http = HttpClient(self.logger)
        self.valid = False
        self.mobile = ""
        self.app_version = APP_VERSION

        # 解析登录方式：账密登录格式为"手机号#密码"（密码较短），token登录格式为长token字符串
        self.login_mode = self._detect_login_mode(cookie)
        if self.login_mode == "password":
            parts = cookie.split('#')
            self.phone = parts[0]
            self.password = parts[1] if len(parts) > 1 else ""
            self.token_online = ""
            # 生成 appid（用于账密登录）
            self.app_id = self._generate_appid()
        else:
            # Token登录格式：token_online 或 token_online#appid
            parts = cookie.split('#')
            self.token_online = parts[0]
            self.phone = ""
            self.password = ""
            # 如果有第二部分且长度足够长（appid特征），则使用它
            if len(parts) >= 2 and len(parts[1]) > 50:
                self.app_id = parts[1]
            else:
                self.app_id = APP_ID

        self.unicom_token_id = self.random_string(32)
        self.token_id_cookie = "chinaunicom-" + self.random_string(32, string.ascii_uppercase + string.digits)
        self.sdkuuid = self.unicom_token_id

        self.http.cookies.set("TOKENID_COOKIE", self.token_id_cookie, domain=".10010.com")
        self.http.cookies.set("UNICOM_TOKENID", self.unicom_token_id, domain=".10010.com")
        self.http.cookies.set("sdkuuid", self.sdkuuid, domain=".10010.com")

        self.rpt_id = ""
        self.market_token = ""
        self.xj_token = ""
        self.wocare_token = ""
        self.wocare_sid = ""
        self.ecs_token = ""

    def _detect_login_mode(self, cookie):
        """检测登录模式：账密登录或token登录"""
        if '#' in cookie:
            parts = cookie.split('#')
            # 账密登录格式：手机号#密码（手机号11位数字，密码通常较短）
            if len(parts) >= 2:
                phone = parts[0]
                password = parts[1]
                # 手机号应为11位数字，密码长度通常小于50
                if phone.isdigit() and len(phone) == 11 and len(password) < 50:
                    return "password"
        # 默认为token登录
        return "token"

    def _generate_appid(self):
        """生成账密登录用的appid"""
        return (
            f"{random.randint(0,9)}f{random.randint(0,9)}af"
            f"{random.randint(0,9)}{random.randint(0,9)}ad"
            f"{random.randint(0,9)}912d306b5053abf90c7ebbb695887bc"
            "870ae0706d573c348539c26c5c0a878641fcc0d3e90acb9be1e6ef858a"
            "59af546f3c826988332376b7d18c8ea2398ee3a9c3db947e2471d32a49612"
        )

    def random_string(self, length, chars=string.ascii_letters + string.digits):
        return ''.join(random.choice(chars) for _ in range(length))

    def get_bizchannelinfo(self):
        info = {
            "bizChannelCode": "225",
            "disriBiz": "party",
            "unionSessionId": "",
            "stType": "",
            "stDesmobile": "",
            "source": "",
            "rptId": self.rpt_id,
            "ticket": "",
            "tongdunTokenId": self.token_id_cookie,
            "xindunTokenId": self.sdkuuid
        }
        return json.dumps(info)

    def get_epay_authinfo(self):
        info = {
            "mobile": "",
            "sessionId": getattr(self, 'session_id', ''),
            "tokenId": getattr(self, 'token_id', ''),
            "userId": ""
        }
        return json.dumps(info)

    # ====================  Login  ====================
    async def online(self):
        """登录方法：根据登录模式自动选择token登录或账密登录"""
        if self.login_mode == "password":
            return await self._login_with_password()
        else:
            return await self._login_with_token()

    async def _login_with_password(self):
        """账号密码登录"""
        if not HAS_CRYPTO:
            self.logger.log("账密登录需要 pycryptodome 库，请安装: pip install pycryptodome")
            return False

        try:
            self.logger.log(f"使用账密登录: {self.phone}")
            rsa = RSAEncrypt()
            encrypted_mobile = rsa.encrypt(self.phone, is_password=False)
            encrypted_password = rsa.encrypt(self.password, is_password=True)

            if not encrypted_mobile or not encrypted_password:
                self.logger.log("RSA加密失败")
                return False

            device_id = hashlib.md5(self.phone.encode()).hexdigest()
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            data = {
                "voipToken": "citc-default-token-do-not-push",
                "deviceBrand": "iPhone",
                "simOperator": "--,%E4%B8%AD%E5%9B%BD%E7%A7%BB%E5%8A%A8,--,--,--",
                "deviceId": device_id,
                "netWay": "wifi",
                "deviceCode": device_id,
                "deviceOS": "15.8.3",
                "uniqueIdentifier": device_id,
                "latitude": "",
                "version": "iphone_c@12.0200",
                "pip": "192.168.5.14",
                "isFirstInstall": "1",
                "remark4": "",
                "keyVersion": "2",
                "longitude": "",
                "simCount": "1",
                "mobile": encrypted_mobile,
                "isRemberPwd": "false",
                "appId": self.app_id,
                "reqtime": timestamp,
                "deviceModel": "iPhone8,2",
                "password": encrypted_password
            }

            headers = {
                "Host": "m.client.10010.com",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": f"ChinaUnicom4.x/12.2 (com.chinaunicom.mobilebusiness; build:44; iOS 15.8.3) Alamofire/4.7.3 unicom{{version:iphone_c@12.0200}}",
            }

            res = await self.http.request(
                'POST',
                'https://m.client.10010.com/mobileService/login.htm',
                data=data,
                headers=headers
            )

            result = res['result']
            code = str(result.get('code', '')) if result else ''

            if code in ['0', '0000']:
                self.token_online = result.get('token_online', '')
                self.ecs_token = result.get('ecs_token', '')
                self.mobile = self.phone
                self.valid = True
                self.province = ""

                # 尝试获取省份信息
                user_list = result.get('list', [])
                if user_list and len(user_list) > 0:
                    self.province = user_list[0].get('proName', '')

                masked_mobile = self.mobile[:3] + "****" + self.mobile[-4:]
                self.logger.log(f"账密登录成功: {masked_mobile} (归属地: {self.province})")

                # 账密登录成功后，尝试更新青龙环境变量为token格式
                try:
                    ql_update_cookie_to_token(self.phone, self.token_online, self.app_id)
                except:
                    pass  # 非青龙环境下忽略

                return True
            elif code == '2':
                self.logger.log("密码错误，请检查登录专用密码")
                return False
            elif code == '11':
                self.logger.log("未设置登录专用密码，请前往联通APP设置")
                return False
            elif code == 'ECS99999':
                self.logger.log("触发安全风控，请手动登录联通APP解除")
                return False
            else:
                desc = result.get('desc', '未知错误') if result else '请求失败'
                self.logger.log(f"账密登录失败: {desc} (Code: {code})")
                return False

        except Exception as e:
            self.logger.log(f"账密登录异常: {str(e)}")
            return False

    async def _login_with_token(self):
        """Token登录（原online方法）"""
        try:
            # Fake device info
            device_id = "968e026d0b00180ad57dce019a59ed44ce3ef0ddd78bc3a221de273c666ec130"
            device_code = "F2D25EE0-DEAD-483F-ADF6-E6434DF72F5F"
            unique_identifier = "ios" + self.random_string(32, "0123456789abcdef")
            
            data = {
                'token_online': self.token_online,
                'reqtime': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'appId': self.app_id,
                'version': self.app_version,
                'step': 'bindlist',
                'isFirstInstall': 0,
                'deviceModel': 'iPhone14,6',
                'deviceOS': '16.6',
                'deviceBrand': 'iPhone',
                #'deviceId': device_id,
                #'deviceCode': device_code,
                'uniqueIdentifier': unique_identifier,
                'simOperator': '--,--,65535,65535,--@--,--,65535,65535,--',
                'voipToken': 'citc-default-token-do-not-push'
            }
            
            res = await self.http.request(
                'POST',
                'https://m.client.10010.com/mobileService/onLine.htm',
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            result = res['result']
            if result and str(result.get('code')) == '0':
                self.valid = True
                self.mobile = result.get('desmobile', '')
                self.ecs_token = result.get('ecs_token', '')
                # Extract province
                self.province = ""
                user_list = result.get('list', [])
                if user_list and len(user_list) > 0:
                    self.province = user_list[0].get('proName', '')
                masked_mobile = self.mobile[:3] + "****" + self.mobile[-4:] if len(self.mobile) >= 11 else self.mobile
                self.logger.log(f"登录成功: {masked_mobile} (归属地: {self.province})")
                return True
            else:
                self.logger.log(f"登录失败: {result}")
                return False
        except Exception as e:
            self.logger.log(f"登录异常: {str(e)}")
            return False

    async def open_plat_line_new(self, url):
        try:
            res = await self.http.request(
                'GET',
                'https://m.client.10010.com/mobileService/openPlatform/openPlatLineNew.htm',
                params={'to_url': url}
            )
            
            location = res['headers'].get('location') or res['headers'].get('Location')
            if location:
                parsed = urlparse(location)
                qs = parse_qs(parsed.query)
                return {
                    'ticket': qs.get('ticket', [''])[0],
                    'type': qs.get('type', ['02'])[0],
                    'loc': location
                }
            self.logger.log("获取ticket失败: 无location")
            return {'ticket': '', 'type': '', 'loc': ''}
        except Exception as e:
            self.logger.log(f"获取ticket异常: {str(e)}")
            return {'ticket': '', 'type': '', 'loc': ''}

    # ====================  Sign Task  ====================
    async def sign_task(self):
        await self.sign_get_continuous()

    async def sign_get_continuous(self):
        try:
            imei = "BB97982E-3F03-46D3-B904-819D626DF478"
            res = await self.http.request(
                'GET',
                'https://activity.10010.com/sixPalaceGridTurntableLottery/signin/getContinuous',
                params={'taskId': '', 'channel': 'wode', 'imei': imei}
            )
            
            result = res['result']
            if result and str(result.get('code')) == '0000':
                today_signed = result.get('data', {}).get('todayIsSignIn', 'n')
                self.logger.log(f"签到状态: {'已签到' if today_signed != 'n' else '未签到'}")
                if today_signed == 'n':
                    await asyncio.sleep(1)
                    await self.sign_day_sign()
            else:
                self.logger.log(f"查询签到状态失败: {result}")
        except Exception as e:
            self.logger.log(f"查询签到状态异常: {str(e)}")

    async def sign_day_sign(self):
        try:
            res = await self.http.request(
                'POST',
                'https://activity.10010.com/sixPalaceGridTurntableLottery/signin/daySign',
                data={}
            )
            
            result = res['result']
            if result and str(result.get('code')) == '0000':
                data = result.get('data', {})
                desc = data.get('statusDesc', '')
                msg = data.get('redSignMessage', '')
                self.logger.log(f"签到成功: {desc} {msg}", notify=True)
            elif str(result.get('code')) == '0002' and '已经签到' in result.get('desc', ''):
                self.logger.log("签到成功: 今日已完成签到", notify=True)
            else:
                self.logger.log(f"签到失败: {result}")
        except Exception as e:
            self.logger.log(f"签到异常: {str(e)}")

    # ====================  Daily Cash (ttlxj)  ====================
    async def ttlxj_task(self):
        self.rpt_id = ""
        target_url = "https://epay.10010.com/ci-mps-st-web/?webViewNavIsHidden=webViewNavIsHidden"
        ticket_info = await self.open_plat_line_new(target_url)
        if not ticket_info['ticket']:
            return
        await self.ttlxj_authorize(ticket_info['ticket'], ticket_info['type'], ticket_info['loc'])

    async def ttlxj_authorize(self, ticket, st_type, referer):
        try:
            data = {
                'response_type': 'rptid',
                'client_id': CLIENT_ID,
                'redirect_uri': 'https://epay.10010.com/ci-mps-st-web/',
                'login_hint': {
                    'credential_type': 'st_ticket',
                    'credential': ticket,
                    'st_type': st_type,
                    'force_logout': True,
                    'source': 'app_sjyyt'
                },
                'device_info': {
                    'token_id': f"chinaunicom-pro-{int(time.time()*1000)}-{self.random_string(13)}",
                    'trace_id': self.random_string(32)
                }
            }
            
            res = await self.http.request(
                'POST',
                'https://epay.10010.com/woauth2/v2/authorize',
                headers={'Origin': 'https://epay.10010.com', 'Referer': referer},
                json=data
            )
            
            result = res['result']
            if res['statusCode'] == 200:
                await self.ttlxj_auth_check()
            else:
                self.logger.log(f"天天领现金授权失败: {result}")
        except Exception as e:
            self.logger.log(f"天天领现金授权异常: {str(e)}")

    async def ttlxj_auth_check(self):
        try:
            res = await self.http.request(
                'POST',
                'https://epay.10010.com/ps-pafs-auth-front/v1/auth/check',
                headers={'bizchannelinfo': self.get_bizchannelinfo()}
            )
            
            result = res['result']
            if str(result.get('code')) == '0000':
                auth_info = result.get('data', {}).get('authInfo', {})
                self.session_id = auth_info.get('sessionId')
                self.token_id = auth_info.get('tokenId')
                await self.ttlxj_user_draw_info()
                await self.ttlxj_query_available()
            elif str(result.get('code')) == '2101000100':
                login_url = result.get('data', {}).get('woauth_login_url')
                await self.ttlxj_login(login_url)
            else:
                self.logger.log(f"天天领现金认证失败: {result}")
        except Exception as e:
            self.logger.log(f"天天领现金认证异常: {str(e)}")

    async def ttlxj_login(self, login_url):
        try:
            full_url = f"{login_url}https://epay.10010.com/ci-mcss-party-web/clockIn/?bizFrom=225&bizChannelCode=225&channelType=WDQB"
            res = await self.http.request('GET', full_url)
            
            location = res['headers'].get('location') or res['headers'].get('Location')
            if location:
                parsed = urlparse(location)
                self.rpt_id = parse_qs(parsed.query).get('rptid', [''])[0]
                if self.rpt_id:
                    await self.ttlxj_auth_check()
                else:
                    self.logger.log("天天领现金获取rptid失败")
            else:
                self.logger.log("天天领现金获取rptid失败: 无location")
        except Exception as e:
            self.logger.log(f"天天领现金登录异常: {str(e)}")

    async def ttlxj_user_draw_info(self):
        try:
            res = await self.http.request(
                'POST',
                'https://epay.10010.com/ci-mcss-party-front/v1/ttlxj/userDrawInfo',
                headers={
                    'bizchannelinfo': self.get_bizchannelinfo(),
                    'authinfo': self.get_epay_authinfo()
                }
            )
            
            result = res['result']
            if str(result.get('code')) == '0000':
                data = result.get('data', {})
                day_of_week = data.get('dayOfWeek')
                draw_key = f"day{day_of_week}"
                has_not_clocked_in = data.get(draw_key) == "1"
                
                self.logger.log(f"天天领现金今天{'未' if has_not_clocked_in else '已'}打卡", notify=True)
                
                if has_not_clocked_in:
                    today = datetime.now().weekday() + 1 # 1-7
                    draw_type = "C" if today % 7 == 0 else "B" # Sunday is 7 -> C, others -> B
                    await self.ttlxj_unify_draw_new(draw_type)
            else:
                self.logger.log(f"天天领现金查询失败: {result}")
        except Exception as e:
            self.logger.log(f"天天领现金查询异常: {str(e)}")

    async def ttlxj_unify_draw_new(self, draw_type):
        try:
            data = {
                'drawType': draw_type,
                'bizFrom': '225',
                'activityId': 'TTLXJ20210330'
            }
            res = await self.http.request(
                'POST',
                'https://epay.10010.com/ci-mcss-party-front/v1/ttlxj/unifyDrawNew',
                headers={
                    'bizchannelinfo': self.get_bizchannelinfo(),
                    'authinfo': self.get_epay_authinfo()
                },
                data=data 
            )
            
            result = res['result']
            if str(result.get('code')) == '0000' and str(result.get('data', {}).get('returnCode')) == '0':
                amount = result.get('data', {}).get('amount')
                msg = result.get('data', {}).get('awardTipContent', '').replace('xx', str(amount))
                self.logger.log(f"天天领现金打卡: {msg}", notify=True)
            else:
                self.logger.log(f"天天领现金打卡失败: {result}")
        except Exception as e:
            self.logger.log(f"天天领现金打卡异常: {str(e)}")

    async def ttlxj_query_available(self):
        try:
            res = await self.http.request(
                'POST',
                'https://epay.10010.com/ci-mcss-party-front/v1/ttlxj/queryAvailable',
                headers={
                    'bizchannelinfo': self.get_bizchannelinfo(),
                    'authinfo': self.get_epay_authinfo()
                }
            )
            
            result = res['result']
            if str(result.get('code')) == '0000' and str(result.get('data', {}).get('returnCode')) == '0':
                amount = result.get('data', {}).get('availableAmount', 0)
                self.logger.log(f"可用立减金: {float(amount)/100:.2f}元", notify=True)
            else:
                self.logger.log(f"天天领现金查询余额失败: {result}")
        except Exception as e:
            self.logger.log(f"天天领现金查询余额异常: {str(e)}")

    # ====================  Blessing (ltzf)  ====================
    async def ltzf_task(self):
        target_url = "https://wocare.unisk.cn/mbh/getToken?channelType=" + SERVICE_LIFE + "&homePage=home&duanlianjieabc=qAz2m"
        ticket_info = await self.open_plat_line_new(target_url)
        if not ticket_info['ticket']:
            return
        
        if not await self.wocare_get_token(ticket_info['ticket']):
            return
            
        tasks = [
            {'name': "星座配对", 'id': 2},
            {'name': "大转盘", 'id': 3},
            {'name': "盲盒抽奖", 'id': 4}
        ]
        
        for task in tasks:
            await self.wocare_get_draw_task(task)
            await self.wocare_load_init(task)

    async def wocare_get_token(self, ticket):
        try:
            params = {
                'channelType': SERVICE_LIFE,
                'type': '02',
                'ticket': ticket,
                'version': APP_VERSION,
                'timestamp': datetime.now().strftime("%Y%m%d%H%M%S%f")[:-3],
                'desmobile': self.mobile,
                'num': 0,
                'postage': self.random_string(32),
                'homePage': 'home',
                'duanlianjieabc': 'qAz2m',
                'userNumber': self.mobile
            }
            
            res = await self.http.request(
                'GET',
                'https://wocare.unisk.cn/mbh/getToken',
                params=params
            )
            
            if res['statusCode'] == 302:
                location = res['headers'].get('location') or res['headers'].get('Location')
                if location:
                    parsed = urlparse(location)
                    self.wocare_sid = parse_qs(parsed.query).get('sid', [''])[0]
                    if self.wocare_sid:
                        #self.logger.log(f"联通祝福获取sid成功: {self.wocare_sid[:5]}...")
                        return await self.wocare_loginmbh()
            self.logger.log("联通祝福获取sid失败")
            return False
        except Exception as e:
            self.logger.log(f"联通祝福获取sid异常: {str(e)}")
            return False

    async def wocare_loginmbh(self):
        try:
            data = {
                'sid': self.wocare_sid,
                'channelType': SERVICE_LIFE,
                'apiCode': 'loginmbh'
            }
            res = await self.wocare_api('loginmbh', data)
            
            result = res['result']
            if str(result.get('resultCode')) == '0000':
                self.wocare_token = result.get('data', {}).get('token')
                if self.wocare_token:
                    #self.logger.log(f"联通祝福登录成功, token: {self.wocare_token[:10]}...")
                    return True
                else:
                    self.logger.log(f"联通祝福登录成功但无token: {result}")
                    return False
            else:
                self.logger.log(f"联通祝福登录失败: {result}")
                return False
        except Exception as e:
            self.logger.log(f"联通祝福登录异常: {str(e)}")
            return False

    def get_wocare_body(self, api_code, data):
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")[:-3]
        msg_content = base64.b64encode(json.dumps(data, separators=(',', ':')).encode('utf-8')).decode('utf-8')
        
        body = {
            'version': MIN_RETRIES,
            'apiCode': api_code,
            'channelId': ANOTHER_API_KEY,
            'transactionId': timestamp + self.random_string(6, string.digits),
            'timeStamp': timestamp,
            'messageContent': msg_content
        }

        sorted_keys = sorted(body.keys())
        sign_str = '&'.join([f"{k}={body[k]}" for k in sorted_keys])
        sign_str += f"&sign={ANOTHER_ENCRYPTION_KEY}"
        body['sign'] = hashlib.md5(sign_str.encode('utf-8')).hexdigest()
        
        return body

    async def wocare_api(self, api_code, data):
        try:
            form_data = self.get_wocare_body(api_code, data)
            res = await self.http.request(
                'POST',
                f"https://wocare.unisk.cn/api/v1/{api_code}",
                data=form_data
            )
            
            result = res['result']
            if result.get('messageContent'):
                try:
                    import re
                    msg_content = result['messageContent']
                    msg_content = re.sub(r'[^a-zA-Z0-9+/=\-_]', '', msg_content)
                    msg_content = msg_content.replace('-', '+').replace('_', '/')
                    
                    missing_padding = len(msg_content) % 4
                    if missing_padding:
                        msg_content += '=' * (4 - missing_padding)
                        
                    decoded = base64.b64decode(msg_content).decode('utf-8')
                    parsed = json.loads(decoded)
                    
                    if 'data' in parsed:
                        result['data'] = parsed['data']
                    else:
                        result['data'] = parsed
                    
                    if parsed.get('resultMsg'):
                        result['resultMsg'] = parsed['resultMsg']
                except Exception as e:
                    # self.logger.log(f"解析messageContent异常: {str(e)}")
                    pass
            return res
        except Exception as e:
            self.logger.log(f"联通祝福API异常: {str(e)}")
            return {'result': {}}

    async def wocare_get_draw_task(self, task_info):
        try:
            data = {
                'token': self.wocare_token,
                'channelType': SERVICE_LIFE,
                'type': task_info['id'],
                'apiCode': 'getDrawTask'
            }
            res = await self.wocare_api('getDrawTask', data)
            result = res['result']
            
            if str(result.get('resultCode')) == '0000':
                task_list = result.get('data', {}).get('taskList', [])
                for task in task_list:
                    if str(task.get('taskStatus')) == '0':
                        await self.wocare_complete_task(task_info, task)
            else:
                self.logger.log(f"联通祝福[{task_info['name']}]查询任务失败: {result}")
        except Exception as e:
            self.logger.log(f"联通祝福查询任务异常: {str(e)}")

    async def wocare_complete_task(self, task_info, task, step="1"):
        try:
            action = "领取任务" if step == "1" else "完成任务"
            data = {
                'token': self.wocare_token,
                'channelType': SERVICE_LIFE,
                'task': task['id'],
                'taskStep': step,
                'type': task_info['id'],
                'apiCode': 'completeTask'
            }
            res = await self.wocare_api('completeTask', data)
            result = res['result']
            
            if str(result.get('resultCode')) == '0000':
                self.logger.log(f"{action}[{task['title']}]成功")
                if step == "1":
                    await self.wocare_complete_task(task_info, task, "4")
            else:
                self.logger.log(f"联通祝福[{task_info['name']}]{action}失败: {result}")
        except Exception as e:
            self.logger.log(f"联通祝福完成任务异常: {str(e)}")

    async def wocare_load_init(self, task_info):
        try:
            data = {
                'token': self.wocare_token,
                'channelType': SERVICE_LIFE,
                'type': task_info['id'],
                'apiCode': 'loadInit'
            }
            res = await self.wocare_api('loadInit', data)
            result = res['result']
            
            if str(result.get('resultCode')) == '0000':
                data = result.get('data', {})
                group_id = data.get('zActiveModuleGroupId')
                count = 0
                
                if task_info['id'] == 2:
                    if not data.get('data', {}).get('isPartake'):
                        count = 1
                elif task_info['id'] == 3:
                    count = int(data.get('raffleCountValue', 0))
                elif task_info['id'] == 4:
                    count = int(data.get('mhRaffleCountValue', 0))
                
                for _ in range(count):
                    await asyncio.sleep(5)
                    await self.wocare_luck_draw(task_info, group_id)
            else:
                self.logger.log(f"联通祝福[{task_info['name']}]查询活动失败: {result}")
        except Exception as e:
            self.logger.log(f"联通祝福查询活动异常: {str(e)}")

    async def wocare_luck_draw(self, task_info, group_id):
        try:
            data = {
                'token': self.wocare_token,
                'channelType': SERVICE_LIFE,
                'zActiveModuleGroupId': group_id,
                'type': task_info['id'],
                'apiCode': 'luckDraw'
            }
            res = await self.wocare_api('luckDraw', data)
            result = res['result']
            
            if str(result.get('resultCode')) == '0000':
                prize = result.get('data', {}).get('data', {}).get('prize', {})
                self.logger.log(f"联通祝福[{task_info['name']}]抽奖: {prize.get('prizeName')} [{prize.get('prizeDesc')}]", notify=True)
            else:
                self.logger.log(f"联通祝福[{task_info['name']}]抽奖失败: {result}")
        except Exception as e:
            self.logger.log(f"联通祝福抽奖异常: {str(e)}")

    # ====================  Market (权益超市)  ====================
    async def market_task(self):
        if not await self.market_login():
            return
        await self.market_share_task()  # 分享小红书任务，获取额外抽奖机会
        await self.market_watering_task()
        await self.market_raffle_task()

    async def market_login(self):
        target_url = "https://contact.bol.wo.cn/"
        ticket_info = await self.open_plat_line_new(target_url)
        if not ticket_info['ticket']:
            return False
            
        try:
            y_gdtco4r = self.random_string(500, string.ascii_letters + string.digits + '._-')
            res = await self.http.request(
                'POST',
                f'https://backward.bol.wo.cn/prod-api/auth/marketUnicomLogin?yGdtco4r={y_gdtco4r}',
                headers={
                    'Host': 'backward.bol.wo.cn',
                    'Origin': 'https://contact.bol.wo.cn',
                    'Referer': 'https://contact.bol.wo.cn/',
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                data={'ticket': ticket_info['ticket']}
            )
            
            result = res['result']
            if result and result.get('code') == 200:
                self.market_token = result.get('data', {}).get('token')
                self.logger.log("权益超市登录成功")
                return True
            else:
                self.logger.log(f"权益超市登录失败: {result}")
                return False
        except Exception as e:
            self.logger.log(f"权益超市登录异常: {str(e)}")
            return False

    async def market_share_task(self):
        """分享小红书任务，获取额外抽奖机会"""
        try:
            # 获取所有任务列表
            res = await self.http.request(
                'GET',
                'https://backward.bol.wo.cn/prod-api/promotion/activityTask/getAllActivityTasks?activityId=12',
                headers={'Authorization': f'Bearer {self.market_token}'}
            )

            result = res['result']
            if not result or result.get('code') != 200:
                self.logger.log(f"获取权益超市任务列表失败: {result}")
                return

            tasks = result.get('data', {}).get('activityTaskUserDetailVOList', [])

            # 找到分享小红书任务 (taskType=14)
            share_task = None
            for task in tasks:
                if task.get('taskType') == 14:
                    share_task = task
                    break

            if not share_task:
                return

            # 检查任务是否已完成
            triggered = share_task.get('triggeredTime', 0)
            trigger_time = share_task.get('triggerTime', 1)
            status = share_task.get('status', 0)

            if status == 1 or triggered >= trigger_time:
                return

            # 获取 param1
            param1 = share_task.get('param1')
            if not param1:
                self.logger.log("分享小红书任务 param1 为空")
                return

            # 调用 checkShare 接口完成任务
            check_res = await self.http.request(
                'POST',
                f'https://backward.bol.wo.cn/prod-api/promotion/activityTaskShare/checkShare?checkKey={param1}',
                headers={
                    'Authorization': f'Bearer {self.market_token}',
                    'Origin': 'https://contact.bol.wo.cn',
                    'Referer': 'https://contact.bol.wo.cn/',
                    'Content-Length': '0'
                },
                data=''
            )

            check_result = check_res['result']
            if not check_result or check_result.get('code') != 200:
                self.logger.log(f"分享小红书任务失败: {check_result}")
        except Exception as e:
            self.logger.log(f"分享小红书任务异常: {str(e)}")

    async def market_watering_task(self):
        try:
            y_gdtco4r = "0hHgWnaEqWi0546ZdRfTeDqJdMBnv_KnzWG6CMU_1bgJe_DjIYJ6DF2QyCn39IVIop_Tl2MtZLEma_cOOBnd3rwlPuPDGi1VtWWYtqBx07xlMOjYRpb2aAZiH1jlx_PLjqQGzoPj1AUFWj9PwC1ELJq3oEw7mi.Vql7wNyVD4unkqvNgLlHPAB4jQSgOYaStVs9LtDqXn3Uw.6UKM2k1gpbGxW.lj8Oz0sNFL2dqf7HoG_5qG2_3427RzOlc8BTQC41UZTOVZWFgIzUN_5ieBSJuEPSrITbbJjOBKfau06OimtckkiRVxQAdTBLmSGvN0Iqp5sZcyRhPnAxWP7rDP1uWG5WMdzfW44SEwjr55XfNLUS.c7rSClxax2RBT3wP.xuYSxawy1OgFrQgIGLIJQx6.7LScnfvwchuTaf.aPkn53J2iXVfb6WPxm1BjYeFvjy1v8HuPMixeh3GGJPj_7rPLIbTUcsPYLwpLcdIbYU5bMjlqaxzfdbuUQnqAEUrh5Fqq2WUkHPwHTrnehvEbvBsn.YZksQODgRjV5Oa9lcbo5dD6fbPbO2E"
            res = await self.http.request(
                'GET',
                f'https://backward.bol.wo.cn/prod-api/promotion/activityTask/getMultiCycleProcess?activityId=13&yGdtco4r={y_gdtco4r}',
                headers={'Authorization': f'Bearer {self.market_token}'}
            )
            
            result = res['result']
            if result and result.get('code') == 200:
                data = result.get('data', {})
                triggered = int(data.get('triggeredTime', 0))
                trigger_time = int(data.get('triggerTime', 1))
                self.logger.log(f"浇花状态: {triggered}/{trigger_time}")

                # 只要未完成全部次数就继续浇花
                if triggered < trigger_time:
                    await self.market_watering()
                else:
                    self.logger.log("浇花任务已全部完成")
            else:
                self.logger.log(f"获取浇花状态失败: {result}")
        except Exception as e:
            self.logger.log(f"权益超市浇花任务异常: {str(e)}")

    async def market_watering(self):
        try:
            res = await self.http.request(
                'POST',
                'https://backward.bol.wo.cn/prod-api/promotion/activityTaskShare/checkWatering',
                headers={'Authorization': f'Bearer {self.market_token}'},
                json={}
            )
            
            result = res['result']
            if result and result.get('code') == 200:
                self.logger.log("权益超市浇花成功", notify=True)
            else:
                self.logger.log(f"权益超市浇花失败: {result.get('msg', result)}")
        except Exception as e:
            self.logger.log(f"权益超市浇花异常: {str(e)}")

    async def market_validate_captcha(self):
        """人机验证"""
        try:
            res = await self.http.request(
                'POST',
                'https://backward.bol.wo.cn/prod-api/promotion/home/raffleActivity/validateCaptcha?id=12',
                headers={'Authorization': f'Bearer {self.market_token}'},
                data=''
            )

            result = res['result']
            if result and result.get('code') == 200:
                self.logger.log("权益超市: 人机验证通过，继续抽奖")
                return await self.market_raffle()
            else:
                self.logger.log(f"权益超市: 人机验证失败 {result}")
                return False
        except Exception as e:
            self.logger.log(f"权益超市人机验证异常: {str(e)}")
            return False

    async def market_raffle_task(self):
        """权益超市抽奖任务"""
        try:
            y_gdtco4r = "0QDEN3AEqWlrU036_dbyBvP8.68dggpJ9Em3UEzaRWLwzFshel7nj1kEQxCiI.B_fIDMRTiEwAgmaG93mDGPLvSObw_.EMz5QG4wZp7CfpHt4y4WwUioW5NoIaRtTpiyNJN6ncFGlF607_haxxASNFfzwkxRl9XZq9UfHhGY.UCzebcoAawBTyh62PdjF.ka.HIygQuhbb16HitF0IfX_cdZc2wVsIUfLSnSYulZaLnoSo.7..nRFnMyydrDjQE4tfOT08heVczyyR6Bpn.ZazNvmNZD1EgfxCRTcQDUdHFb_XDfPbqvX2N0dtYdKgSV_1s5u8RlyUwXr1HlqKEpKb83uWfIPLaOpm3xFnKupjRqj1UoDz.vB0iRRkkYtAd8nPoY654drckOD7GEQQs79zJyMTZV_ExNU72MAqvZRdRUZZz8oho.t6WzyX5R2pOSrPRgO84hba3Ez52DbM_08n8qRm3bW1TaviGW1VEwQVH74R_Eo0pxoZDfHTbAGC3vAAzz7R8sqLVphu972XyCB72Ba1XGElelViYqGnG3p_SZ_LzzpQMJdGSa"
            res = await self.http.request(
                'POST',
                f'https://backward.bol.wo.cn/prod-api/promotion/home/raffleActivity/getUserRaffleCount?yGdtco4r={y_gdtco4r}',
                headers={
                    'Authorization': f'Bearer {self.market_token}',
                    'Content-Length': '0'
                },
                data=''
            )

            result = res['result']
            count = 0
            if result and result.get('code') == 200:
                count = result.get('data', 0)
                self.logger.log(f"权益超市可抽奖次数: {count}")

            for i in range(count):
                await asyncio.sleep(3)
                await self.market_raffle()

            # 抽奖完成后查询奖池信息（仅展示，全局只查一次）
            if SHOW_PRIZE_POOL:
                await market_raffle_state.check_prizes(self.http, self.market_token)
        except Exception as e:
            self.logger.log(f"权益超市抽奖任务异常: {str(e)}")

    async def market_raffle(self):
        try:
            y_gdtco4r = "0rczhaAEqWhb2zAYqBszPmSenkNvPikBhEkGc5MEcyeTZhGCNS_RJHKyNyF3VUZARXyqjTIgGGgmauadjDCorC86QlFzBVqyXVjS1_YHL0dh3Kz.fDFEPcUP.E_1bREOCuXX8g0hQZ0Ix27h63PZGPeQgXabB6erqlLOku8Y34w5eALm2p0vNdaPrLm2ytWfYuBvZR3fVPQdrGnj2gIJkaOiRNaLqQNgOA3EEy6nBZs1cA74ke3uG3K2GLUGIbM6KRESorzR8Lz9HikYNRxj3cRfxj1ur2RO2wlSdY1C8ubWtosCgHPIFaw141bQlZW.mUyhEGJL3eox64bAf.Ll6VHqZYMDGAFYrWZeGhWX8HLSx626iO2tonW2mISGTgaZzS2g5AZcM7ihBBxhJfqUZ3gr6tvYWQTF7T0enm0xTW3yW986PfzxipD8rywjGRTbIrT7Nu5WYv.C5aZ03F9JJRdN5pyjYg7nl6P4kfeig8aNgPRrDlU8PfWHLrhgTprEbJNa2l4nAq6yBiELusVieHFEFWWYoCMq2ea9uIr5Q9akavKPJEfCTpQA"
            res = await self.http.request(
                'POST',
                f'https://backward.bol.wo.cn/prod-api/promotion/home/raffleActivity/userRaffle?yGdtco4r={y_gdtco4r}',
                headers={
                    'Authorization': f'Bearer {self.market_token}',
                    'Content-Length': '0'
                },
                data=''
            )
            
            result = res['result']
            if result and result.get('code') == 200:
                data = result.get('data', {})
                prize = data.get('prizesName') or '未抽中'
                message = data.get('message', '')
                if prize and prize != '未抽中':
                    self.logger.log(f"权益超市抽奖: 恭喜抽中 {prize}", notify=True)
                else:
                    self.logger.log(f"权益超市抽奖: {message or prize}")
                return True
            elif result and result.get('code') == 500:
                # 触发人机验证
                self.logger.log("权益超市: 触发人机验证，自动验证中...")
                return await self.market_validate_captcha()
            else:
                self.logger.log(f"权益超市抽奖失败: {result.get('message', result)}")
                return False
        except Exception as e:
            self.logger.log(f"权益超市抽奖异常: {str(e)}")
            return False

    # ====================  Xinjiang (xj)  ====================
    async def xj_task(self):
        if "新疆" not in self.province:
            #self.logger.log("非新疆归属地")
            return
            
        target_url = "https://zy100.xj169.com/touchpoint/openapi/jumpHandRoom1G?source=155&type=02"
        ticket_info = await self.open_plat_line_new(target_url)
        if not ticket_info['ticket']:
            return
            
        if await self.xj_get_token(ticket_info['ticket']):
            await self.xj_do_draw("Dec2025Act")

    async def xj_get_token(self, ticket):
        try:
            res = await self.http.request(
                'POST',
                'https://zy100.xj169.com/touchpoint/openapi/getTokenAndCity',
                headers={
                    'Referer': f"https://zy100.xj169.com/touchpoint/openapi/jumpHandRoom1G?source=155&type=02&ticket={ticket}",
                    'X-Requested-With': 'XMLHttpRequest',
                    'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8'
                },
                data={'ticket': ticket}
            )
            
            result = res['result']
            if result and result.get('code') == 0:
                self.xj_token = result.get('data', {}).get('token')
                return True
            else:
                self.logger.log(f"新疆联通获取Token失败: {result}")
                return False
        except Exception as e:
            self.logger.log(f"新疆联通获取Token异常: {str(e)}")
            return False

    async def xj_do_draw(self, activity_id="dakaDec2025Act"):
        try:
            prize_dict = {
                '5Gksjhjhyyk': '5G宽视界黄金会员-月卡',
                'hfq_five': '5元话费券(50-5)',
                'hfq_ten': '10元话费券(100-10)',
                'aqyhjVIPhyyk': '爱奇艺黄金VIP会员-月卡',
                'ddkc30ydjq': '滴滴快车30元代金券',
                'jdPLUShyjdnk': '京东PLUS会员京典-年卡',
                'qybbxyk': '权益百宝箱-月卡',
                'xmlyVIPhynk': '喜马拉雅VIP会员-年卡',
                'mtwmhblly': '美团外卖红包66元',
                'thanks1': '未中奖'
            }

            res = await self.http.request(
                'POST',
                'https://zy100.xj169.com/touchpoint/openapi/marchAct/draw_Dec2025Act',
                headers={
                    'userToken': self.xj_token,
                    'X-Requested-With': 'XMLHttpRequest'
                },
                data={'activityId': activity_id, 'prizeId': ''}
            )
            
            result = res['result']
            msg = result.get('msg') or result.get('data')
            
            if msg in prize_dict:
                prize_name = prize_dict[msg]
                self.logger.log(f"新疆联通[{activity_id}]抽奖结果: {prize_name}", notify=True)
            elif result and (result.get('code') == 0 or result.get('code') == 'SUCCESS'):
                self.logger.log(f"新疆联通[{activity_id}]成功: {msg}", notify=True)
            else:
                if msg and ('已经打过卡' in msg or '机会已用完' in msg):
                    self.logger.log(f"新疆联通[{activity_id}]: {msg}")
                else:
                    self.logger.log(f"新疆联通[{activity_id}]失败: {msg}")
        except Exception as e:
            self.logger.log(f"新疆联通[{activity_id}]异常: {str(e)}")

    async def xj_usersday_task(self):
        if "新疆" not in self.province:
            #self.logger.log("非新疆归属地")
            return
        target_url = "https://zy100.xj169.com/touchpoint/openapi/jumpHandRoom1G?source=166&type=02"
        ticket_info = await self.open_plat_line_new(target_url)
        if not ticket_info['ticket']:
            return
            
        if not await self.xj_get_token(ticket_info['ticket']):
            return
            
        day = datetime.now().day
        hour = datetime.now().hour
        
        if hour >= 12:
            if day == 19 or day == 20:
                await self.xj_usersday_draw("hfq_twenty")
            elif 21 <= day <= 25:
                await self.xj_usersday_draw("right_kdjdjq_ten")
            else:
                self.logger.log("联通客户日: 今日无秒杀活动")
        else:
            self.logger.log("联通客户日: 未到12点秒杀时间")

    async def xj_usersday_draw(self, prize_id):
        try:
            prize_dict = {
                'hfq_twenty': '20元话费券(100-20)',
                'right_kdjdjq_ten': '肯德基10元代金券'
            }

            res = await self.http.request(
                'POST',
                'https://zy100.xj169.com/touchpoint/openapi/marchAct/draw_UsersDay2025Act',
                headers={
                    'userToken': self.xj_token,
                    'X-Requested-With': 'XMLHttpRequest'
                },
                data={'activityId': 'usersDay2025Act', 'prizeId': prize_id}
            )
            
            result = res['result']
            if result and (result.get('code') == 0 or result.get('code') == 'SUCCESS'):
                prize_name = prize_dict.get(prize_id, prize_id)
                self.logger.log(f"客户日秒杀成功: {prize_name}", notify=True)
            else:
                self.logger.log(f"客户日秒杀失败: {result.get('data') or result.get('msg')}")
        except Exception as e:
            self.logger.log(f"客户日秒杀异常: {str(e)}")

    # ====================  Cloud Phone (云手机)  ====================

    async def wostore_cloud_task(self):
        """云手机活动: 领券、领取抽奖次数并抽奖"""
        target_url = "https://h5forphone.wostore.cn/cloudPhone/pageCLDPhone.html?channel_id=ST-Quanyi2&cp_id=91002997"
        ticket_info = await self.open_plat_line_new(target_url)
        if not ticket_info['ticket']:
            return

        # 登录获取两个 token
        tokens = await self.wostore_cloud_login(ticket_info['ticket'])
        if not tokens:
            return

        first_token, user_token = tokens

        # 1. 先领券（完成任务前置条件）
        await self.wostore_cloud_get_coupon(first_token)

        # 2. 等待后查询任务列表（触发状态同步）
        await asyncio.sleep(2)
        await self.wostore_cloud_task_list(user_token)

        # 3. 领取抽奖次数 (taskCode 010-2)
        await asyncio.sleep(1)
        await self.wostore_cloud_get_chance(user_token, "010-2")

        # 4. 执行抽奖
        await asyncio.sleep(2)
        await self.wostore_cloud_draw(user_token)

    async def wostore_cloud_login(self, ticket):
        """使用 Ticket 登录获取 Token（两步），返回 (first_token, user_token)"""
        try:
            # Step 1: 用 ticket 换取第一个 token
            url = "https://member.zlhz.wostore.cn/wcy_member/yunPhone/h5Awake/businessHall"
            data = {
                "cpId": "91002997",
                "channelId": "ST-Quanyi2",
                "ticket": ticket,
                "env": "prod",
                "transId": "4990101+底部标签-财富+499+iphone_c@12.0801",
                "qkActId": None
            }
            res = await self.http.request(
                'POST',
                url,
                json=data,
                headers={
                    'Host': 'member.zlhz.wostore.cn',
                    'Origin': 'https://h5forphone.wostore.cn',
                    'Referer': f'https://h5forphone.wostore.cn/cloudPhone/pageCLDPhone.html?channel_id=ST-Quanyi2&ticket={ticket}'
                }
            )

            result = res['result']
            if not (result and result.get('code') == '0'):
                return None

            # 从返回的 url 中提取 token
            redirect_url = result.get('data', {}).get('url', '')
            if 'token=' not in redirect_url:
                return None

            first_token = redirect_url.split('token=')[1].split('&')[0]

            # Step 2: 用 first_token 换取 user_token
            await asyncio.sleep(1)
            login_url = "https://uphone.wostore.cn/h5api/activity-service/user/login"
            login_data = {
                "identityType": "cloudPhoneLogin",
                "code": first_token,
                "channelId": "quanyishop",
                "activityId": "Lottery_2510",
                "device": "device"
            }
            res2 = await self.http.request(
                'POST',
                login_url,
                json=login_data,
                headers={
                    'Host': 'uphone.wostore.cn',
                    'Origin': 'https://uphone.wostore.cn',
                    'Referer': f'https://uphone.wostore.cn/h5/lt/October?ch=quanyishop&token={first_token}',
                    'X-USR-TOKEN': first_token
                }
            )

            result2 = res2['result']
            if result2 and result2.get('code') == 200:
                user_token = result2.get('data', {}).get('user_token')
                return (first_token, user_token)
            return None

        except:
            return None

    async def wostore_cloud_get_coupon(self, first_token):
        """领券（完成任务前置条件）"""
        try:
            url = "https://member.zlhz.wostore.cn/wcy_member/yunPhone/activity/coupon"
            data = {
                "activityId": "FREE_EQUITY_202504",
                "couponId": "3000000000658742",
                "token": first_token
            }
            await self.http.request(
                'POST',
                url,
                json=data,
                headers={
                    'Host': 'member.zlhz.wostore.cn',
                    'Origin': 'https://member.zlhz.wostore.cn',
                    'Referer': f'https://member.zlhz.wostore.cn/wcy_game_vip/cloudPhone/YHQ.html?token={first_token}'
                }
            )
        except:
            pass

    async def wostore_cloud_task_list(self, user_token):
        """查询任务列表（触发状态同步）"""
        try:
            url = "https://uphone.wostore.cn/h5api/activity-service/user/task/list"
            payload = {
                "activityCode": "Lottery_2510"
            }
            await self.http.request(
                'POST',
                url,
                json=payload,
                headers={
                    'Host': 'uphone.wostore.cn',
                    'Origin': 'https://uphone.wostore.cn',
                    'Referer': 'https://uphone.wostore.cn/h5/lt/October?ch=quanyishop',
                    'X-USR-TOKEN': user_token
                }
            )
        except:
            pass

    async def wostore_cloud_get_chance(self, user_token, task_code):
        """领取抽奖次数"""
        try:
            url = "https://uphone.wostore.cn/h5api/activity-service/user/task/raffle/get"
            payload = {
                "activityCode": "Lottery_2510",
                "taskCode": task_code
            }
            await self.http.request(
                'POST',
                url,
                json=payload,
                headers={
                    'Host': 'uphone.wostore.cn',
                    'Origin': 'https://uphone.wostore.cn',
                    'Referer': 'https://uphone.wostore.cn/h5/lt/October?ch=quanyishop',
                    'X-USR-TOKEN': user_token
                }
            )
        except:
            pass

    async def wostore_cloud_draw(self, user_token):
        """执行抽奖"""
        try:
            url = "https://uphone.wostore.cn/h5api/activity-service/lottery"
            payload = {
                "activityCode": "Lottery_2510"
            }

            res = await self.http.request(
                'POST',
                url,
                json=payload,
                headers={
                    'Host': 'uphone.wostore.cn',
                    'Origin': 'https://uphone.wostore.cn',
                    'Referer': 'https://uphone.wostore.cn/h5/lt/October?ch=quanyishop',
                    'X-USR-TOKEN': user_token
                }
            )

            result = res['result']
            if result and result.get('code') == 200:
                prize_name = result.get('prizeName', '未中奖')
                self.logger.log(f"云手机抽奖: {prize_name}", notify=True)
            elif result:
                # 抽奖失败也显示日志
                msg = result.get('msg') or result.get('message') or result.get('data') or str(result)
                self.logger.log(f"云手机抽奖失败: {msg}")
        except Exception as e:
            self.logger.log(f"云手机抽奖异常: {str(e)}")

    # ====================  ShangDu (商都月度福利)  ====================

    async def shangdu_task(self):
        if "河南" not in self.province:
            return
        ticket = await self.shangdu_get_ticket()
        if not ticket:
            return

        if await self.shangdu_login(ticket):
            await asyncio.sleep(1)
            await self.shangdu_signin()

    async def shangdu_get_ticket(self):
        if not getattr(self, 'ecs_token', None):
            self.logger.log("商都福利: 缺少 ecs_token，请检查是否已执行 online 登录")
            return None
            
        app_id = "edop_unicom_4b80047a" 
        try:
            res = await self.http.request(
                'GET',
                'https://m.client.10010.com/edop_ng/getTicketByNative',
                params={
                    'token': self.ecs_token,
                    'appId': app_id
                }
            )   
            result = res['result']
            if isinstance(result, dict) and result.get('rsp_code') == '0000':
                ticket = result.get('ticket')
                return ticket
            else:
                self.logger.log(f"商都福利: Ticket 获取失败 {result}")
                return None
        except Exception as e:
            self.logger.log(f"商都福利获取Ticket异常: {str(e)}")
            return None

    async def shangdu_login(self, ticket):
        try:
            url = f"https://app.shangdu.com/monthlyBenefit/v1/common/config?ticket={ticket}"

            res = await self.http.request(
                'GET',
                url,
                headers={
                    'Host': 'app.shangdu.com',
                    'Origin': 'https://app.shangdu.com',
                    'Referer': 'https://app.shangdu.com/monthlyBenefit/index.html',
                    'edop_flag': '0',
                    'Accept': 'application/json, text/plain, */*'
                }
            )

            result = res['result']
            if isinstance(result, dict) and result.get('code') == '0000':
                # self.logger.log("商都福利: 登录激活成功")
                return True
            else:
                self.logger.log(f"商都福利: 登录激活失败 {result}")
                return False

        except Exception as e:
            self.logger.log(f"商都福利登录异常: {str(e)}")
            return False

    async def shangdu_get_sign_status(self):
        """查询今日签到状态"""
        try:
            res = await self.http.request(
                'POST',
                'https://app.shangdu.com/monthlyBenefit/v1/signIn/queryCumulativeSignAxis',
                headers={
                    'Host': 'app.shangdu.com',
                    'Origin': 'https://app.shangdu.com',
                    'Referer': 'https://app.shangdu.com/monthlyBenefit/index.html',
                    'edop_flag': '0',
                    'Content-Type': 'application/json'
                },
                json={}
            )
            result = res['result']
            if isinstance(result, dict) and result.get('code') == '0000':
                data = result.get('data', {})
                # todaySignFlag: '1' = 已签到, '0' = 未签到
                return data.get('todaySignFlag') == '1'
            return None  # 查询失败，状态未知
        except:
            return None

    async def shangdu_signin(self):
        try:
            res = await self.http.request(
                'POST',
                'https://app.shangdu.com/monthlyBenefit/v1/signIn/userSignIn',
                headers={
                    'Host': 'app.shangdu.com',
                    'Origin': 'https://app.shangdu.com',
                    'Referer': 'https://app.shangdu.com/monthlyBenefit/index.html',
                    'edop_flag': '0',
                    'X-Requested-With': 'XMLHttpRequest',
                    'Content-Type': 'application/json'
                },
                json={}
            )

            result = res['result']
            if isinstance(result, dict):
                code = result.get('code')

                if code == '0000':
                    data = result.get('data', {})
                    if data.get('value') == '0001':
                        self.logger.log("商都福利: 签到失败 (Cookie无效/未登录)")
                        return

                    sign_flag = str(data.get('signFlag', ''))
                    prize_resp = data.get('prizeResp', {})
                    prize_name = prize_resp.get('prizeName') if prize_resp else ""

                    if sign_flag == '1':
                        if prize_name:
                            self.logger.log(f"商都福利签到成功: 获得 {prize_name}", notify=True)
                        else:
                            self.logger.log("商都福利: 今日已签到")
                    else:
                        self.logger.log(f"商都福利签到成功 (signFlag={sign_flag})")

                elif code == '0019':
                    # 服务端返回重复签到，查询实际状态确认
                    await asyncio.sleep(1)
                    is_signed = await self.shangdu_get_sign_status()
                    if is_signed is True:
                        self.logger.log("商都福利: 今日已签到")
                    elif is_signed is False:
                        # 状态显示未签到，但返回重复签到，尝试重试一次
                        self.logger.log("商都福利: 服务端异常(返回重复签到但实际未签)，尝试重试...")
                        await asyncio.sleep(2)
                        await self._shangdu_signin_retry()
                    else:
                        self.logger.log("商都福利: 今日已签到 (状态查询失败)")
                else:
                    msg = result.get('msg') or result.get('desc') or ''
                    self.logger.log(f"商都福利签到失败: {msg} (code={code})")

        except Exception as e:
            self.logger.log(f"商都福利签到异常: {str(e)}")

    async def _shangdu_signin_retry(self):
        """签到重试（仅内部调用）"""
        try:
            res = await self.http.request(
                'POST',
                'https://app.shangdu.com/monthlyBenefit/v1/signIn/userSignIn',
                headers={
                    'Host': 'app.shangdu.com',
                    'Origin': 'https://app.shangdu.com',
                    'Referer': 'https://app.shangdu.com/monthlyBenefit/index.html',
                    'edop_flag': '0',
                    'X-Requested-With': 'XMLHttpRequest',
                    'Content-Type': 'application/json'
                },
                json={}
            )
            result = res['result']
            if isinstance(result, dict):
                code = result.get('code')
                if code == '0000':
                    data = result.get('data', {})
                    prize_resp = data.get('prizeResp', {})
                    prize_name = prize_resp.get('prizeName') if prize_resp else ""
                    if prize_name:
                        self.logger.log(f"商都福利签到成功(重试): 获得 {prize_name}", notify=True)
                    else:
                        self.logger.log("商都福利签到成功(重试)")
                elif code == '0019':
                    self.logger.log("商都福利: 重试仍返回重复签到，请检查")
                else:
                    msg = result.get('msg') or result.get('desc') or ''
                    self.logger.log(f"商都福利签到重试失败: {msg}")
        except Exception as e:
            self.logger.log(f"商都福利签到重试异常: {str(e)}")

    async def user_task(self):
        #self.logger.log(f"\n------------------ 账号 {self.mobile} ------------------")
        if not await self.online():
            return
            
        await self.sign_task()
        await self.ttlxj_task()
        await self.ltzf_task()
        await self.market_task()
        await self.xj_task()
        await self.xj_usersday_task()
        await self.wostore_cloud_task()
        await self.shangdu_task()

async def main():
    start_time = datetime.now()
    print(f"开始运行时间: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    cookies = os.environ.get("chinaUnicomCookie", "")
    if not cookies:
        print("未找到 chinaUnicomCookie 环境变量")
        return 
    
    tasks = []
    for i, cookie in enumerate(cookies.split('@')):
        if not cookie.strip():
            continue
        user = CustomUserService(cookie, index=i+1)
        tasks.append(user.user_task())
    
    if tasks:
        print(f"启动 {len(tasks)} 个账号任务 (并行模式)...")
        await asyncio.gather(*tasks)

    end_time = datetime.now()
    duration = end_time - start_time
    print(f"\n运行结束, 总用时: {duration}")

if __name__ == "__main__":
    asyncio.run(main())
