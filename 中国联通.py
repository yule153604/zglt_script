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

# ====================  Constants  ====================
APP_VERSION = "iphone_c@11.0503"
USER_AGENT = f"Mozilla/5.0 (iPhone; CPU iPhone OS 16_1_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 unicom{{version:{APP_VERSION}}}"
APP_ID = "86b8be06f56ba55e9fa7dff134c6b16c62ca7f319da4a958dd0afa0bf9f36f1daa9922869a8d2313b6f2f9f3b57f2901f0021c4575e4b6949ae18b7f6761d465c12321788dcd980aa1a641789d1188bb"
CLIENT_ID = "73b138fd-250c-4126-94e2-48cbcc8b9cbe"
CLIENT_ID_2 = "1001000003"
ANOTHER_API_KEY = "beea1c7edf7c4989b2d3621c4255132f"
ANOTHER_ENCRYPTION_KEY = "f4cd4ffeb5554586acf65ba7110534f5"
SERVICE_LIFE = "wocareMBHServiceLife1"
MIN_RETRIES = "1"

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

class CustomUserService:
    def __init__(self, cookie, index=1):
        self.cookie = cookie
        self.index = index
        self.logger = Logger(prefix=f"账号{index}")
        self.http = HttpClient(self.logger)
        self.token_online = cookie.split('#')[0]
        self.valid = False
        self.mobile = ""
        self.app_id = APP_ID
        self.app_version = APP_VERSION
        
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
                'deviceId': device_id,
                'deviceCode': device_code,
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
                triggered = data.get('triggeredTime', 0)
                self.logger.log(f"浇花状态: {triggered}/{data.get('triggerTime')}")
                
                if triggered == 0:
                    await self.market_watering()
                else:
                    self.logger.log("今日已完成浇花")
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
                self.logger.log(f"权益超市浇花失败: {result}")
        except Exception as e:
            self.logger.log(f"权益超市浇花异常: {str(e)}")

    async def market_raffle_task(self):
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
                prize = result.get('data', {}).get('prizesName') or '未抽中'
                self.logger.log(f"权益超市抽奖: {prize}", notify=True)
            else:
                self.logger.log(f"权益超市抽奖失败: {result}")
        except Exception as e:
            self.logger.log(f"权益超市抽奖异常: {str(e)}")

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

    # ====================  Nine Grid (九宫格)  ====================
    async def nine_grid_draw(self):
        try:
            current_ac_id = "AC20251202153959"
            payload = {
                "from": "ZXGS97000018441",
                "acId": current_ac_id,
                "reqSeq": self.random_string(32).lower(),
                "imei": self.unicom_token_id.upper()
            }
            count = await self.nine_grid_check_count(payload)
            if count <= 0:
                self.logger.log("积分抽奖: 今日机会已用完")
                return
            res = await self.http.request(
                'POST',
                'https://m.client.10010.com/welfare-mall-front/ninePalaceGrid/luckyDraw/v1',
                headers={
                    'Origin': 'https://img.client.10010.com',
                    'Referer': 'https://img.client.10010.com/',
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                data={'params': json.dumps(payload)}
            )
            
            result = res['result']
            if result and str(result.get('code')) == '0':
                await asyncio.sleep(1.5)
                await self.nine_grid_check_win(payload)
            else:
                self.logger.log(f"积分抽奖失败: {result.get('msg')}")
        except Exception as e:
            self.logger.log(f"积分抽奖异常: {str(e)}")

    async def nine_grid_check_count(self, payload):
        try:
            res = await self.http.request(
                'POST',
                'https://m.client.10010.com/welfare-mall-front/ninePalaceGrid/findLotteryCount/v1',
                headers={
                    'Origin': 'https://img.client.10010.com',
                    'Referer': 'https://img.client.10010.com/',
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                data={'params': json.dumps({'from': payload['from'], 'acId': payload['acId']})}
            )
            
            result = res['result']
            if result and str(result.get('code')) == '0':
                return int(result.get('resdata', {}).get('drawCount', 0))
            return 0
        except:
            return 0

    async def nine_grid_check_win(self, payload):
        try:
            res = await self.http.request(
                'POST',
                'https://m.client.10010.com/welfare-mall-front/ninePalaceGrid/findWinInfo/v1',
                headers={
                    'Origin': 'https://img.client.10010.com',
                    'Referer': 'https://img.client.10010.com/',
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                data={'params': json.dumps(payload)}
            )
            
            result = res['result']
            if result and str(result.get('code')) == '0':
                data = result.get('resdata', {})
                prize = data.get('prizeName', '未中奖')
                if data.get('isWin'):
                    self.logger.log(f"积分抽奖结果: 获得 {prize}", notify=True)
                else:
                    self.logger.log("积分抽奖结果: 未中奖")
        except:
            pass
    # ====================  ShangDu (商都月度福利)  ====================
    
    async def shangdu_task(self):
        if "河南" not in self.province:
            return
        ticket = await self.shangdu_get_ticket()
        if not ticket:
            return

        if await self.shangdu_login(ticket):
            await asyncio.sleep(2)
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
                json={} # 空 JSON 对象
            )
            
            result = res['result']
            if isinstance(result, dict) and result.get('code') == '0000':
                data = result.get('data', {})
                if data.get('value') == '0001':
                    self.logger.log("商都福利: 签到失败 (Cookie无效/未登录)")
                    return

                sign_flag = str(data.get('signFlag'))
                prize_resp = data.get('prizeResp', {})
                prize_name = prize_resp.get('prizeName') if prize_resp else ""
                if not prize_name:
                    prize_name = "未抽中"
                
                if sign_flag == '1':
                    self.logger.log(f"商都福利签到成功: 获得 {prize_name}", notify=True)
                else:
                    self.logger.log(f"商都福利: 签到请求完成 (可能今日已签) {prize_name}")
            else:
                msg = result.get('msg') or result.get('desc') or '未知错误'
                self.logger.log(f"商都福利签到失败: {msg}")
                
        except Exception as e:
            self.logger.log(f"商都福利签到异常: {str(e)}")

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
        await self.nine_grid_draw()
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
