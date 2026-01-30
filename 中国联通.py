# -*- coding: utf-8 -*-
"""
仅供学习交流：本项目仅供编程学习和技术交流使用，请勿用于任何商业用途。
合法使用：请勿将本脚本用于任何非法目的，包括但不限于恶意攻击、刷单等行为。
风险自担：使用本脚本产生的任何后果（包括但不限于账号封禁、财产损失等）由使用者自行承担，开发者不承担任何责任。
隐私保护：本项目不会收集用户的任何敏感信息，所有数据均保存在用户本地。
侵权联系：如果本项目侵犯了您的权益，请及时联系开发者进行处理。
"""

import asyncio, base64, hashlib, json, os, random, string, time
from datetime import datetime
from functools import wraps
from urllib.parse import parse_qs, unquote, urlparse

import httpx
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ====================  Decorators  ====================
def async_task(task_name=None):
    def decorator(func):
        @wraps(func)
        async def wrapper(self, *args, **kwargs):
            try: return await func(self, *args, **kwargs)
            except Exception as e: self.logger.log(f"{task_name or func.__name__.replace('_', ' ').strip()}异常: {e}")
        return wrapper
    return decorator

def async_task_silent(func):
    """静默异步任务装饰器：只捕获异常不记录"""
    @wraps(func)
    async def wrapper(self, *args, **kwargs):
        try:
            return await func(self, *args, **kwargs)
        except Exception:
            pass
    return wrapper

def _sec_headers(self):
    t, c = unquote(self.sec_ticket) if self.sec_ticket else "", f"_jea_id={self.sec_jea_id}" if self.sec_jea_id else ""
    return {"ticket": t, "Cookie": c, "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15", "partnersid": "1702", "clienttype": "uasp_unicom_applet", "Content-Type": "application/json"}

# ====================  Constants  ====================
APP_VERSION, SHOW_PRIZE_POOL = "iphone_c@11.0503", True
USER_AGENT = lambda v: f"Mozilla/5.0 (iPhone; CPU iPhone OS 16_1_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 unicom{{version:{v}}}"
APP_ID = "86b8be06f56ba55e9fa7dff134c6b16c62ca7f319da4a958dd0afa0bf9f36f1daa9922869a8d2313b6f2f9f3b57f2901f0021c4575e4b6949ae18b7f6761d465c12321788dcd980aa1a641789d1188bb"
CLIENT_ID = "73b138fd-250c-4126-94e2-48cbcc8b9cbe"
WOREAD_PRODUCT_ID, WOREAD_SECRET_KEY, WOREAD_PASSWORD, WOREAD_IV = "10000002", "7k1HcDL8RKvc", "woreadst^&*12345", "16-Bytes--String"
WOCARE_CHANNEL_ID, WOCARE_SIGN_KEY, WOCARE_CHANNEL_TYPE, WOCARE_VERSION = "beea1c7edf7c4989b2d3621c4255132f", "f4cd4ffeb5554586acf65ba7110534f5", "wocareMBHServiceLife1", "1"
AITING_BASE_URL, AITING_SIGN_KEY_APPKEY, AITING_SIGN_KEY_API = "https://pcc.woread.com.cn", "7ZxQ9rT3wE5sB2dF", "woread!@#qwe1234"
AITING_SIGN_KEY_REQUERTID, AITING_CLIENT_KEY, AITING_AES_KEY, AITING_AES_IV = "46iCw24ewAZbNkK6", "1", "j2K81755sxV12wFx", "16-Bytes--String"
ADDREADTIME_AES_KEY = "UNS#READDAY39COM"
EXCHANGE_COUPON_CONFIG = {"1元话费券": False, "3元话费券": False, "5元话费券": True, "10元话费券": True, "18元话费券": False}
COUPON_PRODUCT_MAP = {k: v for k, v in zip(EXCHANGE_COUPON_CONFIG.keys(), ["25122309441216995", "25122309482612026", "25122309512816188", "25122309543215732", "25122310293512803"])}
COUPON_POINTS_REQUIRED = {k: int(k.split("元")[0]) * 100 for k in EXCHANGE_COUPON_CONFIG}

# ====================  Utils  ====================
_print_lock = asyncio.Lock()
get_display_width = lambda s: sum(2 if ord(c) > 127 else 1 for c in s)
pad_to_width = lambda s, w: s + " " * max(0, w - get_display_width(s))

class Logger:
    def __init__(self, prefix=""): self.prefix = prefix
    def log(self, message, notify=False):
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] [{self.prefix}] {message}" if self.prefix else f"[{ts}] {message}", flush=True)
    async def log_async(self, message, notify=False):
        async with _print_lock: self.log(message, notify)

class HttpClient:
    def __init__(self, logger_instance):
        self.logger, self.headers, self.cookies, self.timeout, self.retries = logger_instance, {"User-Agent": USER_AGENT(APP_VERSION), "Connection": "keep-alive"}, httpx.Cookies(), 50.0, 3
    async def request(self, method, url, **kwargs):
        headers = {**self.headers, **kwargs.pop("headers", {})}
        cookies = kwargs.pop("cookies", self.cookies)
        for attempt in range(self.retries):
            try:
                async with httpx.AsyncClient(cookies=cookies, http2=False, follow_redirects=False, timeout=self.timeout, verify=False) as client:
                    response = await client.request(method, url, headers=headers, **kwargs)
                    self.cookies.update(response.cookies)
                    text = response.text
                    if text.strip().startswith(("{", "[")):
                        try: result = response.json()
                        except Exception: result = text
                    else: result = text
                    return {"statusCode": response.status_code, "headers": response.headers, "result": result}
            except Exception: await asyncio.sleep(1 + attempt * 2)
        return {"statusCode": -1, "headers": {}, "result": None}
    get = lambda self, url, **kw: self.request("GET", url, **kw)
    post = lambda self, url, **kw: self.request("POST", url, **kw)

class MarketEncrypt:
    KEY = "AB1BLc3Ak1yvClgT"

    @classmethod
    def decrypt(cls, text):
        if not text or isinstance(text, dict): return text
        try: return json.loads(text)
        except: pass
        try:
            cipher = AES.new(cls.KEY.encode(), AES.MODE_ECB)
            return json.loads(unpad(cipher.decrypt(base64.b64decode(text)), AES.block_size).decode())
        except: return text

    @classmethod
    def encrypt(cls, data):
        if not data: return data
        try:
            text = json.dumps(data, separators=(",", ":")) if isinstance(data, (dict, list)) else str(data)
            cipher = AES.new(cls.KEY.encode(), AES.MODE_ECB)
            return base64.b64encode(cipher.encrypt(pad(text.encode(), AES.block_size))).decode()
        except: return data

class MarketRaffleState:
    def __init__(self): self.checked, self.has_prizes, self.prizes, self.lock = False, False, [], asyncio.Lock()
    async def check_prizes(self, http_client, market_token):
        async with self.lock:
            if self.checked: return self.has_prizes
            print("\n" + "=" * 70 + "\n权益超市奖品池查询\n" + "=" * 70)
            try:
                res = await http_client.request("POST", "https://backward.bol.wo.cn/prod-api/promotion/home/raffleActivity/prizeList?id=12", headers={"Authorization": f"Bearer {market_token}"}, json={})
                result = res["result"]
                if result and result.get("code") == 200 and isinstance(result.get("data"), list):
                    self.prizes = result["data"]
                    available_prizes = [p for p in self.prizes if (lambda p: float(p.get("probability", 0)) > 0 or float(p.get("probabilityVip", 0)) > 0 or float(p.get("newVipProbability", 0)) > 0)(p)]
                    print(f"今日奖池共 {len(available_prizes)} 个奖品:\n")
                    print(f"{pad_to_width('奖品名称', 36)} {'普通':>6} {'VIP':>6} {'新会员':>6} {'Limit':>6}")
                    print("-" * 70)
                    for prize in available_prizes:
                        name = prize.get("name", "未知")
                        if get_display_width(name) > 34:
                            while get_display_width(name) > 32: name = name[:-1]
                            name = name + ".."
                        prob, prob_vip, prob_new = float(prize.get("probability", 0)), float(prize.get("probabilityVip", 0)), float(prize.get("newVipProbability", 0))
                        daily_limit = int(prize.get("dailyPrizeLimit", 0))
                        print(f"{pad_to_width(name, 36)} {prob * 100:>5.0f}% {prob_vip * 100:>5.0f}% {prob_new * 100:>5.0f}% {daily_limit:>6}")
                    print("=" * 70 + "\n")
                    self.has_prizes = len(available_prizes) > 0
                else: print(f"奖品池查询失败: {result}")
            except Exception as e: print(f"奖品池查询异常: {str(e)}")
            self.checked = True
            return self.has_prizes

market_raffle_state = MarketRaffleState()

class CustomUserService:
    def __init__(self, cookie, index=1):
        self.cookie, self.index = cookie, index
        self.logger = Logger(prefix=f"账号{index}")
        self.http = HttpClient(self.logger)
        self.valid, self.mobile, self.province = False, "", ""
        self.app_version, self.token_online, self.app_id = APP_VERSION, cookie.strip(), APP_ID
        self.unicom_token_id = "".join(random.choices(string.ascii_letters + string.digits, k=32))
        self.token_id_cookie = "chinaunicom-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=32))
        self.sdkuuid = self.unicom_token_id
        self.random_string = lambda n, c=string.ascii_letters + string.digits: "".join(random.choices(c, k=n))
        for name, val in [("TOKENID_COOKIE", self.token_id_cookie), ("UNICOM_TOKENID", self.unicom_token_id), ("sdkuuid", self.sdkuuid)]:
            self.http.cookies.set(name, val, domain=".10010.com")
        self.rpt_id = self.market_token = self.xj_token = self.wocare_token = self.wocare_sid = self.ecs_token = ""
        self.initial_telephone_amount = 0.0

    get_bizchannelinfo = lambda self: json.dumps({"bizChannelCode": "225", "disriBiz": "party", "unionSessionId": "", "stType": "", "stDesmobile": "", "source": "", "rptId": self.rpt_id, "ticket": "", "tongdunTokenId": self.token_id_cookie, "xindunTokenId": self.sdkuuid})
    get_epay_authinfo = lambda self: json.dumps({"mobile": "", "sessionId": getattr(self, "session_id", ""), "tokenId": getattr(self, "token_id", ""), "userId": ""})

    @async_task("登录")
    async def online(self):
        data = {"token_online": self.token_online, "reqtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "appId": self.app_id, "version": self.app_version, "step": "bindlist", "isFirstInstall": 0, "deviceModel": "iPhone14,6", "deviceOS": "16.6", "deviceBrand": "iPhone", "uniqueIdentifier": "ios" + self.random_string(32, "0123456789abcdef"), "simOperator": "--,--,65535,65535,--@--,--,65535,65535,--", "voipToken": "citc-default-token-do-not-push"}
        res = await self.http.post("https://m.client.10010.com/mobileService/onLine.htm", data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
        if (result := res["result"]) and str(result.get("code")) == "0":
            self.valid, self.mobile, self.ecs_token, self.province = True, result.get("desmobile", ""), result.get("ecs_token", ""), (result.get("list") or [{}])[0].get("proName", "")
            masked = f"{self.mobile[:3]}****{self.mobile[-4:]}" if len(self.mobile) >= 11 else self.mobile
            self.logger.log(f"登录成功: {masked} (归属地: {self.province})")
            return True
        self.logger.log(f"登录失败: {result}")
        return False

    @async_task("获取ticket")
    async def open_plat_line_new(self, url):
        res = await self.http.get("https://m.client.10010.com/mobileService/openPlatform/openPlatLineNew.htm", params={"to_url": url})
        if location := (res["headers"].get("location") or res["headers"].get("Location")):
            qs = parse_qs(urlparse(location).query)
            return {"ticket": qs.get("ticket", [""])[0], "type": qs.get("type", ["02"])[0], "loc": location}
        self.logger.log("获取ticket失败: 无location")
        return {"ticket": "", "type": "", "loc": ""}

    async def sign_task(self):
        await self.sign_get_continuous()
        await self.sign_get_telephone(is_initial=True)
        await self.sign_task_center()
        await self.sign_get_telephone(is_initial=False)
        await self.sign_coupon_exchange()

    @async_task("签到区查询话费红包")
    async def sign_get_telephone(self, is_initial=False):
        res = await self.http.post("https://act.10010.com/SigninApp/convert/getTelephone", data={}, headers={"Referer": "https://img.client.10010.com/"})
        if (result := res["result"]) and str(result.get("status")) == "0000" and (data := result.get("data")):
            telephone = data.get("telephone") or "0"
            if telephone == "--": telephone = "0"
            current = float(telephone)
            if is_initial: self.initial_telephone_amount = current; return
            increase = current - self.initial_telephone_amount
            msg = f"签到区-话费红包: 总额 {current:.2f}元，本次增加 {increase:.2f}元"
            needexp = data.get("needexpNumber") or "0"
            if needexp == "--": needexp = "0"
            if (need_exp := float(needexp)) > 0: msg += f",其中 {need_exp}元 将于 {data.get('month')}月底到期"
            self.logger.log(msg, notify=True)
        else: self.logger.log(f"签到区查询话费红包失败: {result.get('msg') if result else ''}")

    @async_task("查询签到状态")
    async def sign_get_continuous(self):
        res = await self.http.get("https://activity.10010.com/sixPalaceGridTurntableLottery/signin/getContinuous", params={"taskId": "", "channel": "wode", "imei": "BB97982E-3F03-46D3-B904-819D626DF478"})
        if (result := res["result"]) and str(result.get("code")) == "0000":
            signed = result.get("data", {}).get("todayIsSignIn", "n") != "n"
            self.logger.log(f"签到状态: {'已签到' if signed else '未签到'}")
            if not signed: await asyncio.sleep(1); await self.sign_day_sign()
        else: self.logger.log(f"查询签到状态失败: {result}")

    @async_task("签到")
    async def sign_day_sign(self):
        res = await self.http.post("https://activity.10010.com/sixPalaceGridTurntableLottery/signin/daySign", data={})
        if (result := res["result"]) and str(result.get("code")) == "0000":
            data = result.get("data", {})
            self.logger.log(f"签到成功: {data.get('statusDesc', '')} {data.get('redSignMessage', '')}", notify=True)
        elif str(result.get("code")) == "0002" and "已经签到" in result.get("desc", ""): self.logger.log("签到成功: 今日已完成签到", notify=True)
        else: self.logger.log(f"签到失败: {result}")

    async def ttlxj_task(self):
        self.rpt_id = ""
        if (ticket_info := await self.open_plat_line_new("https://epay.10010.com/ci-mps-st-web/?webViewNavIsHidden=webViewNavIsHidden"))["ticket"]:
            await self.ttlxj_authorize(ticket_info["ticket"], ticket_info["type"], ticket_info["loc"])

    @async_task("天天领现金授权")
    async def ttlxj_authorize(self, ticket, st_type, referer):
        data = {"response_type": "rptid", "client_id": CLIENT_ID, "redirect_uri": "https://epay.10010.com/ci-mps-st-web/", "login_hint": {"credential_type": "st_ticket", "credential": ticket, "st_type": st_type, "force_logout": True, "source": "app_sjyyt"}, "device_info": {"token_id": f"chinaunicom-pro-{int(time.time() * 1000)}-{self.random_string(13)}", "trace_id": self.random_string(32)}}
        res = await self.http.post("https://epay.10010.com/woauth2/v2/authorize", headers={"Origin": "https://epay.10010.com", "Referer": referer}, json=data)
        if res["statusCode"] == 200: await self.ttlxj_auth_check()
        else: self.logger.log(f"天天领现金授权失败: {res['result']}")

    @async_task("天天领现金认证")
    async def ttlxj_auth_check(self):
        res = await self.http.post("https://epay.10010.com/ps-pafs-auth-front/v1/auth/check", headers={"bizchannelinfo": self.get_bizchannelinfo()})
        result = res["result"]
        if str(result.get("code")) == "0000":
            auth = result.get("data", {}).get("authInfo", {})
            self.session_id, self.token_id = auth.get("sessionId"), auth.get("tokenId")
            await self.ttlxj_user_draw_info()
            await self.ttlxj_query_available()
        elif str(result.get("code")) == "2101000100": await self.ttlxj_login(result.get("data", {}).get("woauth_login_url"))
        else: self.logger.log(f"天天领现金认证失败: {result}")

    @async_task("天天领现金登录")
    async def ttlxj_login(self, login_url):
        res = await self.http.get(f"{login_url}https://epay.10010.com/ci-mcss-party-web/clockIn/?bizFrom=225&bizChannelCode=225&channelType=WDQB")
        if location := (res["headers"].get("location") or res["headers"].get("Location")):
            rpt_id = parse_qs(urlparse(location).query).get("rptid", [""])[0]
            if rpt_id: self.rpt_id = rpt_id; await self.ttlxj_auth_check()
            else: self.logger.log("天天领现金获取rptid失败")
        else: self.logger.log("天天领现金获取rptid失败: 无location")

    @async_task("天天领现金查询")
    async def ttlxj_user_draw_info(self):
        res = await self.http.post("https://epay.10010.com/ci-mcss-party-front/v1/ttlxj/userDrawInfo", headers={"bizchannelinfo": self.get_bizchannelinfo(), "authinfo": self.get_epay_authinfo()})
        if (result := res["result"]) and str(result.get("code")) == "0000":
            data = result.get("data", {})
            day_key = f"day{data.get('dayOfWeek')}"
            not_clocked = data.get(day_key) == "1"
            self.logger.log(f"天天领现金今天{'未' if not_clocked else '已'}打卡", notify=True)
            if not_clocked:
                draw_type = "C" if (datetime.now().weekday() + 1) % 7 == 0 else "B"
                await self.ttlxj_unify_draw_new(draw_type)
        else: self.logger.log(f"天天领现金查询失败: {result}")

    @async_task("天天领现金打卡")
    async def ttlxj_unify_draw_new(self, draw_type):
        res = await self.http.post("https://epay.10010.com/ci-mcss-party-front/v1/ttlxj/unifyDrawNew", headers={"bizchannelinfo": self.get_bizchannelinfo(), "authinfo": self.get_epay_authinfo()}, data={"drawType": draw_type, "bizFrom": "225", "activityId": "TTLXJ20210330"})
        if (result := res["result"]) and str(result.get("code")) == "0000" and str(result.get("data", {}).get("returnCode")) == "0":
            amount = result["data"].get("amount")
            msg = result["data"].get("awardTipContent", "").replace("xx", str(amount))
            self.logger.log(f"天天领现金打卡: {msg}", notify=True)
        else: self.logger.log(f"天天领现金打卡失败: {result}")

    @async_task("天天领现金查询余额")
    async def ttlxj_query_available(self):
        res = await self.http.post("https://epay.10010.com/ci-mcss-party-front/v1/ttlxj/queryAvailable", headers={"bizchannelinfo": self.get_bizchannelinfo(), "authinfo": self.get_epay_authinfo()})
        if (result := res["result"]) and str(result.get("code")) == "0000" and str(result.get("data", {}).get("returnCode")) == "0":
            self.logger.log(f"可用立减金: {float(result['data'].get('availableAmount', 0)) / 100:.2f}元", notify=True)
        else: self.logger.log(f"天天领现金查询余额失败: {result}")

    async def ltzf_task(self):
        target_url = f"https://wocare.unisk.cn/mbh/getToken?channelType={WOCARE_CHANNEL_TYPE}&homePage=home&duanlianjieabc=qAz2m"
        if not (ticket_info := await self.open_plat_line_new(target_url))["ticket"]: return
        if not await self.wocare_get_token(ticket_info["ticket"]): return
        for task in [{"name": "星座配对", "id": 2}, {"name": "大转盘", "id": 3}, {"name": "盲盒抽奖", "id": 4}]: await self.wocare_get_draw_task(task); await self.wocare_load_init(task)

    @async_task("联通祝福获取sid")
    async def wocare_get_token(self, ticket):
        params = {k: v for k, v in [("channelType", WOCARE_CHANNEL_TYPE), ("type", "02"), ("ticket", ticket), ("version", APP_VERSION), ("timestamp", datetime.now().strftime("%Y%m%d%H%M%S%f")[:-3]), ("desmobile", self.mobile), ("num", 0), ("postage", self.random_string(32)), ("homePage", "home"), ("duanlianjieabc", "qAz2m"), ("userNumber", self.mobile)]}
        res = await self.http.get("https://wocare.unisk.cn/mbh/getToken", params=params)
        if res["statusCode"] == 302 and (loc := res["headers"].get("location") or res["headers"].get("Location")):
            sid = parse_qs(urlparse(loc).query).get("sid", [""])[0]
            if sid: self.wocare_sid = sid; return await self.wocare_loginmbh()
        self.logger.log("联通祝福获取sid失败"); return False

    @async_task("联通祝福登录")
    async def wocare_loginmbh(self):
        res = await self.wocare_api("loginmbh", {"sid": self.wocare_sid, "channelType": WOCARE_CHANNEL_TYPE, "apiCode": "loginmbh"})
        if (result := res["result"]) and str(result.get("resultCode")) == "0000":
            token = result.get("data", {}).get("token")
            if token:
                self.wocare_token = token
                return True
            self.logger.log(f"联通祝福登录成功但无token: {result}")
        else: self.logger.log(f"联通祝福登录失败: {result}")
        return False

    def get_wocare_body(self, api_code, data):
        ts = datetime.now().strftime("%Y%m%d%H%M%S%f")[:-3]
        body = {"version": WOCARE_VERSION, "apiCode": api_code, "channelId": WOCARE_CHANNEL_ID, "transactionId": ts + self.random_string(6, string.digits), "timeStamp": ts, "messageContent": base64.b64encode(json.dumps(data, separators=(",", ":")).encode()).decode()}
        sign_str = "&".join(f"{k}={body[k]}" for k in sorted(body)) + f"&sign={WOCARE_SIGN_KEY}"
        body["sign"] = hashlib.md5(sign_str.encode()).hexdigest()
        return body

    async def wocare_api(self, api_code, data):
        try:
            res = await self.http.post(f"https://wocare.unisk.cn/api/v1/{api_code}", data=self.get_wocare_body(api_code, data))
            if (result := res["result"]) and (msg := result.get("messageContent")):
                try:
                    import re
                    msg_clean = re.sub(r"[^a-zA-Z0-9+/=\-_]", "", msg).replace("-", "+").replace("_", "/")
                    if len(msg_clean) % 4:
                        msg_clean += "=" * (4 - len(msg_clean) % 4)
                    parsed = json.loads(base64.b64decode(msg_clean).decode())
                    result["data"] = parsed.get("data", parsed)
                    if parsed.get("resultMsg"): result["resultMsg"] = parsed["resultMsg"]
                except: pass
            return res
        except Exception as e: self.logger.log(f"联通祝福API异常: {e}"); return {"result": {}}

    @async_task("联通祝福查询任务")
    async def wocare_get_draw_task(self, task_info):
        res = await self.wocare_api("getDrawTask", {"token": self.wocare_token, "channelType": WOCARE_CHANNEL_TYPE, "type": task_info["id"], "apiCode": "getDrawTask"})
        if (result := res["result"]) and str(result.get("resultCode")) == "0000":
            for task in result.get("data", {}).get("taskList", []):
                if str(task.get("taskStatus")) == "0": await self.wocare_complete_task(task_info, task)
        else: self.logger.log(f"联通祝福[{task_info['name']}]查询任务失败: {result}")

    @async_task("联通祝福完成任务")
    async def wocare_complete_task(self, task_info, task, step="1"):
        action = "领取任务" if step == "1" else "完成任务"
        res = await self.wocare_api("completeTask", {"token": self.wocare_token, "channelType": WOCARE_CHANNEL_TYPE, "task": task["id"], "taskStep": step, "type": task_info["id"], "apiCode": "completeTask"})
        if str(res["result"].get("resultCode")) == "0000":
            if step == "1": await self.wocare_complete_task(task_info, task, "4")
        else: self.logger.log(f"联通祝福[{task_info['name']}]{action}失败: {res['result']}")

    @async_task("联通祝福查询活动")
    async def wocare_load_init(self, task_info):
        res = await self.wocare_api("loadInit", {"token": self.wocare_token, "channelType": WOCARE_CHANNEL_TYPE, "type": task_info["id"], "apiCode": "loadInit"})
        if (result := res["result"]) and str(result.get("resultCode")) == "0000":
            data = result.get("data", {})
            group_id = data.get("zActiveModuleGroupId")
            count = {2: 1 if not data.get("data", {}).get("isPartake") else 0, 3: int(data.get("raffleCountValue", 0)), 4: int(data.get("mhRaffleCountValue", 0))}.get(task_info["id"], 0)
            for _ in range(count): await asyncio.sleep(2); await self.wocare_luck_draw(task_info, group_id)
        else: self.logger.log(f"联通祝福[{task_info['name']}]查询活动失败: {result}")

    @async_task("联通祝福抽奖")
    async def wocare_luck_draw(self, task_info, group_id):
        res = await self.wocare_api("luckDraw", {"token": self.wocare_token, "channelType": WOCARE_CHANNEL_TYPE, "zActiveModuleGroupId": group_id, "type": task_info["id"], "apiCode": "luckDraw"})
        if (result := res["result"]) and str(result.get("resultCode")) == "0000":
            prize = result.get("data", {}).get("data", {}).get("prize", {})
            self.logger.log(f"联通祝福[{task_info['name']}]抽奖: {prize.get('prizeName')} [{prize.get('prizeDesc')}]", notify=True)
        else: self.logger.log(f"联通祝福[{task_info['name']}]抽奖失败: {result}")

    async def market_task(self):
        if not await self.market_login(): return
        await self.market_share_task()
        await self.market_watering_task()
        await self.market_raffle_task()
        await self.market_privilege_task()

    @async_task("权益超市登录")
    async def market_login(self):
        if not (ticket_info := await self.open_plat_line_new("https://contact.bol.wo.cn/"))["ticket"]: return False
        res = await self.http.post(f"https://backward.bol.wo.cn/prod-api/auth/marketUnicomLogin?ticket={ticket_info['ticket']}&channel=unicomTab", headers={"Content-Type": "application/json"}, json={})
        if (result := res["result"]) and result.get("code") == 200:
            self.market_token = result.get("data", {}).get("token")
            self.logger.log("权益超市登录成功")
            return True
        self.logger.log(f"权益超市登录失败: {result}")
        return False

    @async_task("分享小红书任务")
    async def market_share_task(self):
        res = await self.http.get("https://backward.bol.wo.cn/prod-api/promotion/activityTask/getAllActivityTasks?activityId=12", headers={"Authorization": f"Bearer {self.market_token}"})
        if (not (result := MarketEncrypt.decrypt(res["result"])) or result.get("code") != 200): return self.logger.log(f"获取权益超市任务列表失败: {result}")
        tasks = result.get("data", {}).get("activityTaskUserDetailVOList", [])
        if not (share_task := next((t for t in tasks if t.get("taskType") == 14), None)): return
        if share_task.get("status") == 1 or share_task.get("triggeredTime", 0) >= share_task.get("triggerTime", 1): return
        if not (param1 := share_task.get("param1")): return self.logger.log("分享小红书任务 param1 为空")
        check_res = await self.http.post(f"https://backward.bol.wo.cn/prod-api/promotion/activityTaskShare/checkShare?checkKey={param1}", headers={"Authorization": f"Bearer {self.market_token}", "Origin": "https://contact.bol.wo.cn", "Referer": "https://contact.bol.wo.cn/", "Content-Length": "0"}, data="")
        if (not (check_result := MarketEncrypt.decrypt(check_res["result"])) or check_result.get("code") != 200): self.logger.log(f"分享小红书任务失败: {check_result}")

    @async_task("权益超市浇花任务")
    async def market_watering_task(self):
        y_gdtco4r = "0hHgWnaEqWi0546ZdRfTeDqJdMBnv_KnzWG6CMU_1bgJe_DjIYJ6DF2QyCn39IVIop_Tl2MtZLEma_cOOBnd3rwlPuPDGi1VtWWYtqBx07xlMOjYRpb2aAZiH1jlx_PLjqQGzoPj1AUFWj9PwC1ELJq3oEw7mi.Vql7wNyVD4unkqvNgLlHPAB4jQSgOYaStVs9LtDqXn3Uw.6UKM2k1gpbGxW.lj8Oz0sNFL2dqf7HoG_5qG2_3427RzOlc8BTQC41UZTOVZWFgIzUN_5ieBSJuEPSrITbbJjOBKfau06OimtckkiRVxQAdTBLmSGvN0Iqp5sZcyRhPnAxWP7rDP1uWG5WMdzfW44SEwjr55XfNLUS.c7rSClxax2RBT3wP.xuYSxawy1OgFrQgIGLIJQx6.7LScnfvwchuTaf.aPkn53J2iXVfb6WPxm1BjYeFvjy1v8HuPMixeh3GGJPj_7rPLIbTUcsPYLwpLcdIbYU5bMjlqaxzfdbuUQnqAEUrh5Fqq2WUkHPwHTrnehvEbvBsn.YZksQODgRjV5Oa9lcbo5dD6fbPbO2E"
        res = await self.http.get(f"https://backward.bol.wo.cn/prod-api/promotion/activityTask/getMultiCycleProcess?activityId=13&yGdtco4r={y_gdtco4r}", headers={"Authorization": f"Bearer {self.market_token}"})
        if (result := res["result"]) and result.get("code") == 200:
            triggered, total = int(result.get("data", {}).get("triggeredTime", 0)), int(result.get("data", {}).get("triggerTime", 1))
            self.logger.log(f"浇花状态: {triggered}/{total}")
            if triggered < total: await self.market_watering()
            else: self.logger.log("浇花任务已全部完成")
        else: self.logger.log(f"获取浇花状态失败: {result}")

    @async_task("权益超市浇花")
    async def market_watering(self):
        res = await self.http.post(f"https://backward.bol.wo.cn/prod-api/promotion/activityTaskShare/checkWatering?xbsosjl=xbsosjlsujif&timeVerRan={int(time.time() * 1000)}", headers={"Authorization": f"Bearer {self.market_token}"}, json={})
        if (result := res["result"]) and result.get("code") == 200: self.logger.log("权益超市浇花成功", notify=True)
        else: self.logger.log(f"权益超市浇花失败: {result.get('msg', result)}")

    @async_task("权益超市人机验证")
    async def market_validate_captcha(self):
        res = await self.http.post("https://backward.bol.wo.cn/prod-api/promotion/home/raffleActivity/validateCaptcha?id=12", headers={"Authorization": f"Bearer {self.market_token}"}, data="")
        if (result := res["result"]) and result.get("code") == 200: self.logger.log("权益超市: 人机验证通过，继续抽奖"); return await self.market_raffle()
        self.logger.log(f"权益超市: 人机验证失败 {result}"); return False

    @async_task("权益超市抽奖任务")
    async def market_raffle_task(self):
        res = await self.http.post("https://backward.bol.wo.cn/prod-api/promotion/home/raffleActivity/getUserRaffleCount?id=12&channel=unicomTab", headers={"Authorization": f"Bearer {self.market_token}"}, json={})
        count = res["result"].get("data", 0) if res["result"] and res["result"].get("code") == 200 else 0
        self.logger.log(f"权益超市可抽奖次数: {count}")
        for _ in range(count): await asyncio.sleep(4); await self.market_raffle()
        if SHOW_PRIZE_POOL: await market_raffle_state.check_prizes(self.http, self.market_token)

    @async_task("权益超市抽奖")
    async def market_raffle(self):
        res = await self.http.post(f"https://backward.bol.wo.cn/prod-api/promotion/home/raffleActivity/userRaffle?id=12&channel=unicomTab&timeVerRan={int(time.time() * 1000)}", headers={"Authorization": f"Bearer {self.market_token}"}, json={})
        if (result := res["result"]) and result.get("code") == 200:
            data = result.get("data", {})
            if data.get("isWinning") and (prize := data.get("prizesName")): self.logger.log(f"权益超市抽奖: 恭喜抽中 {prize}", notify=True)
            else: self.logger.log("权益超市抽奖: 未抽中")
            return True
        elif result and result.get("code") == 500: self.logger.log("权益超市: 触发人机验证，自动验证中..."); return await self.market_validate_captcha()
        self.logger.log(f"权益超市抽奖失败: {result.get('msg', result)}"); return False

    @async_task("优享权益")
    async def market_privilege_task(self):
        if not self.market_token: return
        now = datetime.now()
        current_time = f"{now.year}-{now.month}-{now.day}"
        res = await self.http.post("https://backward.bol.wo.cn/prod-api/promotion/activity/roll/getActivitiesDetail", headers={"Authorization": f"Bearer {self.market_token}", "Content-Type": "application/json", "Referer": "https://contact.bol.wo.cn/"}, json={"majorId": 3, "subCodeList": ["YOUCHOICEONE"], "currentTime": current_time, "withUserStatus": 1})
        if not (result := res["result"]) or result.get("code") != 200: return self.logger.log(f"优享权益: 获取活动详情失败 {result.get('msg', '')}")
        if not (data_list := result.get("data", [])): return
        activity = data_list[0]
        if activity.get("userAvailableTimes", 0) <= 0: return self.logger.log("优享权益: 今日已领取")
        if not (detail_list := activity.get("detailList", [])): return
        available = [i for i in detail_list if int(i.get("leftQuantity", 0)) > 0]
        if not available: return self.logger.log("优享权益: 所有权益均无库存")
        surprise, normal = sorted([i for i in available if i.get("isSurprise") == 1], key=lambda x: int(x.get("sort", 0)), reverse=True), sorted([i for i in available if i.get("isSurprise") != 1], key=lambda x: int(x.get("sort", 0)), reverse=True)
        act_id, act_code = activity.get("activityId"), activity.get("activityCode", "YOUCHOICEONE")
        for item in surprise + normal:
            name, pid, pcode = item.get("productName", ""), item.get("id"), item.get("productCode", "")
            if item in surprise and item.get("isUnlock") == 0:
                if not await self._unlock_surprise_privilege(pid, act_code): self.logger.log(f"优享权益: [{name}] 解锁失败"); continue
            if await self._receive_privilege(act_id, pid, pcode, item.get("channelId"), item.get("accountType", "4"), current_time): return self.logger.log(f"优享权益: [{name}] 领取成功!", notify=True)
            self.logger.log(f"优享权益: [{name}] 领取失败")
        self.logger.log("优享权益: 所有权益领取失败")

    async def _unlock_surprise_privilege(self, product_id, activity_code):
        try:
            res = await self.http.post("https://backward.bol.wo.cn/prod-api/promotion/activity/roll/unlock/surpriseInterest", headers={"Authorization": f"Bearer {self.market_token}", "Content-Type": "application/json", "Referer": "https://contact.bol.wo.cn/"}, json={"timeVerRan": int(time.time() * 1000), "mobile": self.mobile, "id": product_id, "activityId": activity_code})
            return res["result"] and res["result"].get("code") == 200
        except: return False

    async def _receive_privilege(self, activity_id, product_id, product_code, channel_id, account_type, current_time):
        try:
            res = await self.http.post("https://backward.bol.wo.cn/prod-api/promotion/activity/roll/receiveRights", headers={"Authorization": f"Bearer {self.market_token}", "Content-Type": "application/json", "Referer": "https://contact.bol.wo.cn/"}, json={"channelId": channel_id, "activityId": activity_id, "productId": product_id, "productCode": product_code, "currentTime": current_time, "accountType": account_type})
            return res["result"] and res["result"].get("code") == 200
        except: return False

    async def xj_usersday_task(self):
        if "新疆" not in self.province: return
        if not (ticket_info := await self.open_plat_line_new("https://zy100.xj169.com/touchpoint/openapi/jumpHandRoom1G?source=166&type=02"))["ticket"]: return
        if not await self.xj_get_token(ticket_info["ticket"]): return
        day, hour = datetime.now().day, datetime.now().hour
        if hour >= 12:
            prize_id = "hfq_twenty" if day in [19, 20] else ("right_kdjdjq_ten" if 21 <= day <= 25 else None)
            if prize_id: await self.xj_usersday_draw(prize_id)
            else: self.logger.log("联通客户日: 今日无秒杀活动")
        else: self.logger.log("联通客户日: 未到12点秒杀时间")

    @async_task("新疆联通获取Token")
    async def xj_get_token(self, ticket):
        res = await self.http.post("https://zy100.xj169.com/touchpoint/openapi/getTokenAndCity", headers={"Referer": f"https://zy100.xj169.com/touchpoint/openapi/jumpHandRoom1G?source=166&type=02&ticket={ticket}", "X-Requested-With": "XMLHttpRequest", "Content-Type": "application/x-www-form-urlencoded;charset=utf-8"}, data={"ticket": ticket})
        if (result := res["result"]) and result.get("code") == 0:
            self.xj_token = result.get("data", {}).get("token")
            return True
        self.logger.log(f"新疆联通获取Token失败: {result}"); return False

    @async_task("客户日秒杀")
    async def xj_usersday_draw(self, prize_id):
        prize_dict = {"hfq_twenty": "20元话费券(100-20)", "right_kdjdjq_ten": "肯德基10元代金券"}
        res = await self.http.post("https://zy100.xj169.com/touchpoint/openapi/marchAct/draw_UsersDay2025Act", headers={"userToken": self.xj_token, "X-Requested-With": "XMLHttpRequest"}, data={"activityId": "usersDay2026Act", "prizeId": prize_id})
        if (result := res["result"]) and result.get("code") in [0, "SUCCESS"]: self.logger.log(f"客户日秒杀成功: {prize_dict.get(prize_id, prize_id)}", notify=True)
        else: self.logger.log(f"客户日秒杀失败: {result.get('data') or result.get('msg')}")

    @async_task("云手机")
    async def wostore_cloud_task(self):
        if not (ticket_info := await self.open_plat_line_new("https://h5forphone.wostore.cn/cloudPhone/dialogCloudPhone.html?channel_id=ST-Zujian001-gs&cp_id=91002997"))["ticket"]: return
        if not (tokens := await self.wostore_cloud_login(ticket_info["ticket"])): return
        first_token, user_token = tokens
        await self.wostore_cloud_sign(user_token)
        await asyncio.sleep(1)
        await self.wostore_cloud_task_list(user_token)
        await asyncio.sleep(1)
        await self.wostore_cloud_get_chance(user_token, "2508-01")
        await asyncio.sleep(1)
        await self.wostore_cloud_draw(user_token)

    @async_task_silent
    async def wostore_cloud_login(self, ticket):
        res = await self.http.post("https://member.zlhz.wostore.cn/wcy_member/yunPhone/h5Awake/businessHall", json={"cpId": "91002997", "channelId": "ST-Zujian001-gs", "ticket": ticket, "env": "prod", "transId": "S2ndpage1235+开福袋！+F1+CJDD00D0001+iphone_c@12.0801", "qkActId": None}, headers={"Host": "member.zlhz.wostore.cn", "Origin": "https://h5forphone.wostore.cn", "Referer": f"https://h5forphone.wostore.cn/cloudPhone/dialogCloudPhone.html?channel_id=ST-Zujian001-gs&ticket={ticket}"})
        if not ((result := res["result"]) and result.get("code") == "0"): return None
        redirect_url = result.get("data", {}).get("url", "")
        if "token=" not in redirect_url: return None
        first_token = redirect_url.split("token=")[1].split("&")[0]
        await asyncio.sleep(1)
        res2 = await self.http.post("https://uphone.wostore.cn/h5api/activity-service/user/login", json={"identityType": "cloudPhoneLogin", "code": first_token, "channelId": "ST-Zujian001-gs", "activityId": "Lottery_251201", "device": "device"}, headers={"Host": "uphone.wostore.cn", "Origin": "https://uphone.wostore.cn", "Referer": f"https://uphone.wostore.cn/h5/lt/December?ch=ST-Zujian001-gs&token={first_token}", "X-USR-TOKEN": first_token})
        if (result2 := res2["result"]) and result2.get("code") == 200: return (first_token, result2.get("data", {}).get("user_token"))
        return None

    @async_task("云手机积分签到")
    async def wostore_cloud_sign(self, user_token):
        res = await self.http.post("https://uphone.wostore.cn/h5api/activity-service/points/v1/sign", json={"activityCode": "Points_Sign_2507"}, headers={"Host": "uphone.wostore.cn", "Origin": "https://uphone.wostore.cn", "Referer": "https://uphone.wostore.cn/h5/lt/points", "X-USR-TOKEN": user_token})
        if (result := res["result"]) and result.get("code") == 200: self.logger.log(f"云手机积分签到: {result.get('msg', '成功')}")

    @async_task_silent
    async def wostore_cloud_task_list(self, user_token):
        await self.http.post("https://uphone.wostore.cn/h5api/activity-service/user/task/list", json={"activityCode": "Lottery_251201"}, headers={"Host": "uphone.wostore.cn", "Origin": "https://uphone.wostore.cn", "Referer": "https://uphone.wostore.cn/h5/lt/December?ch=ST-Zujian001-gs", "X-USR-TOKEN": user_token})

    @async_task_silent
    async def wostore_cloud_get_chance(self, user_token, task_code):
        await self.http.post("https://uphone.wostore.cn/h5api/activity-service/user/task/raffle/get", json={"activityCode": "Lottery_251201", "taskCode": task_code}, headers={"Host": "uphone.wostore.cn", "Origin": "https://uphone.wostore.cn", "Referer": "https://uphone.wostore.cn/h5/lt/December?ch=ST-Zujian001-gs", "X-USR-TOKEN": user_token})

    @async_task("云手机抽奖")
    async def wostore_cloud_draw(self, user_token):
        res = await self.http.post("https://uphone.wostore.cn/h5api/activity-service/lottery", json={"activityCode": "Lottery_251201"}, headers={"Host": "uphone.wostore.cn", "Origin": "https://uphone.wostore.cn", "Referer": "https://uphone.wostore.cn/h5/lt/December?ch=ST-Zujian001-gs", "X-USR-TOKEN": user_token})
        if (result := res["result"]) and result.get("code") == 200: self.logger.log(f"云手机抽奖: {result.get('prizeName', '未中奖')}", notify=True)
        elif result: self.logger.log(f"云手机抽奖失败: {result.get('msg') or result.get('message') or result.get('data') or result}")

    @async_task("签到区-任务中心")
    async def sign_task_center(self):
        for _ in range(20):
            res = await self.http.get("https://activity.10010.com/sixPalaceGridTurntableLottery/task/taskList", params={"type": 2}, headers={"Referer": "https://img.client.10010.com/"})
            if str(result.get("code", "") if (result := res["result"]) else "") != "0000": return
            all_tasks = [t for tag in result.get("data", {}).get("tagList", []) for t in tag.get("taskDTOList", [])] + result.get("data", {}).get("taskList", [])
            all_tasks = [t for t in all_tasks if t]
            if not all_tasks: break
            if do_task := next((t for t in all_tasks if t.get("taskState") == "1" and t.get("taskType") == "5"), None): await self.sign_do_task_from_list(do_task); await asyncio.sleep(1); continue
            if claim_task := next((t for t in all_tasks if t.get("taskState") == "0"), None): await self.sign_get_task_reward(claim_task.get("id")); await asyncio.sleep(1); continue
            break
        await self.sign_month_reward()

    @async_task_silent
    async def sign_month_reward(self):
        res = await self.http.get("https://activity.10010.com/sixPalaceGridTurntableLottery/floor/getMonthSign", headers={"Referer": "https://img.client.10010.com/"})
        if str(result.get("code", "") if (result := res["result"]) else "") != "0000": return
        for task in result.get("data", {}).get("taskList", []):
            if str(task.get("taskStatus", "")) == "1":
                reward_res = await self.http.get("https://activity.10010.com/sixPalaceGridTurntableLottery/task/getTaskReward", params={"taskId": task.get("taskId", ""), "taskType": "30", "id": task.get("id", "")}, headers={"Referer": "https://img.client.10010.com/"})
                if str(rr.get("code", "") if (rr := reward_res["result"]) else "") == "0000":
                    data = rr.get("data", {})
                    if str(data.get("code", "")) == "0000": self.logger.log(f"签到区-月签奖励: [{task.get('taskName', '')}] {data.get('prizeName', '')}{data.get('prizeNameRed', '')}", notify=True)
                await asyncio.sleep(1)

    @async_task("签到区-话费券兑换")
    async def sign_coupon_exchange(self):
        enabled_coupons = [name for name, enabled in EXCHANGE_COUPON_CONFIG.items() if enabled]
        if not enabled_coupons or not (prize_list := await self._get_coupon_prize_list()): return
        current_points = int(self.initial_telephone_amount * 100)
        for coupon_name in enabled_coupons:
            if not (product_id := COUPON_PRODUCT_MAP.get(coupon_name)): continue
            if not (prize_info := next((p for p in prize_list if p.get("product_id") == product_id), None)): continue
            if (btn := prize_info.get("buttonDTO")) and btn.get("name") == "面额已参与兑换": self.logger.log(f"签到区-话费券: [{coupon_name}] 今日已兑换"); continue
            if int(prize_info.get("stockSurplus", 0)) <= 0: continue
            if current_points < (req := COUPON_POINTS_REQUIRED.get(coupon_name, 0)): self.logger.log(f"签到区-话费券: [{coupon_name}] 积分不足 (需要{req}, 当前{current_points})"); continue
            for _ in range(3): await self._do_coupon_exchange(product_id, prize_info.get("type_code", "21003_01")); await asyncio.sleep(0.5)
            await asyncio.sleep(1)
            if new_list := await self._get_coupon_prize_list():
                if new_info := next((p for p in new_list if p.get("product_id") == product_id), None):
                    if (nb := new_info.get("buttonDTO")) and nb.get("name") == "面额已参与兑换": self.logger.log(f"签到区-话费券: [{coupon_name}] 兑换成功!", notify=True)
                    else: self.logger.log(f"签到区-话费券: [{coupon_name}] 兑换失败")
                else: self.logger.log(f"签到区-话费券: [{coupon_name}] 验证失败")
            await asyncio.sleep(1)

    async def _get_coupon_prize_list(self):
        try:
            res = await self.http.post("https://act.10010.com/SigninApp/new_convert/prizeList", headers={"Referer": "https://img.client.10010.com/", "Content-Type": "application/x-www-form-urlencoded"}, data="")
            if (result := res["result"]) and str(result.get("status", "")) == "0000":
                for tab in result.get("data", {}).get("datails", {}).get("tabItems", []):
                    if tab.get("defaultShowList") and tab.get("state") == "抢兑中": return tab.get("timeLimitQuanListData", [])
        except: pass
        return None

    async def _do_coupon_exchange(self, product_id, type_code):
        try:
            uuid_res = await self.http.post("https://act.10010.com/SigninApp/convert/prizeConvert", headers={"Referer": "https://img.client.10010.com/", "Content-Type": "application/x-www-form-urlencoded"}, data=f"product_id={product_id}&typeCode={type_code}")
            if not ((uuid_result := uuid_res["result"]) and str(uuid_result.get("status", "")) == "0000"): return False
            if not (uuid := uuid_result.get("data", {}).get("uuid", "")): return False
            exchange_res = await self.http.post("https://act.10010.com/SigninApp/convert/prizeConvertResult", headers={"Referer": "https://img.client.10010.com/", "Content-Type": "application/x-www-form-urlencoded"}, data=f"uuid={uuid}")
            return (exchange_result := exchange_res["result"]) and str(exchange_result.get("status", "")) == "0000"
        except: return False

    @async_task_silent
    async def sign_do_task_from_list(self, task):
        if (url := task.get("url", "")) and url != "1" and url.startswith("http"): await self.http.get(url, headers={"Referer": "https://img.client.10010.com/"}); await asyncio.sleep(random.random() * 2)
        order_id = await self.get_task_order_id()
        await self.http.get("https://activity.10010.com/sixPalaceGridTurntableLottery/task/completeTask", params={"taskId": task.get("id"), "orderId": order_id, "systemCode": "QDQD"})

    async def get_task_order_id(self):
        order_id = self.random_string(32).upper()
        try: await self.http.post("https://m.client.10010.com/taskcallback/topstories/gettaskip", data={"mobile": self.mobile, "orderId": order_id})
        except: pass
        return order_id

    @async_task_silent
    async def sign_get_task_reward(self, task_id):
        await self.http.get("https://activity.10010.com/sixPalaceGridTurntableLottery/task/getTaskReward", params={"taskId": task_id})

    SEC_UA = "ChinaUnicom4.x/12.3.1 (com.chinaunicom.mobilebusiness; build:77; iOS 16.6.0) Alamofire/4.7.3 unicom{version:iphone_c@12.0301}"

    @async_task("联通安全管家任务")
    async def security_butler_task(self):
        if not self.ecs_token or not self.mobile: return
        self.sec_old_points = self.sec_ticket1 = self.sec_token = self.sec_ticket = self.sec_jea_id = None
        await self._sec_get_ticket_by_native()
        await self._sec_get_auth_token()
        await self._sec_get_ticket_for_jf()
        if not self.sec_ticket or not self.sec_token: return self.logger.log("安全管家获取票据失败，跳过任务")
        await asyncio.sleep(1)
        await self._sec_get_user_info()
        await self._sec_execute_all_tasks()
        await asyncio.sleep(1)
        await self._sec_get_user_info()

    @async_task("安全管家获取ticket")
    async def _sec_get_ticket_by_native(self):
        ts = datetime.now().strftime("%Y%m%d%H%M%S")
        res = await self.http.get(f"https://m.client.10010.com/edop_ng/getTicketByNative?token={self.ecs_token}&appId=edop_unicom_3a6cc75a", headers={"Cookie": f"PvSessionId={ts}{self.unicom_token_id};c_mobile={self.mobile};c_version=iphone_c@11.0800;ecs_token={self.ecs_token}", "Accept": "*", "Connection": "keep-alive", "Content-Type": "application/x-www-form-urlencoded", "Host": "m.client.10010.com", "User-Agent": self.SEC_UA})
        if result := res["result"]: self.sec_ticket1 = result.get("ticket")

    @async_task("安全管家获取token")
    async def _sec_get_auth_token(self):
        if not self.sec_ticket1: return
        res = await self.http.post("https://uca.wo116114.com/api/v1/auth/ticket?product_line=uasp&entry_point=h5&entry_point_id=edop_unicom_3a6cc75a", headers={"User-Agent": self.SEC_UA, "Content-Type": "application/json", "clientType": "uasp_unicom_applet"}, json={"productId": "", "type": 1, "ticket": self.sec_ticket1})
        if (result := res["result"]) and result.get("data"): self.sec_token = result["data"].get("access_token")

    @async_task("安全管家获取积分票据")
    async def _sec_get_ticket_for_jf(self):
        if not self.sec_token: return
        res = await self.http.post("https://uca.wo116114.com/api/v1/auth/getTicket?product_line=uasp&entry_point=h5&entry_point_id=edop_unicom_3a6cc75a", headers={"User-Agent": self.SEC_UA, "Content-Type": "application/json", "auth-sa-token": self.sec_token, "clientType": "uasp_unicom_applet"}, json={"productId": "91311616", "phone": self.mobile})
        if not ((result := res["result"]) and result.get("data")): return
        self.sec_ticket = result["data"].get("ticket")
        res2 = await self.http.post("https://m.jf.10010.com/jf-external-application/page/query", headers={"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15", "partnersid": "1702", "ticket": unquote(self.sec_ticket) if self.sec_ticket else "", "clienttype": "uasp_unicom_applet"}, json={"activityId": "s747395186896173056", "partnersId": "1702"})
        if sc := res2.get("headers", {}).get("set-cookie") or res2.get("headers", {}).get("Set-Cookie"):
            for cookie in sc if isinstance(sc, list) else [sc]:
                if cookie and cookie.startswith("_jea_id="): self.sec_jea_id = cookie.split(";")[0].split("=")[1]; break

    async def _sec_operate_blacklist(self, phone_number, op_type):
        try:
            json_data = {"productId": "91015539", "type": 1, "operationType": op_type, "contents": [{"content": phone_number, "contentTag": "", "nickname": None, "configTime": None}]}
            if op_type == 0: json_data["blacklistSource"] = 0
            res = await self.http.post("https://uca.wo116114.com/sjgj/woAssistant/umm/configs/v1/config?product_line=uasp&entry_point=h5&entry_point_id=wxdefbc1986dc757a6", headers={"User-Agent": self.SEC_UA, "auth-sa-token": self.sec_token, "clientType": "uasp_unicom_applet", "token": self.sec_token, "Content-Type": "application/json"}, json=json_data)
            return res["result"]
        except Exception as e: self.logger.log(f"安全管家操作黑名单异常: {e}"); return None

    async def _sec_add_to_blacklist(self):
        phone = "13088888888"
        if (result := await self._sec_operate_blacklist(phone, 0)) and (result.get("code") in ["0000", 0] or result.get("msg") == "成功"): return
        if result and "号码已存在" in result.get("msg", ""):
            if (del_r := await self._sec_operate_blacklist(phone, 1)) and (del_r.get("code") in ["0000", 0] or "成功" in str(del_r.get("msg", ""))): await asyncio.sleep(1); await self._sec_operate_blacklist(phone, 0)

    @async_task_silent
    async def _sec_mark_phone_number(self):
        await self.http.post("https://uca.wo116114.com/sjgj/unicomAssistant/uasp/configs/v1/addressBook/saveTagPhone?product_line=uasp&entry_point=h5&entry_point_id=wxdefbc1986dc757a6", headers={"User-Agent": self.SEC_UA, "auth-sa-token": self.sec_token, "clientType": "uasp_unicom_applet", "Content-Type": "application/json"}, json={"tagPhoneNo": "13088330789", "tagIds": [26], "status": 0, "productId": "91311616"})

    @async_task_silent
    async def _sec_sync_address_book(self):
        await self.http.post("https://uca.wo116114.com/sjgj/unicomAssistant/uasp/configs/v1/addressBookBatchConfig?product_line=uasp&entry_point=h5&entry_point_id=edop_unicom_3a6cc75a", headers={"User-Agent": self.SEC_UA, "auth-sa-token": self.sec_token, "clientType": "uasp_unicom_applet", "Content-Type": "application/json"}, json={"addressBookDTOList": [{"addressBookPhoneNo": "13088888888", "addressBookName": "水水"}], "productId": "91311616", "opType": "1"})

    @async_task_silent
    async def _sec_set_interception_rules(self):
        await self.http.post("https://uca.wo116114.com/sjgj/woAssistant/umm/configs/v1/config?product_line=uasp&entry_point=h5&entry_point_id=wxdefbc1986dc757a6", headers={"User-Agent": self.SEC_UA, "auth-sa-token": self.sec_token, "clientType": "uasp_unicom_applet", "Content-Type": "application/json"}, json={"contents": [{"name": "rings-once", "contentTag": "8", "contentName": "响一声", "content": "0", "icon": "alerting"}], "operationType": 0, "type": 3, "productId": "91311616"})

    @async_task_silent
    async def _sec_view_weekly_summary(self):
        sec_headers = {"auth-sa-token": self.sec_token, "clientType": "uasp_unicom_applet", "Content-Type": "application/json"}
        await self.http.post("https://uca.wo116114.com/sjgj/unicomAssistant/uasp/configs/v1/weeklySwitchStatus?product_line=uasp&entry_point=h5&entry_point_id=wxdefbc1986dc757a6", headers=sec_headers, json={"productId": "91311616"})
        await self.http.post("https://uca.wo116114.com/sjgj/unicomAssistant/uasp/report/v1/queryKeyData?product_line=uasp&entry_point=h5&entry_point_id=wxdefbc1986dc757a6", headers=sec_headers, json={"productId": "91311616"})
        await self.http.post("https://uca.wo116114.com/sjgj/unicomAssistant/uasp/report/v1/weeklySummary?product_line=uasp&entry_point=h5&entry_point_id=wxdefbc1986dc757a6", headers=sec_headers, json={"productId": "91311616"})

    @async_task_silent
    async def _sec_sign_in(self, task_code):
        await self.http.post("https://m.jf.10010.com/jf-external-application/jftask/sign", headers={**_sec_headers(self)}, json={"taskCode": task_code})

    @async_task_silent
    async def _sec_receive_points(self, task_code):
        await self.http.post("https://m.jf.10010.com/jf-external-application/jftask/receive", headers={**_sec_headers(self)}, json={"taskCode": task_code})

    @async_task("安全管家执行任务")
    async def _sec_finish_task(self, task_code, task_name):
        await self.http.post("https://m.jf.10010.com/jf-external-application/jftask/toFinish", headers={**_sec_headers(self)}, json={"taskCode": task_code})
        task_handlers = {"联通助理-添加黑名单": self._sec_add_to_blacklist, "联通助理-号码标记": self._sec_mark_phone_number, "联通助理-同步通讯录": self._sec_sync_address_book, "联通助理-骚扰拦截设置": self._sec_set_interception_rules, "联通助理-查看周报": self._sec_view_weekly_summary}
        if handler := task_handlers.get(task_name): await handler()

    @async_task("安全管家执行所有任务")
    async def _sec_execute_all_tasks(self):
        res = await self.http.post("https://m.jf.10010.com/jf-external-application/jftask/taskDetail", headers={**_sec_headers(self)}, json={})
        if not (result := res["result"]) or not result.get("data") or not result["data"].get("taskDetail"): return self.logger.log("安全管家: 查询任务列表失败")
        executable_names = {"联通助理-添加黑名单", "联通助理-号码标记", "联通助理-同步通讯录", "联通助理-骚扰拦截设置", "联通助理-查看周报"}
        for task in result["data"]["taskDetail"].get("taskList", []):
            task_code, task_name = task.get("taskCode", ""), task.get("taskName", "")
            if task_name not in executable_names and "签到" not in task_name: continue
            if (remaining := task.get("needCount", 1) - task.get("finishCount", 0)) > 0:
                for _ in range(remaining):
                    await asyncio.sleep(1)
                    try:
                        if "签到" in task_name: await self._sec_sign_in(task_code); await self._sec_receive_points(task_code); break
                        else: await self._sec_finish_task(task_code, task_name); await asyncio.sleep(1); await self._sec_receive_points(task_code)
                    except: break
            elif task.get("finishText") == "待领取": await asyncio.sleep(1); await self._sec_receive_points(task_code)

    @async_task("安全管家获取积分")
    async def _sec_get_user_info(self):
        res = await self.http.post("https://m.jf.10010.com/jf-external-application/jftask/userInfo", headers={**_sec_headers(self), "User-Agent": "Mozilla/5.0 (Linux; Android 9; ONEPLUS A5000) AppleWebKit/537.36"}, json={})
        if not (result := res["result"]) or result.get("code") != "0000" or not result.get("data"): return self.logger.log(f"安全管家: 查询积分失败: {result.get('msg') if result else '无响应'}")
        current_points = int(result["data"].get("availableScore", 0))
        if self.sec_old_points is None: self.sec_old_points = current_points
        elif (gained := current_points - self.sec_old_points) > 0: self.logger.log(f"安全管家: 本次获得{gained}积分", notify=True)

    async def shangdu_task(self):
        if "河南" not in self.province: return
        if (ticket := await self.shangdu_get_ticket()) and await self.shangdu_login(ticket): await asyncio.sleep(1); await self.shangdu_signin()

    async def shangdu_get_ticket(self):
        if not getattr(self, "ecs_token", None): self.logger.log("商都福利: 缺少 ecs_token，请检查是否已执行 online 登录"); return None
        try:
            res = await self.http.get("https://m.client.10010.com/edop_ng/getTicketByNative", params={"token": self.ecs_token, "appId": "edop_unicom_4b80047a"})
            if isinstance((r := res["result"]), dict) and r.get("rsp_code") == "0000": return r.get("ticket")
            self.logger.log(f"商都福利: Ticket 获取失败 {r}"); return None
        except Exception as e: self.logger.log(f"商都福利获取Ticket异常: {e}"); return None

    async def shangdu_login(self, ticket):
        sd_headers = {"Host": "app.shangdu.com", "Origin": "https://app.shangdu.com", "Referer": "https://app.shangdu.com/monthlyBenefit/index.html", "edop_flag": "0", "Accept": "application/json, text/plain, */*"}
        try:
            res = await self.http.get(f"https://app.shangdu.com/monthlyBenefit/v1/common/config?ticket={ticket}", headers=sd_headers)
            if isinstance((r := res["result"]), dict) and r.get("code") == "0000": return True
            self.logger.log(f"商都福利: 登录激活失败 {r}"); return False
        except Exception as e: self.logger.log(f"商都福利登录异常: {e}"); return False

    async def shangdu_get_sign_status(self):
        sd_headers = {"Host": "app.shangdu.com", "Origin": "https://app.shangdu.com", "Referer": "https://app.shangdu.com/monthlyBenefit/index.html", "edop_flag": "0", "Content-Type": "application/json"}
        try:
            res = await self.http.post("https://app.shangdu.com/monthlyBenefit/v1/signIn/queryCumulativeSignAxis", headers=sd_headers, json={})
            return res["result"].get("data", {}).get("todaySignFlag") == "1" if isinstance(res["result"], dict) and res["result"].get("code") == "0000" else None
        except: return None

    @async_task("商都福利签到")
    async def shangdu_signin(self):
        sd_headers = {"Host": "app.shangdu.com", "Origin": "https://app.shangdu.com", "Referer": "https://app.shangdu.com/monthlyBenefit/index.html", "edop_flag": "0", "X-Requested-With": "XMLHttpRequest", "Content-Type": "application/json"}
        res = await self.http.post("https://app.shangdu.com/monthlyBenefit/v1/signIn/userSignIn", headers=sd_headers, json={})
        if not isinstance((result := res["result"]), dict): return
        code = result.get("code")
        if code == "0000":
            data = result.get("data", {})
            if data.get("value") == "0001": return self.logger.log("商都福利: 签到失败 (Cookie无效/未登录)")
            prize_name = (data.get("prizeResp") or {}).get("prizeName", "")
            if str(data.get("signFlag", "")) == "1": self.logger.log(f"商都福利签到成功: 获得 {prize_name}" if prize_name else "商都福利: 今日已签到", notify=bool(prize_name))
            else: self.logger.log(f"商都福利签到成功 (signFlag={data.get('signFlag')})")
        elif code == "0019":
            await asyncio.sleep(1)
            if (is_signed := await self.shangdu_get_sign_status()) is True: self.logger.log("商都福利: 今日已签到")
            elif is_signed is False: self.logger.log("商都福利: 服务端异常(返回重复签到但实际未签)，尝试重试..."); await asyncio.sleep(2); await self._shangdu_signin_retry()
            else: self.logger.log("商都福利: 今日已签到 (状态查询失败)")
        else: self.logger.log(f"商都福利签到失败: {result.get('msg') or result.get('desc') or ''} (code={code})")

    @async_task_silent
    async def _shangdu_signin_retry(self):
        sd_headers = {"Host": "app.shangdu.com", "Origin": "https://app.shangdu.com", "Referer": "https://app.shangdu.com/monthlyBenefit/index.html", "edop_flag": "0", "X-Requested-With": "XMLHttpRequest", "Content-Type": "application/json"}
        res = await self.http.post("https://app.shangdu.com/monthlyBenefit/v1/signIn/userSignIn", headers=sd_headers, json={})
        if isinstance((result := res["result"]), dict):
            code = result.get("code")
            if code == "0000":
                prize_name = (result.get("data", {}).get("prizeResp") or {}).get("prizeName", "")
                self.logger.log(f"商都福利签到成功(重试): 获得 {prize_name}" if prize_name else "商都福利签到成功(重试)", notify=bool(prize_name))
            elif code == "0019": self.logger.log("商都福利: 重试仍返回重复签到，请检查")
            else: self.logger.log(f"商都福利签到重试失败: {result.get('msg') or result.get('desc') or ''}")

    def _woread_encode(self, data, password=WOREAD_PASSWORD):
        try:
            text = (json.dumps(data, separators=(",", ":")) if isinstance(data, (dict, list)) else str(data))
            cipher = AES.new(password.encode("utf-8"), AES.MODE_CBC, WOREAD_IV.encode("utf-8"))
            return base64.b64encode(cipher.encrypt(pad(text.encode("utf-8"), AES.block_size)).hex().encode("utf-8")).decode("utf-8")
        except Exception as e: self.logger.log(f"联通阅读加密异常: {e}"); return ""

    async def woread_auth(self):
        try:
            timestamp = str(int(datetime.now().timestamp() * 1000))
            md5_hash = hashlib.md5(f"{WOREAD_PRODUCT_ID}{WOREAD_SECRET_KEY}{timestamp}".encode("utf-8")).hexdigest()
            res = await self.http.post(f"https://10010.woread.com.cn/ng_woread_service/rest/app/auth/{WOREAD_PRODUCT_ID}/{timestamp}/{md5_hash}", headers={"Content-Type": "application/json", "User-Agent": "okhttp/3.14.9"}, json={"sign": self._woread_encode({"timestamp": datetime.now().strftime("%Y%m%d%H%M%S")})})
            if (result := res["result"]) and str(result.get("code")) == "0000":
                self.woread_accesstoken = result.get("data", {}).get("accesstoken", "")
                return True
            self.logger.log(f"联通阅读预登录失败: {result.get('message', '') if result else '请求失败'}")
            return False
        except Exception as e: self.logger.log(f"联通阅读预登录异常: {e}"); return False

    async def woread_login(self):
        try:
            if not await self.woread_auth(): return False
            if not getattr(self, "token_online", None): self.logger.log("联通阅读: 缺少 token_online"); return False
            inner_json = json.dumps({"tokenOnline": self._woread_encode_str(self.token_online), "phone": self._woread_encode_str(self.mobile), "timestamp": datetime.now().strftime("%Y%m%d%H%M%S")}, separators=(",", ":"))
            res = await self.http.post("https://10010.woread.com.cn/ng_woread_service/rest/account/login", headers={"accesstoken": self.woread_accesstoken, "Content-Type": "application/json", "User-Agent": "okhttp/3.14.9"}, json={"sign": self._woread_encode_str(inner_json)})
            if (result := res["result"]) and str(result.get("code")) == "0000":
                data = result.get("data", {})
                self.woread_token, self.woread_verifycode, self.woread_userid, self.woread_userindex = data.get("token", ""), data.get("verifycode", ""), data.get("userid", ""), data.get("userindex", "")
                self.logger.log("联通阅读: 登录成功")
                return True
            self.logger.log(f"联通阅读登录失败: {result.get('msg', '') or result.get('message', '') if result else '请求失败'}")
            return False
        except Exception as e: self.logger.log(f"联通阅读登录异常: {e}"); return False

    def _woread_encode_str(self, text):
        try:
            cipher = AES.new(WOREAD_PASSWORD.encode("utf-8"), AES.MODE_CBC, WOREAD_IV.encode("utf-8"))
            return base64.b64encode(cipher.encrypt(pad(text.encode("utf-8"), AES.block_size)).hex().encode("utf-8")).decode("utf-8")
        except Exception as e: self.logger.log(f"联通阅读加密异常: {e}"); return ""

    async def woread_get_book_info(self):
        wr_headers = {"accesstoken": self.woread_accesstoken, "User-Agent": "okhttp/3.14.9"}
        try:
            res = await self.http.get("https://10010.woread.com.cn/ng_woread_service/rest/basics/recommposdetail/14856", headers=wr_headers)
            if not (result := res["result"]) or str(result.get("code")) != "0000": self.logger.log("联通阅读: 获取书籍列表失败"); return False
            data = result.get("data", {})
            booklist, bindinfo = data.get("booklist", {}).get("message", []), data.get("bindinfo", [])
            if not booklist or not bindinfo: self.logger.log("联通阅读: 获取书籍列表为空"); return False
            self.wr_catid, self.wr_cardid, self.wr_cntindex = booklist[0].get("catindex", ""), bindinfo[0].get("recommposiindex", ""), booklist[0].get("cntindex", "")
            if not self.wr_cntindex: return False
            res2 = await self.http.post("https://10010.woread.com.cn/ng_woread_service/rest/cnt/chalist", headers={**wr_headers, "Content-Type": "application/json"}, json={"sign": self._woread_encode({"curPage": 1, "limit": 30, "index": self.wr_cntindex, "sort": 0, "finishFlag": 1, **self._get_woread_param()})})
            if (chapters := (res2["result"] or {}).get("list", [])) and (chapter_content := chapters[0].get("charptercontent", [])):
                self.wr_chapterallindex, self.wr_chapterid = chapter_content[0].get("chapterallindex", ""), chapter_content[0].get("chapterid", "")
                return True
            return False
        except Exception as e: self.logger.log(f"联通阅读获取书籍异常: {e}"); return False

    _get_woread_param = lambda self: {"timestamp": datetime.now().strftime("%Y%m%d%H%M%S"), "token": getattr(self, "woread_token", ""), "userid": getattr(self, "woread_userid", ""), "userId": getattr(self, "woread_userid", ""), "userIndex": getattr(self, "woread_userindex", ""), "userAccount": self.mobile, "verifyCode": getattr(self, "woread_verifycode", "")}

    @async_task("联通阅读模拟阅读")
    async def woread_read_process(self):
        if not await self.woread_get_book_info(): return self.logger.log("联通阅读: 无法获取书籍信息，跳过阅读")
        wr_headers = {"accesstoken": self.woread_accesstoken, "Content-Type": "application/json", "User-Agent": "okhttp/3.14.9"}
        await self.http.post(f"https://10010.woread.com.cn/ng_woread_service/rest/cnt/wordsDetail?catid={self.wr_catid}&cardid={self.wr_cardid}&cntindex={self.wr_cntindex}&chapterallindex={self.wr_chapterallindex}&chapterseno=1", headers=wr_headers, json={"sign": self._woread_encode({"chapterAllIndex": self.wr_chapterallindex, "cntIndex": self.wr_cntindex, "cntTypeFlag": "1", **self._get_woread_param()})})
        await asyncio.sleep(1)
        add_param = {"readTime": "2", "cntIndex": self.wr_cntindex, "cntType": "1", "catid": "0", "pageIndex": "", "cardid": self.wr_cardid, "cntindex": self.wr_cntindex, "cnttype": "1", "chapterallindex": self.wr_chapterallindex, "chapterseno": "1", "channelid": "", "chapterid": self.wr_chapterid, "readtype": 1, "isend": "0", **self._get_woread_param()}
        res = await self.http.post("https://10010.woread.com.cn/ng_woread_service/rest/history/addReadTime", headers=wr_headers, json={"sign": self._woread_encode(add_param)})
        self.logger.log("联通阅读: 模拟阅读成功" if (result := res["result"]) and str(result.get("code")) == "0000" else f"联通阅读: 模拟阅读失败: {result.get('msg', '') if result else ''}")

    @async_task("联通阅读抽奖")
    async def woread_draw_new(self):
        wr_headers = {"accesstoken": self.woread_accesstoken, "Content-Type": "application/json", "User-Agent": "okhttp/3.14.9"}
        res = await self.http.post("https://10010.woread.com.cn/ng_woread_service/rest/basics/doDraw", headers=wr_headers, json={"sign": self._woread_encode({"activeindex": "8051", **self._get_woread_param()})})
        if (result := res["result"]) and str(result.get("code")) == "0000":
            self.logger.log(f"联通阅读抽奖: {result.get('data', {}).get('prizedesc', '未知奖品')}", notify=True)
        else:
            msg = (result.get("msg", "") or result.get("message", "")) if result else "请求失败"
            self.logger.log(f"联通阅读: {msg}" if "已抽" in msg or "次数" in msg else f"联通阅读抽奖失败: {msg}")

    @async_task_silent
    async def woread_queryTicketAccount(self):
        wr_headers = {"accesstoken": self.woread_accesstoken, "Content-Type": "application/json", "User-Agent": "okhttp/3.14.9"}
        res = await self.http.post("https://10010.woread.com.cn/ng_woread_service/rest/phone/vouchers/queryTicketAccount", headers=wr_headers, json={"sign": self._woread_encode(self._get_woread_param())})
        if (result := res["result"]) and str(result.get("code")) == "0000":
            self.logger.log(f"联通阅读话费红包余额: {float(result.get('data', {}).get('usableNum', 0)) / 100:.2f}元", notify=True)

    async def woread_task(self):
        if not await self.woread_login(): return self.logger.log("联通阅读: 登录失败，跳过任务")
        await self.woread_read_process()
        await self.woread_draw_new()
        await self.woread_queryTicketAccount()

    # ==================== 联通爱听专区 ====================
    def generate_random_imei(self):
        tac = "".join(str(random.randint(0, 9)) for _ in range(8))
        snr = "".join(str(random.randint(0, 9)) for _ in range(6))
        imei_base = tac + snr
        digits = [int(d) for d in imei_base]
        for i in range(len(digits) - 1, -1, -2):
            digits[i] *= 2
            if digits[i] > 9: digits[i] -= 9
        check_digit = (10 - sum(digits) % 10) % 10
        return imei_base + str(check_digit)

    def aiting_get_aes(self, data, key):
        text = json.dumps(data, separators=(",", ":")) if isinstance(data, (dict, list)) else str(data)
        cipher = AES.new(key[:16].encode(), AES.MODE_CBC, AITING_AES_IV.encode())
        return base64.b64encode(cipher.encrypt(pad(text.encode(), AES.block_size)).hex().encode()).decode()

    def aiting_aes_encrypt(self, data, key, iv):
        text = json.dumps(data, separators=(",", ":")) if isinstance(data, (dict, list)) else str(data)
        cipher = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
        return base64.b64encode(cipher.encrypt(pad(text.encode(), AES.block_size)).hex().upper().encode()).decode()

    aiting_generate_sign = lambda self, params, key: hashlib.md5(f"{'&'.join(f'{k}={params[k]}' for k in sorted(params))}&key={key}".encode()).hexdigest()
    aiting_generate_woid = lambda self, imei: f"WOA{self.random_string(6)}{imei[:8] if len(imei) >= 8 else imei.ljust(8, '0')}LOT{self.random_string(4)}LV{self.random_string(2)}"
    aiting_calculate_clientconfirm = lambda self, userid, imei: self.aiting_aes_encrypt(f"android{userid}{imei}", AITING_AES_KEY, AITING_AES_IV)
    aiting_calculate_passcode = lambda self, timestamp, phone: hashlib.md5(f"{timestamp}{phone}{AITING_CLIENT_KEY}".encode()).hexdigest()
    aiting_build_statisticsinfo = lambda self, userid, useraccount, imei, clientconfirm: "&".join(f"{k}={v}" for k, v in {"channelid": "28015001", "sid": self.random_string(20), "eid": self.random_string(20), "osversion": "Android12", "clientallid": "000000100000000000058.0.2.1225", "display": "2400_1080", "ip": "192.168.3.24", "nettypename": "wifi", "version": "802", "versionname": "8.0.2", "terminalName": "Redmi", "terminalType": "Redmi_K30_Pro", "udid": "null", "woid": self.aiting_generate_woid(imei), "useraccount": useraccount, "userid": userid, "clientconfirm": clientconfirm}.items())

    def _aiting_requertid(self, timestamp=None, nonce=None):
        ts = timestamp or str(int(time.time() * 1000))
        nc = nonce or str(random.randint(100000, 999999))
        sign_params = {"jwt": self.aiting_jwt, "nonestr": nc, "osversion": "Android12", "terminalName": "Redmi", "timestamp": ts}
        return ts, nc, hashlib.md5(f"{'&'.join(f'{k}={sign_params[k]}' for k in sorted(sign_params))}&key={AITING_SIGN_KEY_REQUERTID}".encode()).hexdigest()

    def _aiting_headers(self, ts, nonce, requertid):
        return {"AuthorizationClient": f"Bearer {self.aiting_jwt}", "requerttime": ts, "nonestr": nonce, "requertid": requertid, "statisticsinfo": self.aiting_statisticsinfo, "User-Agent": "okhttp/4.9.0"}

    @async_task("爱听获取JWT")
    async def aiting_get_jwt_token(self, statisticsinfo):
        timestamp = str(int(time.time() * 1000))
        sign_params = {"clientSource": "3", "clientId": "android", "source": "3", "timestamp": timestamp}
        sign = self.aiting_generate_sign(sign_params, AITING_SIGN_KEY_APPKEY)
        client_id_b64 = base64.b64encode("395DEDE9C1D6FE11B7C9C0D82B353E74".encode()).decode()
        res = await self.http.post(f"{AITING_BASE_URL}/oauth/client/appkey", headers={"Skip-Authorization-Check": "true", "statisticsinfo": statisticsinfo, "Content-Type": "application/json"}, json={"clientSource": "3", "clientId": client_id_b64, "source": "3", "timestamp": timestamp, "sign": sign})
        return result.get("key") if (result := res["result"]) and result.get("code") == "0000" else None

    @async_task("爱听获取Profile")
    async def aiting_get_read_profile(self, user_token, userid, jwt_token, statisticsinfo):
        req_time, nonce = str(int(time.time() * 1000)), str(random.randint(100000, 999999))
        sign_params = {"jwt": jwt_token, "nonestr": nonce, "osversion": "Android12", "terminalName": "Redmi", "timestamp": req_time}
        requertid = hashlib.md5(f"{'&'.join(f'{k}={sign_params[k]}' for k in sorted(sign_params))}&key={AITING_SIGN_KEY_REQUERTID}".encode()).hexdigest()
        res = await self.http.get(f"{AITING_BASE_URL}/pcc/rest/sns/profile/readprofile/7", params={"userid": userid, "token": user_token, "encryptflag": "1"}, headers={"User-Agent": "okhttp/4.9.0", "requerttime": req_time, "nonestr": nonce, "requertid": requertid, "AuthorizationClient": f"Bearer {jwt_token}", "statisticsinfo": statisticsinfo})
        return result.get("message") if (result := res["result"]) and result.get("code") == "0000" else None

    @async_task("爱听业务登录")
    async def aiting_api_login(self, phone, useraccount, jwt_token, statisticsinfo):
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        passcode = self.aiting_calculate_passcode(timestamp, phone)
        url = f"{AITING_BASE_URL}/mainrest/rest/read/user/ulogin//3/{useraccount}/1/1/0?networktype=3&ua=Redmi+K30+Pro&isencode=true&clientversion=8.0.2&versionname=Android_1_1080x2356&channelid=28015001&userlabelisencode=1&validatecode=&sid=&timestamp={timestamp}&passcode={passcode}"
        req_time, nonce = str(int(time.time() * 1000)), str(random.randint(100000, 999999))
        sign_params = {"jwt": jwt_token, "nonestr": nonce, "osversion": "Android12", "terminalName": "Redmi", "timestamp": req_time}
        requertid = hashlib.md5(f"{'&'.join(f'{k}={sign_params[k]}' for k in sorted(sign_params))}&key={AITING_SIGN_KEY_REQUERTID}".encode()).hexdigest()
        res = await self.http.get(url, headers={"statisticsinfo": statisticsinfo, "requerttime": req_time, "nonestr": nonce, "requertid": requertid, "AuthorizationClient": f"Bearer {jwt_token}", "User-Agent": "okhttp/4.9.0"})
        if (result := res["result"]) and result.get("code") == "0000" and (msg := result.get("message")):
            token = msg.get("accountinfo", {}).get("token") or msg.get("token")
            return {"token": token, "userid": msg.get("accountinfo", {}).get("userid") or msg.get("userid")} if token else None
        return None

    @async_task("爱听登录流程")
    async def aiting_login_flow(self):
        if not (self.woread_token and self.woread_userid): return self.logger.log("爱听: 需要先完成联通阅读登录") or False
        self.aiting_woread_token, self.aiting_base_userid = self.woread_token, self.woread_userid
        phone, imei = self.mobile, self.generate_random_imei()
        clientconfirm = self.aiting_calculate_clientconfirm(self.aiting_base_userid, imei)
        temp_stats = self.aiting_build_statisticsinfo(self.aiting_base_userid, phone, imei, clientconfirm)
        self.aiting_jwt = await self.aiting_get_jwt_token(temp_stats)
        if not self.aiting_jwt: return False
        profile_msg = await self.aiting_get_read_profile(self.aiting_woread_token, self.aiting_base_userid, self.aiting_jwt, temp_stats)
        if not profile_msg or not profile_msg.get("mobile"): return False
        real_useraccount = profile_msg["mobile"]
        self.aiting_statisticsinfo = self.aiting_build_statisticsinfo(self.aiting_base_userid, real_useraccount, imei, clientconfirm)
        login_data = await self.aiting_api_login(phone, real_useraccount, self.aiting_jwt, self.aiting_statisticsinfo)
        if not login_data: return False
        self.aiting_token, self.aiting_userid = login_data["token"], login_data["userid"]
        self.logger.log("爱听登录成功")
        return True

    @async_task("爱听获取Ticket")
    async def aiting_get_ticket(self):
        ts, nonce, requertid = self._aiting_requertid()
        sign = self.aiting_generate_sign({"timestamp": ts, "token": self.aiting_token, "userid": self.aiting_userid}, AITING_SIGN_KEY_API)
        res = await self.http.post(f"{AITING_BASE_URL}/activity/rest/unicom/points/getInfoTicket", headers={**self._aiting_headers(ts, nonce, requertid), "Content-Type": "application/json"}, json={"sign": sign, "timestamp": ts, "token": self.aiting_token, "userid": self.aiting_userid})
        if (result := res["result"]) and result.get("code") == "0000" and (msg := result.get("message")) and "ticket=" in msg:
            return parse_qs(urlparse(msg).query).get("ticket", [""])[0]
        return None

    @async_task("爱听签到")
    async def aiting_sign_in(self):
        ts, nonce, requertid = self._aiting_requertid()
        res = await self.http.get(f"https://woread.com.cn/rest/read/usersign/sign/3/{self.aiting_base_userid}/{self.aiting_woread_token}", params={"isresign": "0", "isnewversion": "1", "isfreeLimt": "0"}, headers={**self._aiting_headers(ts, nonce, requertid), "Content-Type": "application/json"})
        if (result := res["result"]) and result.get("code") == "0000":
            self.logger.log(f"爱听签到成功: {result.get('desc', '')} (连续{result.get('continuousDays', 0)}天)", notify=True)
        else: self.logger.log(f"爱听签到: {result.get('desc') or result.get('message') or '失败'}")

    get_jf_headers = lambda self, ticket: {"ticket": ticket, "pageid": "s789081246969976832", "clienttype": "aiting_android", "partnersid": "1706", "content-type": "application/json;charset=UTF-8", "User-Agent": "Mozilla/5.0 (Linux; Android 12; Redmi K30 Pro) AppleWebKit/537.36 WoReaderApp/Android", "Origin": "https://m.jf.10010.com", "Referer": f"https://m.jf.10010.com/jf-external-application/index.html?ticket={ticket}&pageID=s789081246969976832"}

    @async_task("爱听查询积分")
    async def jf_get_user_info(self, ticket):
        res = await self.http.post("https://m.jf.10010.com/jf-external-application/jftask/userInfo", headers=self.get_jf_headers(ticket), json={})
        if (result := res["result"]) and result.get("code") == "0000" and (data := result.get("data")):
            self.logger.log(f"爱听积分: 今日已赚{data.get('todayEarnScore', 0)}, 余额{data.get('availableScore', 0)}", notify=True)
            return data
        return None

    @async_task_silent
    async def jf_get_task_detail(self, ticket):
        res = await self.http.post("https://m.jf.10010.com/jf-external-application/jftask/taskDetail", headers=self.get_jf_headers(ticket), json={})
        return result["data"]["taskDetail"].get("taskList", []) if (result := res["result"]) and result.get("data", {}).get("taskDetail") else []

    @async_task_silent
    async def jf_to_finish(self, ticket, task_code):
        await self.http.post("https://m.jf.10010.com/jf-external-application/jftask/toFinish", headers=self.get_jf_headers(ticket), json={"taskCode": task_code})

    @async_task_silent
    async def jf_pop_up(self, ticket):
        return (await self.http.post("https://m.jf.10010.com/jf-external-application/jftask/popUp", headers=self.get_jf_headers(ticket), json={}))["result"]

    @async_task_silent
    async def aiting_complete_task_api(self, task_type):
        ts, nonce, requertid = self._aiting_requertid()
        body = {"source": "3", "timestamp": ts, "token": self.aiting_woread_token, "type": str(task_type), "userid": self.aiting_base_userid}
        body["sign"] = self.aiting_generate_sign(body, AITING_SIGN_KEY_API)
        await self.http.post(f"{AITING_BASE_URL}/activity/rest/unicom/points/completiontask", headers={**self._aiting_headers(ts, nonce, requertid), "Content-Type": "application/json"}, json=body)

    @async_task_silent
    async def aiting_get_secretkey(self):
        ts, nonce, requertid = self._aiting_requertid()
        res = await self.http.get(f"https://woread.com.cn/rest/read/statistics/getsecretkey/3/{self.aiting_base_userid}", params={"token": self.aiting_woread_token}, headers=self._aiting_headers(ts, nonce, requertid))
        return result.get("message") if (result := res["result"]) and result.get("code") == "0000" else None

    @async_task_silent
    async def aiting_add_read_time(self, read_time_seconds):
        if not (secretkey := await self.aiting_get_secretkey()): return
        ts, nonce, requertid = self._aiting_requertid()
        count_time, book_id = str(read_time_seconds * 1000), "4524960"
        encrypted = self.aiting_aes_encrypt({"userid": self.aiting_base_userid, "counttime": count_time, "timestamp": ts, "secretkey": secretkey, "cntindex": book_id, "cnttype": 1, "readtype": 1}, ADDREADTIME_AES_KEY, AITING_AES_IV)
        await self.http.post(f"https://woread.com.cn/rest/read/statistics/addreadtime/3/{encrypted}", headers={**self._aiting_headers(ts, nonce, requertid), "Content-Type": "application/json"}, json={"channelid": "28015001", "creadertime": datetime.now().strftime("%y%m%d%H%M%S"), "imei": self.generate_random_imei(), "list": {"cntindex": book_id, "cnttype": 1, "readtime": count_time, "readtype": 1}, "list1": [{"cntindex": book_id, "cnttype": 1, "readtime": count_time, "readtype": 1}], "listentimes": count_time, "uuid": self.random_string(32)})

    @async_task_silent
    async def aiting_new_read_add(self):
        ts, nonce, requertid = self._aiting_requertid()
        await self.http.post(f"https://woread.com.cn/rest/read/new/newreadadd/3/{self.aiting_base_userid}/{self.aiting_woread_token}", params={"isfreeLimt": "0", "isgray": "true"}, headers={**self._aiting_headers(ts, nonce, requertid), "User-Agent": "Redmi K30 Pro", "Content-Type": "application/json"}, json={"source": 3, "cntindex": "4524960", "chapterallindex": "100136247350", "readtype": 3})

    @async_task("爱听执行任务")
    async def aiting_do_tasks(self, ticket):
        task_list = await self.jf_get_task_detail(ticket)
        if not task_list: return
        todo_list = [t for t in task_list if t.get("finish") == 0 and "邀请" not in t.get("taskName", "")]
        if not todo_list: return self.logger.log("爱听任务: 所有任务已完成")
        self.logger.log(f"爱听任务: 发现{len(todo_list)}个待办任务")
        read_tasks = [t for t in todo_list if ("阅读" in t.get("taskName", "") or "听读" in t.get("taskName", "")) and "邀请" not in t.get("taskName", "")]
        for task in read_tasks:
            remaining = (task.get("needCount", 1) or 1) - (task.get("finishCount", 0) or 0)
            if remaining <= 0: continue
            self.logger.log(f"爱听执行阅读任务: {task.get('taskName')} (剩余{remaining}次)")
            for i in range(remaining):
                await self.jf_to_finish(ticket, task.get("taskCode"))
                await self.aiting_new_read_add()
                await asyncio.sleep(5)
                await self.aiting_add_read_time(120)
                await asyncio.sleep(2)
                if (res := await self.jf_pop_up(ticket)) and res.get("data", {}).get("score"):
                    self.logger.log(f"爱听阅读任务获得{res['data']['score']}积分", notify=True)
                await asyncio.sleep(2)
        notify_task = next((t for t in todo_list if "通知" in t.get("taskName", "")), None)
        if notify_task:
            await self.jf_to_finish(ticket, notify_task.get("taskCode"))
            await asyncio.sleep(1)
            await self.aiting_complete_task_api(2)
            await asyncio.sleep(2)
            if (res := await self.jf_pop_up(ticket)) and res.get("data", {}).get("score"):
                self.logger.log(f"爱听通知任务获得{res['data']['score']}积分", notify=True)
        other_tasks = [t for t in todo_list if "通知" not in t.get("taskName", "") and "阅读" not in t.get("taskName", "") and "听读" not in t.get("taskName", "") and "邀请" not in t.get("taskName", "") and "签到" not in t.get("taskName", "")]
        for task in other_tasks:
            remaining = (task.get("needCount", 1) or 1) - (task.get("finishCount", 0) or 0)
            if remaining <= 0: continue
            self.logger.log(f"爱听执行通用任务: {task.get('taskName')} (剩余{remaining}次)")
            for i in range(remaining):
                await self.jf_to_finish(ticket, task.get("taskCode"))
                await asyncio.sleep(2)
                await self.aiting_complete_task_api(4)
                if (res := await self.jf_pop_up(ticket)) and res.get("data", {}).get("score"):
                    self.logger.log(f"爱听通用任务获得{res['data']['score']}积分", notify=True)
                await asyncio.sleep(1.5)

    async def aiting_task(self):
        if not await self.aiting_login_flow(): return self.logger.log("爱听: 登录失败，跳过任务")
        self.aiting_biz_ticket = await self.aiting_get_ticket()
        if not self.aiting_biz_ticket: return self.logger.log("爱听: 获取Ticket失败")
        await self.aiting_sign_in()
        await self.aiting_do_tasks(self.aiting_biz_ticket)
        await self.jf_get_user_info(self.aiting_biz_ticket)

    async def user_task(self):
        if not await self.online(): return
        for task in [self.sign_task, self.ttlxj_task, self.ltzf_task, self.market_task, self.wostore_cloud_task, self.security_butler_task, self.shangdu_task, self.woread_task, self.aiting_task]: await task()

async def main():
    start_time = datetime.now()
    print(f"开始运行时间: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    if not (cookies := os.environ.get("chinaUnicomCookie", "")): return print("未找到 chinaUnicomCookie 环境变量")
    tasks = [CustomUserService(cookie, index=i + 1).user_task() for i, cookie in enumerate(cookies.split("@")) if cookie.strip()]
    if tasks: print(f"启动 {len(tasks)} 个账号任务 (并行模式)..."); await asyncio.gather(*tasks)
    print(f"\n运行结束, 总用时: {datetime.now() - start_time}")

if __name__ == "__main__": asyncio.run(main())

