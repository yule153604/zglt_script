# -*- coding: utf-8 -*-
"""
仅供学习交流：本项目仅供编程学习和技术交流使用，请勿用于任何商业用途。
合法使用：请勿将本脚本用于任何非法目的，包括但不限于恶意攻击、刷单等行为。
风险自担：使用本脚本产生的任何后果（包括但不限于账号封禁、财产损失等）由使用者自行承担，开发者不承担任何责任。
隐私保护：本项目不会收集用户的任何敏感信息，所有数据均保存在用户本地。
侵权联系：如果本项目侵犯了您的权益，请及时联系开发者进行处理。
"""

import asyncio
import base64
import hashlib
import json
import os
import random
import string
import time
from datetime import datetime
from functools import wraps
from urllib.parse import parse_qs, unquote, urlparse

import httpx
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# ====================  Decorators  ====================
def async_task(task_name=None):
    """异步任务装饰器：统一异常处理"""

    def decorator(func):
        @wraps(func)
        async def wrapper(self, *args, **kwargs):
            try:
                return await func(self, *args, **kwargs)
            except Exception as e:
                name = task_name or func.__name__.replace("_", " ").strip()
                self.logger.log(f"{name}异常: {e}")

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


# ====================  Constants  ====================
APP_VERSION = "iphone_c@11.0503"
SHOW_PRIZE_POOL = True  # 是否显示权益超市奖品池信息
USER_AGENT = f"Mozilla/5.0 (iPhone; CPU iPhone OS 16_1_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 unicom{{version:{APP_VERSION}}}"
APP_ID = "86b8be06f56ba55e9fa7dff134c6b16c62ca7f319da4a958dd0afa0bf9f36f1daa9922869a8d2313b6f2f9f3b57f2901f0021c4575e4b6949ae18b7f6761d465c12321788dcd980aa1a641789d1188bb"
CLIENT_ID = "73b138fd-250c-4126-94e2-48cbcc8b9cbe"

# ====================  Woread Constants  ====================
WOREAD_PRODUCT_ID = "10000002"
WOREAD_SECRET_KEY = "7k1HcDL8RKvc"
WOREAD_PASSWORD = "woreadst^&*12345"
WOREAD_IV = "16-Bytes--String"

# ====================  Wocare Constants  ====================
WOCARE_CHANNEL_ID = "beea1c7edf7c4989b2d3621c4255132f"
WOCARE_SIGN_KEY = "f4cd4ffeb5554586acf65ba7110534f5"
WOCARE_CHANNEL_TYPE = "wocareMBHServiceLife1"
WOCARE_VERSION = "1"

# ====================  Coupon Exchange Config (话费券兑换配置)  ====================
# True=开启兑换, False=关闭兑换
# 注意: 需要在抢兑时间段内才能兑换 (通常为 10:00-14:00, 18:00-22:00)
EXCHANGE_COUPON_CONFIG = {
    "1元话费券": False,  # 100积分, 满20元可用
    "3元话费券": False,  # 300积分, 满30元可用
    "5元话费券": True,  # 500积分, 满50元可用
    "10元话费券": True,  # 1000积分, 满100元可用
    "18元话费券": False,  # 1800积分, 满200元可用
}

# 话费券产品映射表 (名称 -> product_id)
COUPON_PRODUCT_MAP = {
    "1元话费券": "25122309441216995",
    "3元话费券": "25122309482612026",
    "5元话费券": "25122309512816188",
    "10元话费券": "25122309543215732",
    "18元话费券": "25122310293512803",
}

# 话费券积分需求表 (名称 -> 需要积分数, 积分=话费红包*100)
COUPON_POINTS_REQUIRED = {
    "1元话费券": 100,  # 需要1元话费红包
    "3元话费券": 300,  # 需要3元话费红包
    "5元话费券": 500,  # 需要5元话费红包
    "10元话费券": 1000,  # 需要10元话费红包
    "18元话费券": 1800,  # 需要18元话费红包
}


# ====================  Global Market Raffle State  ====================
# 全局奖池状态，多账号共享，只查询一次
class MarketRaffleState:
    def __init__(self):
        self.checked = False  # 是否已检查
        self.has_prizes = False  # 是否有奖品可抽
        self.prizes = []  # 奖品列表
        self.lock = asyncio.Lock()  # 异步锁

    async def check_prizes(self, http_client, market_token):
        """检查奖池状态，只执行一次"""

        def get_display_width(s):
            """计算字符串显示宽度（中文占2，英文占1）"""
            return sum(2 if ord(c) > 127 else 1 for c in s)

        def pad_to_width(s, target_width):
            """填充字符串到指定显示宽度"""
            return s + " " * max(0, target_width - get_display_width(s))

        async with self.lock:
            if self.checked:
                return self.has_prizes

            print("\n" + "=" * 70)
            print("权益超市奖品池查询")
            print("=" * 70)

            try:
                res = await http_client.request(
                    "POST",
                    "https://backward.bol.wo.cn/prod-api/promotion/home/raffleActivity/prizeList?id=12",
                    headers={"Authorization": f"Bearer {market_token}"},
                    json={},
                )

                result = res["result"]
                if (
                    result
                    and result.get("code") == 200
                    and isinstance(result.get("data"), list)
                ):
                    self.prizes = result["data"]

                    # 筛选任意中奖率>0的奖品
                    available_prizes = []
                    for p in self.prizes:
                        try:
                            prob = float(p.get("probability", 0))
                            prob_vip = float(p.get("probabilityVip", 0))
                            prob_new = float(p.get("newVipProbability", 0))
                        except (ValueError, TypeError):
                            prob = prob_vip = prob_new = 0.0
                        if prob > 0 or prob_vip > 0 or prob_new > 0:
                            available_prizes.append(p)

                    total = len(available_prizes)
                    print(f"今日奖池共 {total} 个奖品:\n")

                    # 表头
                    print(
                        f"{pad_to_width('奖品名称', 36)} {'普通':>6} {'VIP':>6} {'新会员':>6} {'Limit':>6}"
                    )
                    print("-" * 70)

                    for prize in available_prizes:
                        name = prize.get("name", "未知")
                        # 按显示宽度截断
                        if get_display_width(name) > 34:
                            while get_display_width(name) > 32:
                                name = name[:-1]
                            name = name + ".."
                        try:
                            prob = float(prize.get("probability", 0))
                            prob_vip = float(prize.get("probabilityVip", 0))
                            prob_new = float(prize.get("newVipProbability", 0))
                            daily_limit = int(prize.get("dailyPrizeLimit", 0))
                        except (ValueError, TypeError):
                            prob = prob_vip = prob_new = 0.0
                            daily_limit = 0

                        print(
                            f"{pad_to_width(name, 36)} {prob * 100:>5.0f}% {prob_vip * 100:>5.0f}% {prob_new * 100:>5.0f}% {daily_limit:>6}"
                        )

                    print("=" * 70 + "\n")
                    self.has_prizes = total > 0
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
# 全局打印锁，防止异步并发时日志输出混乱
_print_lock = asyncio.Lock()


# 辅助函数
def get_display_width(s):
    return sum(2 if ord(c) > 127 else 1 for c in s)


def pad_to_width(s, w):
    return s + " " * max(0, w - get_display_width(s))


class Logger:
    def __init__(self, prefix=""):
        self.prefix = prefix

    def log(self, message, notify=False):
        ts = datetime.now().strftime("%H:%M:%S")
        print(
            f"[{ts}] [{self.prefix}] {message}" if self.prefix else f"[{ts}] {message}",
            flush=True,
        )

    async def log_async(self, message, notify=False):
        async with _print_lock:
            self.log(message, notify)


class HttpClient:
    def __init__(self, logger_instance):
        self.logger = logger_instance
        self.headers = {"User-Agent": USER_AGENT, "Connection": "keep-alive"}
        self.cookies = httpx.Cookies()
        self.timeout, self.retries = 50.0, 3

    async def request(self, method, url, **kwargs):
        headers = {**self.headers, **kwargs.pop("headers", {})}
        cookies = kwargs.pop("cookies", self.cookies)

        for attempt in range(self.retries):
            try:
                async with httpx.AsyncClient(
                    cookies=cookies,
                    http2=False,
                    follow_redirects=False,
                    timeout=self.timeout,
                    verify=False,
                ) as client:
                    response = await client.request(
                        method, url, headers=headers, **kwargs
                    )
                    self.cookies.update(response.cookies)
                    try:
                        result = response.json()
                    except Exception:
                        result = response.text
                    return {
                        "statusCode": response.status_code,
                        "headers": response.headers,
                        "result": result,
                    }
            except Exception as e:
                if attempt == self.retries - 1:
                    self.logger.log(f"Request failed: {method} {url} - {e}")
                    return {"statusCode": -1, "headers": {}, "result": None}
                await asyncio.sleep(1 + attempt * 2)
        return {"statusCode": -1, "headers": {}, "result": None}

    # 快捷方法
    async def get(self, url, **kw):
        return await self.request("GET", url, **kw)

    async def post(self, url, **kw):
        return await self.request("POST", url, **kw)


# ====================  Market Encrypt (权益超市加解密)  ====================
class MarketEncrypt:
    KEY = "AB1BLc3Ak1yvClgT"

    @classmethod
    def decrypt(cls, text):
        """AES解密"""
        if not text or isinstance(text, dict):
            return text
        try:
            if text.strip().startswith(("{", "[")):
                return json.loads(text)
        except Exception:
            pass
        try:
            cipher = AES.new(cls.KEY.encode(), AES.MODE_ECB)
            return json.loads(
                unpad(cipher.decrypt(base64.b64decode(text)), AES.block_size).decode()
            )
        except Exception:
            return text

    @classmethod
    def encrypt(cls, data):
        """AES加密"""
        try:
            text = (
                json.dumps(data, separators=(",", ":"))
                if isinstance(data, (dict, list))
                else str(data)
            )
            cipher = AES.new(cls.KEY.encode(), AES.MODE_ECB)
            return base64.b64encode(
                cipher.encrypt(pad(text.encode(), AES.block_size))
            ).decode()
        except Exception:
            return data


class CustomUserService:
    def __init__(self, cookie, index=1):
        self.cookie, self.index = cookie, index
        self.logger = Logger(prefix=f"账号{index}")
        self.http = HttpClient(self.logger)
        self.valid, self.mobile, self.province = False, "", ""
        self.app_version = APP_VERSION
        self.token_online, self.app_id = cookie.strip(), APP_ID

        # 生成随机标识
        def rand_str(n, c=string.ascii_letters + string.digits):
            return "".join(random.choices(c, k=n))

        self.unicom_token_id = rand_str(32)
        self.token_id_cookie = "chinaunicom-" + rand_str(
            32, string.ascii_uppercase + string.digits
        )
        self.sdkuuid = self.unicom_token_id
        self.random_string = rand_str

        # 设置Cookie
        for name, val in [
            ("TOKENID_COOKIE", self.token_id_cookie),
            ("UNICOM_TOKENID", self.unicom_token_id),
            ("sdkuuid", self.sdkuuid),
        ]:
            self.http.cookies.set(name, val, domain=".10010.com")

        # Token存储
        self.rpt_id = self.market_token = self.xj_token = self.wocare_token = (
            self.wocare_sid
        ) = self.ecs_token = ""
        self.initial_telephone_amount = 0.0

    def get_bizchannelinfo(self):
        return json.dumps(
            {
                "bizChannelCode": "225",
                "disriBiz": "party",
                "unionSessionId": "",
                "stType": "",
                "stDesmobile": "",
                "source": "",
                "rptId": self.rpt_id,
                "ticket": "",
                "tongdunTokenId": self.token_id_cookie,
                "xindunTokenId": self.sdkuuid,
            }
        )

    def get_epay_authinfo(self):
        return json.dumps(
            {
                "mobile": "",
                "sessionId": getattr(self, "session_id", ""),
                "tokenId": getattr(self, "token_id", ""),
                "userId": "",
            }
        )

    # ====================  Login  ====================
    @async_task("登录")
    async def online(self):
        """Token登录"""
        data = {
            "token_online": self.token_online,
            "reqtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "appId": self.app_id,
            "version": self.app_version,
            "step": "bindlist",
            "isFirstInstall": 0,
            "deviceModel": "iPhone14,6",
            "deviceOS": "16.6",
            "deviceBrand": "iPhone",
            "uniqueIdentifier": "ios" + self.random_string(32, "0123456789abcdef"),
            "simOperator": "--,--,65535,65535,--@--,--,65535,65535,--",
            "voipToken": "citc-default-token-do-not-push",
        }
        res = await self.http.post(
            "https://m.client.10010.com/mobileService/onLine.htm",
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if (result := res["result"]) and str(result.get("code")) == "0":
            self.valid, self.mobile = True, result.get("desmobile", "")
            self.ecs_token = result.get("ecs_token", "")
            self.province = (result.get("list") or [{}])[0].get("proName", "")
            masked = (
                f"{self.mobile[:3]}****{self.mobile[-4:]}"
                if len(self.mobile) >= 11
                else self.mobile
            )
            self.logger.log(f"登录成功: {masked} (归属地: {self.province})")
            return True
        self.logger.log(f"登录失败: {result}")
        return False

    @async_task("获取ticket")
    async def open_plat_line_new(self, url):
        res = await self.http.get(
            "https://m.client.10010.com/mobileService/openPlatform/openPlatLineNew.htm",
            params={"to_url": url},
        )
        if location := (
            res["headers"].get("location") or res["headers"].get("Location")
        ):
            qs = parse_qs(urlparse(location).query)
            return {
                "ticket": qs.get("ticket", [""])[0],
                "type": qs.get("type", ["02"])[0],
                "loc": location,
            }
        self.logger.log("获取ticket失败: 无location")
        return {"ticket": "", "type": "", "loc": ""}

    # ====================  Sign Task  ====================
    async def sign_task(self):
        await self.sign_get_continuous()
        await self.sign_get_telephone(is_initial=True)
        await self.sign_task_center()
        await self.sign_get_telephone(is_initial=False)
        await self.sign_coupon_exchange()

    @async_task("签到区查询话费红包")
    async def sign_get_telephone(self, is_initial=False):
        res = await self.http.post(
            "https://act.10010.com/SigninApp/convert/getTelephone",
            data={},
            headers={"Referer": "https://img.client.10010.com/"},
        )
        if (
            (result := res["result"])
            and str(result.get("status")) == "0000"
            and (data := result.get("data"))
        ):
            current = float(data.get("telephone") or 0)
            if is_initial:
                self.initial_telephone_amount = current
                return
            increase = current - self.initial_telephone_amount
            msg = f"签到区-话费红包: 总额 {current:.2f}元，本次增加 {increase:.2f}元"
            if (need_exp := float(data.get("needexpNumber") or 0)) > 0:
                msg += f",其中 {need_exp}元 将于 {data.get('month')}月底到期"
            self.logger.log(msg, notify=True)
        else:
            self.logger.log(
                f"签到区查询话费红包失败: {result.get('msg') if result else ''}"
            )

    @async_task("查询签到状态")
    async def sign_get_continuous(self):
        res = await self.http.get(
            "https://activity.10010.com/sixPalaceGridTurntableLottery/signin/getContinuous",
            params={
                "taskId": "",
                "channel": "wode",
                "imei": "BB97982E-3F03-46D3-B904-819D626DF478",
            },
        )
        if (result := res["result"]) and str(result.get("code")) == "0000":
            signed = result.get("data", {}).get("todayIsSignIn", "n") != "n"
            self.logger.log(f"签到状态: {'已签到' if signed else '未签到'}")
            if not signed:
                await asyncio.sleep(1)
                await self.sign_day_sign()
        else:
            self.logger.log(f"查询签到状态失败: {result}")

    @async_task("签到")
    async def sign_day_sign(self):
        res = await self.http.post(
            "https://activity.10010.com/sixPalaceGridTurntableLottery/signin/daySign",
            data={},
        )
        if (result := res["result"]) and str(result.get("code")) == "0000":
            data = result.get("data", {})
            self.logger.log(
                f"签到成功: {data.get('statusDesc', '')} {data.get('redSignMessage', '')}",
                notify=True,
            )
        elif str(result.get("code")) == "0002" and "已经签到" in result.get("desc", ""):
            self.logger.log("签到成功: 今日已完成签到", notify=True)
        else:
            self.logger.log(f"签到失败: {result}")

    # ====================  Daily Cash (ttlxj)  ====================
    async def ttlxj_task(self):
        self.rpt_id = ""
        if (
            ticket_info := await self.open_plat_line_new(
                "https://epay.10010.com/ci-mps-st-web/?webViewNavIsHidden=webViewNavIsHidden"
            )
        )["ticket"]:
            await self.ttlxj_authorize(
                ticket_info["ticket"], ticket_info["type"], ticket_info["loc"]
            )

    @async_task("天天领现金授权")
    async def ttlxj_authorize(self, ticket, st_type, referer):
        data = {
            "response_type": "rptid",
            "client_id": CLIENT_ID,
            "redirect_uri": "https://epay.10010.com/ci-mps-st-web/",
            "login_hint": {
                "credential_type": "st_ticket",
                "credential": ticket,
                "st_type": st_type,
                "force_logout": True,
                "source": "app_sjyyt",
            },
            "device_info": {
                "token_id": f"chinaunicom-pro-{int(time.time() * 1000)}-{self.random_string(13)}",
                "trace_id": self.random_string(32),
            },
        }
        res = await self.http.post(
            "https://epay.10010.com/woauth2/v2/authorize",
            headers={"Origin": "https://epay.10010.com", "Referer": referer},
            json=data,
        )
        if res["statusCode"] == 200:
            await self.ttlxj_auth_check()
        else:
            self.logger.log(f"天天领现金授权失败: {res['result']}")

    @async_task("天天领现金认证")
    async def ttlxj_auth_check(self):
        res = await self.http.post(
            "https://epay.10010.com/ps-pafs-auth-front/v1/auth/check",
            headers={"bizchannelinfo": self.get_bizchannelinfo()},
        )
        result = res["result"]
        if str(result.get("code")) == "0000":
            auth = result.get("data", {}).get("authInfo", {})
            self.session_id, self.token_id = auth.get("sessionId"), auth.get("tokenId")
            await self.ttlxj_user_draw_info()
            await self.ttlxj_query_available()
        elif str(result.get("code")) == "2101000100":
            await self.ttlxj_login(result.get("data", {}).get("woauth_login_url"))
        else:
            self.logger.log(f"天天领现金认证失败: {result}")

    @async_task("天天领现金登录")
    async def ttlxj_login(self, login_url):
        res = await self.http.get(
            f"{login_url}https://epay.10010.com/ci-mcss-party-web/clockIn/?bizFrom=225&bizChannelCode=225&channelType=WDQB"
        )
        if location := (
            res["headers"].get("location") or res["headers"].get("Location")
        ):
            rpt_id = parse_qs(urlparse(location).query).get("rptid", [""])[0]
            if rpt_id:
                self.rpt_id = rpt_id
                await self.ttlxj_auth_check()
            else:
                self.logger.log("天天领现金获取rptid失败")
        else:
            self.logger.log("天天领现金获取rptid失败: 无location")

    @async_task("天天领现金查询")
    async def ttlxj_user_draw_info(self):
        res = await self.http.post(
            "https://epay.10010.com/ci-mcss-party-front/v1/ttlxj/userDrawInfo",
            headers={
                "bizchannelinfo": self.get_bizchannelinfo(),
                "authinfo": self.get_epay_authinfo(),
            },
        )
        if (result := res["result"]) and str(result.get("code")) == "0000":
            data = result.get("data", {})
            day_key = f"day{data.get('dayOfWeek')}"
            not_clocked = data.get(day_key) == "1"
            self.logger.log(
                f"天天领现金今天{'未' if not_clocked else '已'}打卡", notify=True
            )
            if not_clocked:
                draw_type = "C" if (datetime.now().weekday() + 1) % 7 == 0 else "B"
                await self.ttlxj_unify_draw_new(draw_type)
        else:
            self.logger.log(f"天天领现金查询失败: {result}")

    @async_task("天天领现金打卡")
    async def ttlxj_unify_draw_new(self, draw_type):
        res = await self.http.post(
            "https://epay.10010.com/ci-mcss-party-front/v1/ttlxj/unifyDrawNew",
            headers={
                "bizchannelinfo": self.get_bizchannelinfo(),
                "authinfo": self.get_epay_authinfo(),
            },
            data={
                "drawType": draw_type,
                "bizFrom": "225",
                "activityId": "TTLXJ20210330",
            },
        )
        if (
            (result := res["result"])
            and str(result.get("code")) == "0000"
            and str(result.get("data", {}).get("returnCode")) == "0"
        ):
            amount = result["data"].get("amount")
            msg = result["data"].get("awardTipContent", "").replace("xx", str(amount))
            self.logger.log(f"天天领现金打卡: {msg}", notify=True)
        else:
            self.logger.log(f"天天领现金打卡失败: {result}")

    @async_task("天天领现金查询余额")
    async def ttlxj_query_available(self):
        res = await self.http.post(
            "https://epay.10010.com/ci-mcss-party-front/v1/ttlxj/queryAvailable",
            headers={
                "bizchannelinfo": self.get_bizchannelinfo(),
                "authinfo": self.get_epay_authinfo(),
            },
        )
        if (
            (result := res["result"])
            and str(result.get("code")) == "0000"
            and str(result.get("data", {}).get("returnCode")) == "0"
        ):
            self.logger.log(
                f"可用立减金: {float(result['data'].get('availableAmount', 0)) / 100:.2f}元",
                notify=True,
            )
        else:
            self.logger.log(f"天天领现金查询余额失败: {result}")

    # ====================  Blessing (ltzf)  ====================
    async def ltzf_task(self):
        target_url = f"https://wocare.unisk.cn/mbh/getToken?channelType={WOCARE_CHANNEL_TYPE}&homePage=home&duanlianjieabc=qAz2m"
        if not (ticket_info := await self.open_plat_line_new(target_url))["ticket"]:
            return
        if not await self.wocare_get_token(ticket_info["ticket"]):
            return
        for task in [
            {"name": "星座配对", "id": 2},
            {"name": "大转盘", "id": 3},
            {"name": "盲盒抽奖", "id": 4},
        ]:
            await self.wocare_get_draw_task(task)
            await self.wocare_load_init(task)

    @async_task("联通祝福获取sid")
    async def wocare_get_token(self, ticket):
        params = {
            "channelType": WOCARE_CHANNEL_TYPE,
            "type": "02",
            "ticket": ticket,
            "version": APP_VERSION,
            "timestamp": datetime.now().strftime("%Y%m%d%H%M%S%f")[:-3],
            "desmobile": self.mobile,
            "num": 0,
            "postage": self.random_string(32),
            "homePage": "home",
            "duanlianjieabc": "qAz2m",
            "userNumber": self.mobile,
        }
        res = await self.http.get("https://wocare.unisk.cn/mbh/getToken", params=params)
        if res["statusCode"] == 302 and (
            loc := res["headers"].get("location") or res["headers"].get("Location")
        ):
            sid = parse_qs(urlparse(loc).query).get("sid", [""])[0]
            if sid:
                self.wocare_sid = sid
                return await self.wocare_loginmbh()
        self.logger.log("联通祝福获取sid失败")
        return False

    @async_task("联通祝福登录")
    async def wocare_loginmbh(self):
        res = await self.wocare_api(
            "loginmbh",
            {
                "sid": self.wocare_sid,
                "channelType": WOCARE_CHANNEL_TYPE,
                "apiCode": "loginmbh",
            },
        )
        if (result := res["result"]) and str(result.get("resultCode")) == "0000":
            token = result.get("data", {}).get("token")
            if token:
                self.wocare_token = token
                return True
            self.logger.log(f"联通祝福登录成功但无token: {result}")
        else:
            self.logger.log(f"联通祝福登录失败: {result}")
        return False

    def get_wocare_body(self, api_code, data):
        ts = datetime.now().strftime("%Y%m%d%H%M%S%f")[:-3]
        body = {
            "version": WOCARE_VERSION,
            "apiCode": api_code,
            "channelId": WOCARE_CHANNEL_ID,
            "transactionId": ts + self.random_string(6, string.digits),
            "timeStamp": ts,
            "messageContent": base64.b64encode(
                json.dumps(data, separators=(",", ":")).encode()
            ).decode(),
        }
        sign_str = (
            "&".join(f"{k}={body[k]}" for k in sorted(body))
            + f"&sign={WOCARE_SIGN_KEY}"
        )
        body["sign"] = hashlib.md5(sign_str.encode()).hexdigest()
        return body

    async def wocare_api(self, api_code, data):
        try:
            res = await self.http.post(
                f"https://wocare.unisk.cn/api/v1/{api_code}",
                data=self.get_wocare_body(api_code, data),
            )
            if (result := res["result"]) and (msg := result.get("messageContent")):
                try:
                    import re

                    msg = (
                        re.sub(r"[^a-zA-Z0-9+/=\-_]", "", msg)
                        .replace("-", "+")
                        .replace("_", "/")
                    )
                    msg += "=" * (4 - len(msg) % 4) if len(msg) % 4 else ""
                    parsed = json.loads(base64.b64decode(msg).decode())
                    result["data"] = parsed.get("data", parsed)
                    if parsed.get("resultMsg"):
                        result["resultMsg"] = parsed["resultMsg"]
                except Exception:
                    pass
            return res
        except Exception as e:
            self.logger.log(f"联通祝福API异常: {e}")
            return {"result": {}}

    @async_task("联通祝福查询任务")
    async def wocare_get_draw_task(self, task_info):
        res = await self.wocare_api(
            "getDrawTask",
            {
                "token": self.wocare_token,
                "channelType": WOCARE_CHANNEL_TYPE,
                "type": task_info["id"],
                "apiCode": "getDrawTask",
            },
        )
        if (result := res["result"]) and str(result.get("resultCode")) == "0000":
            for task in result.get("data", {}).get("taskList", []):
                if str(task.get("taskStatus")) == "0":
                    await self.wocare_complete_task(task_info, task)
        else:
            self.logger.log(f"联通祝福[{task_info['name']}]查询任务失败: {result}")

    @async_task("联通祝福完成任务")
    async def wocare_complete_task(self, task_info, task, step="1"):
        action = "领取任务" if step == "1" else "完成任务"
        res = await self.wocare_api(
            "completeTask",
            {
                "token": self.wocare_token,
                "channelType": WOCARE_CHANNEL_TYPE,
                "task": task["id"],
                "taskStep": step,
                "type": task_info["id"],
                "apiCode": "completeTask",
            },
        )
        if str(res["result"].get("resultCode")) == "0000":
            if step == "1":
                await self.wocare_complete_task(task_info, task, "4")
        else:
            self.logger.log(
                f"联通祝福[{task_info['name']}]{action}失败: {res['result']}"
            )

    @async_task("联通祝福查询活动")
    async def wocare_load_init(self, task_info):
        res = await self.wocare_api(
            "loadInit",
            {
                "token": self.wocare_token,
                "channelType": WOCARE_CHANNEL_TYPE,
                "type": task_info["id"],
                "apiCode": "loadInit",
            },
        )
        if (result := res["result"]) and str(result.get("resultCode")) == "0000":
            data = result.get("data", {})
            group_id = data.get("zActiveModuleGroupId")
            count = {
                2: 1 if not data.get("data", {}).get("isPartake") else 0,
                3: int(data.get("raffleCountValue", 0)),
                4: int(data.get("mhRaffleCountValue", 0)),
            }.get(task_info["id"], 0)
            for _ in range(count):
                await asyncio.sleep(2)
                await self.wocare_luck_draw(task_info, group_id)
        else:
            self.logger.log(f"联通祝福[{task_info['name']}]查询活动失败: {result}")

    @async_task("联通祝福抽奖")
    async def wocare_luck_draw(self, task_info, group_id):
        res = await self.wocare_api(
            "luckDraw",
            {
                "token": self.wocare_token,
                "channelType": WOCARE_CHANNEL_TYPE,
                "zActiveModuleGroupId": group_id,
                "type": task_info["id"],
                "apiCode": "luckDraw",
            },
        )
        if (result := res["result"]) and str(result.get("resultCode")) == "0000":
            prize = result.get("data", {}).get("data", {}).get("prize", {})
            self.logger.log(
                f"联通祝福[{task_info['name']}]抽奖: {prize.get('prizeName')} [{prize.get('prizeDesc')}]",
                notify=True,
            )
        else:
            self.logger.log(f"联通祝福[{task_info['name']}]抽奖失败: {result}")

    # ====================  Market (权益超市)  ====================
    async def market_task(self):
        if not await self.market_login():
            return
        await self.market_share_task()
        await self.market_watering_task()
        await self.market_raffle_task()
        await self.market_privilege_task()

    @async_task("权益超市登录")
    async def market_login(self):
        if not (
            ticket_info := await self.open_plat_line_new("https://contact.bol.wo.cn/")
        )["ticket"]:
            return False
        res = await self.http.post(
            f"https://backward.bol.wo.cn/prod-api/auth/marketUnicomLogin?ticket={ticket_info['ticket']}&channel=unicomTab",
            headers={"Content-Type": "application/json"},
            json={},
        )
        if (result := res["result"]) and result.get("code") == 200:
            self.market_token = result.get("data", {}).get("token")
            self.logger.log("权益超市登录成功")
            return True
        self.logger.log(f"权益超市登录失败: {result}")
        return False

    @async_task("分享小红书任务")
    async def market_share_task(self):
        """分享小红书任务，获取额外抽奖机会"""
        res = await self.http.get(
            "https://backward.bol.wo.cn/prod-api/promotion/activityTask/getAllActivityTasks?activityId=12",
            headers={"Authorization": f"Bearer {self.market_token}"},
        )
        if (
            not (result := MarketEncrypt.decrypt(res["result"]))
            or result.get("code") != 200
        ):
            self.logger.log(f"获取权益超市任务列表失败: {result}")
            return
        tasks = result.get("data", {}).get("activityTaskUserDetailVOList", [])
        if not (
            share_task := next((t for t in tasks if t.get("taskType") == 14), None)
        ):
            return
        if share_task.get("status") == 1 or share_task.get(
            "triggeredTime", 0
        ) >= share_task.get("triggerTime", 1):
            return
        if not (param1 := share_task.get("param1")):
            self.logger.log("分享小红书任务 param1 为空")
            return
        check_res = await self.http.post(
            f"https://backward.bol.wo.cn/prod-api/promotion/activityTaskShare/checkShare?checkKey={param1}",
            headers={
                "Authorization": f"Bearer {self.market_token}",
                "Origin": "https://contact.bol.wo.cn",
                "Referer": "https://contact.bol.wo.cn/",
                "Content-Length": "0",
            },
            data="",
        )
        if (
            not (check_result := MarketEncrypt.decrypt(check_res["result"]))
            or check_result.get("code") != 200
        ):
            self.logger.log(f"分享小红书任务失败: {check_result}")

    @async_task("权益超市浇花任务")
    async def market_watering_task(self):
        y_gdtco4r = "0hHgWnaEqWi0546ZdRfTeDqJdMBnv_KnzWG6CMU_1bgJe_DjIYJ6DF2QyCn39IVIop_Tl2MtZLEma_cOOBnd3rwlPuPDGi1VtWWYtqBx07xlMOjYRpb2aAZiH1jlx_PLjqQGzoPj1AUFWj9PwC1ELJq3oEw7mi.Vql7wNyVD4unkqvNgLlHPAB4jQSgOYaStVs9LtDqXn3Uw.6UKM2k1gpbGxW.lj8Oz0sNFL2dqf7HoG_5qG2_3427RzOlc8BTQC41UZTOVZWFgIzUN_5ieBSJuEPSrITbbJjOBKfau06OimtckkiRVxQAdTBLmSGvN0Iqp5sZcyRhPnAxWP7rDP1uWG5WMdzfW44SEwjr55XfNLUS.c7rSClxax2RBT3wP.xuYSxawy1OgFrQgIGLIJQx6.7LScnfvwchuTaf.aPkn53J2iXVfb6WPxm1BjYeFvjy1v8HuPMixeh3GGJPj_7rPLIbTUcsPYLwpLcdIbYU5bMjlqaxzfdbuUQnqAEUrh5Fqq2WUkHPwHTrnehvEbvBsn.YZksQODgRjV5Oa9lcbo5dD6fbPbO2E"
        res = await self.http.get(
            f"https://backward.bol.wo.cn/prod-api/promotion/activityTask/getMultiCycleProcess?activityId=13&yGdtco4r={y_gdtco4r}",
            headers={"Authorization": f"Bearer {self.market_token}"},
        )
        if (result := res["result"]) and result.get("code") == 200:
            triggered, total = (
                int(result.get("data", {}).get("triggeredTime", 0)),
                int(result.get("data", {}).get("triggerTime", 1)),
            )
            self.logger.log(f"浇花状态: {triggered}/{total}")
            if triggered < total:
                await self.market_watering()
            else:
                self.logger.log("浇花任务已全部完成")
        else:
            self.logger.log(f"获取浇花状态失败: {result}")

    @async_task("权益超市浇花")
    async def market_watering(self):
        res = await self.http.post(
            f"https://backward.bol.wo.cn/prod-api/promotion/activityTaskShare/checkWatering?xbsosjl=xbsosjlsujif&timeVerRan={int(time.time() * 1000)}",
            headers={"Authorization": f"Bearer {self.market_token}"},
            json={},
        )
        if (result := res["result"]) and result.get("code") == 200:
            self.logger.log("权益超市浇花成功", notify=True)
        else:
            self.logger.log(f"权益超市浇花失败: {result.get('msg', result)}")

    @async_task("权益超市人机验证")
    async def market_validate_captcha(self):
        res = await self.http.post(
            "https://backward.bol.wo.cn/prod-api/promotion/home/raffleActivity/validateCaptcha?id=12",
            headers={"Authorization": f"Bearer {self.market_token}"},
            data="",
        )
        if (result := res["result"]) and result.get("code") == 200:
            self.logger.log("权益超市: 人机验证通过，继续抽奖")
            return await self.market_raffle()
        self.logger.log(f"权益超市: 人机验证失败 {result}")
        return False

    @async_task("权益超市抽奖任务")
    async def market_raffle_task(self):
        res = await self.http.post(
            "https://backward.bol.wo.cn/prod-api/promotion/home/raffleActivity/getUserRaffleCount?id=12&channel=unicomTab",
            headers={"Authorization": f"Bearer {self.market_token}"},
            json={},
        )
        count = (
            res["result"].get("data", 0)
            if res["result"] and res["result"].get("code") == 200
            else 0
        )
        self.logger.log(f"权益超市可抽奖次数: {count}")
        for _ in range(count):
            await asyncio.sleep(4)
            await self.market_raffle()
        if SHOW_PRIZE_POOL:
            await market_raffle_state.check_prizes(self.http, self.market_token)

    @async_task("权益超市抽奖")
    async def market_raffle(self):
        res = await self.http.post(
            f"https://backward.bol.wo.cn/prod-api/promotion/home/raffleActivity/userRaffle?id=12&channel=unicomTab&timeVerRan={int(time.time() * 1000)}",
            headers={"Authorization": f"Bearer {self.market_token}"},
            json={},
        )
        if (result := res["result"]) and result.get("code") == 200:
            data = result.get("data", {})
            if data.get("isWinning") and (prize := data.get("prizesName")):
                self.logger.log(f"权益超市抽奖: 恭喜抽中 {prize}", notify=True)
            else:
                self.logger.log("权益超市抽奖: 未抽中")
            return True
        elif result and result.get("code") == 500:
            self.logger.log("权益超市: 触发人机验证，自动验证中...")
            return await self.market_validate_captcha()
        self.logger.log(f"权益超市抽奖失败: {result.get('msg', result)}")
        return False

    @async_task("优享权益")
    async def market_privilege_task(self):
        """优享权益: 每日领取一款权益"""
        if not self.market_token:
            return
        now = datetime.now()
        current_time = f"{now.year}-{now.month}-{now.day}"
        res = await self.http.post(
            "https://backward.bol.wo.cn/prod-api/promotion/activity/roll/getActivitiesDetail",
            headers={
                "Authorization": f"Bearer {self.market_token}",
                "Content-Type": "application/json",
                "Referer": "https://contact.bol.wo.cn/",
            },
            json={
                "majorId": 3,
                "subCodeList": ["YOUCHOICEONE"],
                "currentTime": current_time,
                "withUserStatus": 1,
            },
        )
        if not (result := res["result"]) or result.get("code") != 200:
            self.logger.log(f"优享权益: 获取活动详情失败 {result.get('msg', '')}")
            return
        if not (data_list := result.get("data", [])):
            return
        activity = data_list[0]
        if activity.get("userAvailableTimes", 0) <= 0:
            self.logger.log("优享权益: 今日已领取")
            return
        if not (detail_list := activity.get("detailList", [])):
            return
        available = [i for i in detail_list if int(i.get("leftQuantity", 0)) > 0]
        if not available:
            self.logger.log("优享权益: 所有权益均无库存")
            return
        # 分类并按sort降序
        surprise = sorted(
            [i for i in available if i.get("isSurprise") == 1],
            key=lambda x: int(x.get("sort", 0)),
            reverse=True,
        )
        normal = sorted(
            [i for i in available if i.get("isSurprise") != 1],
            key=lambda x: int(x.get("sort", 0)),
            reverse=True,
        )
        act_id, act_code = (
            activity.get("activityId"),
            activity.get("activityCode", "YOUCHOICEONE"),
        )

        for item in surprise + normal:
            name, pid, pcode = (
                item.get("productName", ""),
                item.get("id"),
                item.get("productCode", ""),
            )
            if item in surprise and item.get("isUnlock") == 0:
                if not await self._unlock_surprise_privilege(pid, act_code):
                    self.logger.log(f"优享权益: [{name}] 解锁失败")
                    continue
            if await self._receive_privilege(
                act_id,
                pid,
                pcode,
                item.get("channelId"),
                item.get("accountType", "4"),
                current_time,
            ):
                self.logger.log(f"优享权益: [{name}] 领取成功!", notify=True)
                return
            self.logger.log(f"优享权益: [{name}] 领取失败")
        self.logger.log("优享权益: 所有权益领取失败")

    async def _unlock_surprise_privilege(self, product_id, activity_code):
        """解锁惊喜权益"""
        try:
            res = await self.http.post(
                "https://backward.bol.wo.cn/prod-api/promotion/activity/roll/unlock/surpriseInterest",
                headers={
                    "Authorization": f"Bearer {self.market_token}",
                    "Content-Type": "application/json",
                    "Referer": "https://contact.bol.wo.cn/",
                },
                json={
                    "timeVerRan": int(time.time() * 1000),
                    "mobile": self.mobile,
                    "id": product_id,
                    "activityId": activity_code,
                },
            )
            return res["result"] and res["result"].get("code") == 200
        except Exception:
            return False

    async def _receive_privilege(
        self,
        activity_id,
        product_id,
        product_code,
        channel_id,
        account_type,
        current_time,
    ):
        """领取权益"""
        try:
            res = await self.http.post(
                "https://backward.bol.wo.cn/prod-api/promotion/activity/roll/receiveRights",
                headers={
                    "Authorization": f"Bearer {self.market_token}",
                    "Content-Type": "application/json",
                    "Referer": "https://contact.bol.wo.cn/",
                },
                json={
                    "channelId": channel_id,
                    "activityId": activity_id,
                    "productId": product_id,
                    "productCode": product_code,
                    "currentTime": current_time,
                    "accountType": account_type,
                },
            )
            return res["result"] and res["result"].get("code") == 200
        except Exception:
            return False

    # ====================  Xinjiang (xj)  ====================
    async def xj_task(self):
        if "新疆" not in self.province:
            return
        if not (
            ticket_info := await self.open_plat_line_new(
                "https://zy100.xj169.com/touchpoint/openapi/jumpHandRoom1G?source=155&type=02"
            )
        )["ticket"]:
            return
        if await self.xj_get_token(ticket_info["ticket"]):
            await self.xj_do_draw("Jan2026Act")

    @async_task("新疆联通获取Token")
    async def xj_get_token(self, ticket):
        res = await self.http.post(
            "https://zy100.xj169.com/touchpoint/openapi/getTokenAndCity",
            headers={
                "Referer": f"https://zy100.xj169.com/touchpoint/openapi/jumpHandRoom1G?source=155&type=02&ticket={ticket}",
                "X-Requested-With": "XMLHttpRequest",
                "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
            },
            data={"ticket": ticket},
        )
        if (result := res["result"]) and result.get("code") == 0:
            self.xj_token = result.get("data", {}).get("token")
            return True
        self.logger.log(f"新疆联通获取Token失败: {result}")
        return False

    @async_task("新疆联通抽奖")
    async def xj_do_draw(self, activity_id="dakaJan2026Act"):
        prize_dict = {
            "5Gksjhjhyyk": "5G宽视界黄金会员-月卡",
            "hfq_five": "5元话费券(50-5)",
            "hfq_ten": "10元话费券(100-10)",
            "aqyhjVIPhyyk": "爱奇艺黄金VIP会员-月卡",
            "ddkc30ydjq": "滴滴快车30元代金券",
            "jdPLUShyjdnk": "京东PLUS会员京典-年卡",
            "qybbxyk": "权益百宝箱-月卡",
            "xmlyVIPhynk": "喜马拉雅VIP会员-年卡",
            "mtwmhblly": "美团外卖红包66元",
            "thanks1": "未中奖",
        }
        res = await self.http.post(
            "https://zy100.xj169.com/touchpoint/openapi/marchAct/draw_Jan2026Act",
            headers={"userToken": self.xj_token, "X-Requested-With": "XMLHttpRequest"},
            data={"activityId": activity_id, "prizeId": ""},
        )
        msg = (result := res["result"]).get("msg") or result.get("data")
        if msg in prize_dict:
            self.logger.log(
                f"新疆联通[{activity_id}]抽奖结果: {prize_dict[msg]}", notify=True
            )
        elif result.get("code") in [0, "SUCCESS"]:
            self.logger.log(f"新疆联通[{activity_id}]成功: {msg}", notify=True)
        elif msg and ("已经打过卡" in msg or "机会已用完" in msg):
            self.logger.log(f"新疆联通[{activity_id}]: {msg}")
        else:
            self.logger.log(f"新疆联通[{activity_id}]失败: {msg}")

    async def xj_usersday_task(self):
        if "新疆" not in self.province:
            return
        if not (
            ticket_info := await self.open_plat_line_new(
                "https://zy100.xj169.com/touchpoint/openapi/jumpHandRoom1G?source=166&type=02"
            )
        )["ticket"]:
            return
        if not await self.xj_get_token(ticket_info["ticket"]):
            return
        day, hour = datetime.now().day, datetime.now().hour
        if hour >= 12:
            prize_id = (
                "hfq_twenty"
                if day in [19, 20]
                else ("right_kdjdjq_ten" if 21 <= day <= 25 else None)
            )
            if prize_id:
                await self.xj_usersday_draw(prize_id)
            else:
                self.logger.log("联通客户日: 今日无秒杀活动")
        else:
            self.logger.log("联通客户日: 未到12点秒杀时间")

    @async_task("客户日秒杀")
    async def xj_usersday_draw(self, prize_id):
        prize_dict = {
            "hfq_twenty": "20元话费券(100-20)",
            "right_kdjdjq_ten": "肯德基10元代金券",
        }
        res = await self.http.post(
            "https://zy100.xj169.com/touchpoint/openapi/marchAct/draw_UsersDay2025Act",
            headers={"userToken": self.xj_token, "X-Requested-With": "XMLHttpRequest"},
            data={"activityId": "usersDay2025Act", "prizeId": prize_id},
        )
        if (result := res["result"]) and result.get("code") in [0, "SUCCESS"]:
            self.logger.log(
                f"客户日秒杀成功: {prize_dict.get(prize_id, prize_id)}", notify=True
            )
        else:
            self.logger.log(
                f"客户日秒杀失败: {result.get('data') or result.get('msg')}"
            )

    # ====================  Cloud Phone (云手机)  ====================
    @async_task("云手机")
    async def wostore_cloud_task(self):
        """云手机活动: 积分签到、领取抽奖次数并抽奖"""
        if not (
            ticket_info := await self.open_plat_line_new(
                "https://h5forphone.wostore.cn/cloudPhone/dialogCloudPhone.html?channel_id=ST-Zujian001-gs&cp_id=91002997"
            )
        )["ticket"]:
            return
        if not (tokens := await self.wostore_cloud_login(ticket_info["ticket"])):
            return
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
        """使用 Ticket 登录获取 Token"""
        res = await self.http.post(
            "https://member.zlhz.wostore.cn/wcy_member/yunPhone/h5Awake/businessHall",
            json={
                "cpId": "91002997",
                "channelId": "ST-Zujian001-gs",
                "ticket": ticket,
                "env": "prod",
                "transId": "S2ndpage1235+开福袋！+F1+CJDD00D0001+iphone_c@12.0801",
                "qkActId": None,
            },
            headers={
                "Host": "member.zlhz.wostore.cn",
                "Origin": "https://h5forphone.wostore.cn",
                "Referer": f"https://h5forphone.wostore.cn/cloudPhone/dialogCloudPhone.html?channel_id=ST-Zujian001-gs&ticket={ticket}",
            },
        )
        if not ((result := res["result"]) and result.get("code") == "0"):
            return None
        redirect_url = result.get("data", {}).get("url", "")
        if "token=" not in redirect_url:
            return None
        first_token = redirect_url.split("token=")[1].split("&")[0]
        await asyncio.sleep(1)
        res2 = await self.http.post(
            "https://uphone.wostore.cn/h5api/activity-service/user/login",
            json={
                "identityType": "cloudPhoneLogin",
                "code": first_token,
                "channelId": "ST-Zujian001-gs",
                "activityId": "Lottery_251201",
                "device": "device",
            },
            headers={
                "Host": "uphone.wostore.cn",
                "Origin": "https://uphone.wostore.cn",
                "Referer": f"https://uphone.wostore.cn/h5/lt/December?ch=ST-Zujian001-gs&token={first_token}",
                "X-USR-TOKEN": first_token,
            },
        )
        if (result2 := res2["result"]) and result2.get("code") == 200:
            return (first_token, result2.get("data", {}).get("user_token"))
        return None

    @async_task("云手机积分签到")
    async def wostore_cloud_sign(self, user_token):
        res = await self.http.post(
            "https://uphone.wostore.cn/h5api/activity-service/points/v1/sign",
            json={"activityCode": "Points_Sign_2507"},
            headers={
                "Host": "uphone.wostore.cn",
                "Origin": "https://uphone.wostore.cn",
                "Referer": "https://uphone.wostore.cn/h5/lt/points",
                "X-USR-TOKEN": user_token,
            },
        )
        if (result := res["result"]) and result.get("code") == 200:
            self.logger.log(f"云手机积分签到: {result.get('msg', '成功')}")

    @async_task_silent
    async def wostore_cloud_task_list(self, user_token):
        await self.http.post(
            "https://uphone.wostore.cn/h5api/activity-service/user/task/list",
            json={"activityCode": "Lottery_251201"},
            headers={
                "Host": "uphone.wostore.cn",
                "Origin": "https://uphone.wostore.cn",
                "Referer": "https://uphone.wostore.cn/h5/lt/December?ch=ST-Zujian001-gs",
                "X-USR-TOKEN": user_token,
            },
        )

    @async_task_silent
    async def wostore_cloud_get_chance(self, user_token, task_code):
        await self.http.post(
            "https://uphone.wostore.cn/h5api/activity-service/user/task/raffle/get",
            json={"activityCode": "Lottery_251201", "taskCode": task_code},
            headers={
                "Host": "uphone.wostore.cn",
                "Origin": "https://uphone.wostore.cn",
                "Referer": "https://uphone.wostore.cn/h5/lt/December?ch=ST-Zujian001-gs",
                "X-USR-TOKEN": user_token,
            },
        )

    @async_task("云手机抽奖")
    async def wostore_cloud_draw(self, user_token):
        res = await self.http.post(
            "https://uphone.wostore.cn/h5api/activity-service/lottery",
            json={"activityCode": "Lottery_251201"},
            headers={
                "Host": "uphone.wostore.cn",
                "Origin": "https://uphone.wostore.cn",
                "Referer": "https://uphone.wostore.cn/h5/lt/December?ch=ST-Zujian001-gs",
                "X-USR-TOKEN": user_token,
            },
        )
        if (result := res["result"]) and result.get("code") == 200:
            self.logger.log(
                f"云手机抽奖: {result.get('prizeName', '未中奖')}", notify=True
            )
        elif result:
            self.logger.log(
                f"云手机抽奖失败: {result.get('msg') or result.get('message') or result.get('data') or result}"
            )

    # ====================  Sign Task Center (签到区-任务中心)  ====================
    @async_task("签到区-任务中心")
    async def sign_task_center(self):
        """签到区-任务中心: 获取任务列表、执行任务、领取奖励"""
        for _ in range(20):  # 防止死循环
            res = await self.http.get(
                "https://activity.10010.com/sixPalaceGridTurntableLottery/task/taskList",
                params={"type": 2},
                headers={"Referer": "https://img.client.10010.com/"},
            )
            if (
                str(result.get("code", "") if (result := res["result"]) else "")
                != "0000"
            ):
                return
            all_tasks = [
                t
                for tag in result.get("data", {}).get("tagList", [])
                for t in tag.get("taskDTOList", [])
            ]
            all_tasks.extend(result.get("data", {}).get("taskList", []))
            all_tasks = [t for t in all_tasks if t]
            if not all_tasks:
                break
            # 优先级1: 执行可执行的任务
            if do_task := next(
                (
                    t
                    for t in all_tasks
                    if t.get("taskState") == "1" and t.get("taskType") == "5"
                ),
                None,
            ):
                await self.sign_do_task_from_list(do_task)
                await asyncio.sleep(1)
                continue
            # 优先级2: 领取已完成任务的奖励
            if claim_task := next(
                (t for t in all_tasks if t.get("taskState") == "0"), None
            ):
                await self.sign_get_task_reward(claim_task.get("id"))
                await asyncio.sleep(1)
                continue
            break
        await self.sign_month_reward()

    @async_task_silent
    async def sign_month_reward(self):
        """签到区-月签到奖励"""
        res = await self.http.get(
            "https://activity.10010.com/sixPalaceGridTurntableLottery/floor/getMonthSign",
            headers={"Referer": "https://img.client.10010.com/"},
        )
        if str(result.get("code", "") if (result := res["result"]) else "") != "0000":
            return
        for task in result.get("data", {}).get("taskList", []):
            if str(task.get("taskStatus", "")) == "1":  # 待领取
                reward_res = await self.http.get(
                    "https://activity.10010.com/sixPalaceGridTurntableLottery/task/getTaskReward",
                    params={
                        "taskId": task.get("taskId", ""),
                        "taskType": "30",
                        "id": task.get("id", ""),
                    },
                    headers={"Referer": "https://img.client.10010.com/"},
                )
                if (
                    str(rr.get("code", "") if (rr := reward_res["result"]) else "")
                    == "0000"
                ):
                    data = rr.get("data", {})
                    if str(data.get("code", "")) == "0000":
                        self.logger.log(
                            f"签到区-月签奖励: [{task.get('taskName', '')}] {data.get('prizeName', '')}{data.get('prizeNameRed', '')}",
                            notify=True,
                        )
                await asyncio.sleep(1)

    @async_task("签到区-话费券兑换")
    async def sign_coupon_exchange(self):
        """签到区-话费券兑换: 根据配置尝试兑换话费券"""
        enabled_coupons = [
            name for name, enabled in EXCHANGE_COUPON_CONFIG.items() if enabled
        ]
        if not enabled_coupons or not (
            prize_list := await self._get_coupon_prize_list()
        ):
            return
        current_points = int(self.initial_telephone_amount * 100)
        for coupon_name in enabled_coupons:
            if not (product_id := COUPON_PRODUCT_MAP.get(coupon_name)):
                continue
            if not (
                prize_info := next(
                    (p for p in prize_list if p.get("product_id") == product_id), None
                )
            ):
                continue
            if (btn := prize_info.get("buttonDTO")) and btn.get(
                "name"
            ) == "面额已参与兑换":
                self.logger.log(f"签到区-话费券: [{coupon_name}] 今日已兑换")
                continue
            if int(prize_info.get("stockSurplus", 0)) <= 0:
                continue
            if current_points < (req := COUPON_POINTS_REQUIRED.get(coupon_name, 0)):
                self.logger.log(
                    f"签到区-话费券: [{coupon_name}] 积分不足 (需要{req}, 当前{current_points})"
                )
                continue
            for _ in range(3):
                await self._do_coupon_exchange(
                    product_id, prize_info.get("type_code", "21003_01")
                )
                await asyncio.sleep(0.5)
            await asyncio.sleep(1)
            if new_list := await self._get_coupon_prize_list():
                if new_info := next(
                    (p for p in new_list if p.get("product_id") == product_id), None
                ):
                    if (nb := new_info.get("buttonDTO")) and nb.get(
                        "name"
                    ) == "面额已参与兑换":
                        self.logger.log(
                            f"签到区-话费券: [{coupon_name}] 兑换成功!", notify=True
                        )
                    else:
                        self.logger.log(f"签到区-话费券: [{coupon_name}] 兑换失败")
                else:
                    self.logger.log(f"签到区-话费券: [{coupon_name}] 验证失败")
            await asyncio.sleep(1)

    async def _get_coupon_prize_list(self):
        """获取话费券奖品列表"""
        try:
            res = await self.http.post(
                "https://act.10010.com/SigninApp/new_convert/prizeList",
                headers={
                    "Referer": "https://img.client.10010.com/",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                data="",
            )
            if (result := res["result"]) and str(result.get("status", "")) == "0000":
                for tab in (
                    result.get("data", {}).get("datails", {}).get("tabItems", [])
                ):
                    if tab.get("defaultShowList") and tab.get("state") == "抢兑中":
                        return tab.get("timeLimitQuanListData", [])
        except Exception:
            pass
        return None

    async def _do_coupon_exchange(self, product_id, type_code):
        """执行话费券兑换"""
        try:
            uuid_res = await self.http.post(
                "https://act.10010.com/SigninApp/convert/prizeConvert",
                headers={
                    "Referer": "https://img.client.10010.com/",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                data=f"product_id={product_id}&typeCode={type_code}",
            )
            if not (
                (uuid_result := uuid_res["result"])
                and str(uuid_result.get("status", "")) == "0000"
            ):
                return False
            if not (uuid := uuid_result.get("data", {}).get("uuid", "")):
                return False
            exchange_res = await self.http.post(
                "https://act.10010.com/SigninApp/convert/prizeConvertResult",
                headers={
                    "Referer": "https://img.client.10010.com/",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                data=f"uuid={uuid}",
            )
            return (exchange_result := exchange_res["result"]) and str(
                exchange_result.get("status", "")
            ) == "0000"
        except Exception:
            return False

    @async_task_silent
    async def sign_do_task_from_list(self, task):
        """执行签到区任务"""
        if (url := task.get("url", "")) and url != "1" and url.startswith("http"):
            await self.http.get(
                url, headers={"Referer": "https://img.client.10010.com/"}
            )
            await asyncio.sleep(random.random() * 2)
        order_id = await self.get_task_order_id()
        await self.http.get(
            "https://activity.10010.com/sixPalaceGridTurntableLottery/task/completeTask",
            params={
                "taskId": task.get("id"),
                "orderId": order_id,
                "systemCode": "QDQD",
            },
        )

    async def get_task_order_id(self):
        """获取任务 orderId"""
        order_id = self.random_string(32).upper()
        try:
            await self.http.post(
                "https://m.client.10010.com/taskcallback/topstories/gettaskip",
                data={"mobile": self.mobile, "orderId": order_id},
            )
        except Exception:
            pass
        return order_id

    @async_task_silent
    async def sign_get_task_reward(self, task_id):
        """领取签到区任务奖励"""
        await self.http.get(
            "https://activity.10010.com/sixPalaceGridTurntableLottery/task/getTaskReward",
            params={"taskId": task_id},
        )

    # ====================  Security Butler (联通安全管家)  ====================
    SEC_UA = "ChinaUnicom4.x/12.3.1 (com.chinaunicom.mobilebusiness; build:77; iOS 16.6.0) Alamofire/4.7.3 unicom{version:iphone_c@12.0301}"

    @async_task("联通安全管家任务")
    async def security_butler_task(self):
        """联通安全管家: 执行各项安全任务获取积分"""
        if not self.ecs_token or not self.mobile:
            return
        self.sec_old_points = self.sec_ticket1 = self.sec_token = self.sec_ticket = (
            self.sec_jea_id
        ) = None
        await self._sec_get_ticket_by_native()
        await self._sec_get_auth_token()
        await self._sec_get_ticket_for_jf()
        if not self.sec_ticket or not self.sec_token:
            self.logger.log("安全管家获取票据失败，跳过任务")
            return
        await asyncio.sleep(1)
        await self._sec_get_user_info()
        await self._sec_execute_all_tasks()
        await asyncio.sleep(1)
        await self._sec_get_user_info()

    @async_task("安全管家获取ticket")
    async def _sec_get_ticket_by_native(self):
        ts = datetime.now().strftime("%Y%m%d%H%M%S")
        res = await self.http.get(
            f"https://m.client.10010.com/edop_ng/getTicketByNative?token={self.ecs_token}&appId=edop_unicom_3a6cc75a",
            headers={
                "Cookie": f"PvSessionId={ts}{self.unicom_token_id};c_mobile={self.mobile};c_version=iphone_c@11.0800;ecs_token={self.ecs_token}",
                "Accept": "*",
                "Connection": "keep-alive",
                "Content-Type": "application/x-www-form-urlencoded",
                "Host": "m.client.10010.com",
                "User-Agent": self.SEC_UA,
            },
        )
        if result := res["result"]:
            self.sec_ticket1 = result.get("ticket")

    @async_task("安全管家获取token")
    async def _sec_get_auth_token(self):
        if not self.sec_ticket1:
            return
        res = await self.http.post(
            "https://uca.wo116114.com/api/v1/auth/ticket?product_line=uasp&entry_point=h5&entry_point_id=edop_unicom_3a6cc75a",
            headers={
                "User-Agent": self.SEC_UA,
                "Content-Type": "application/json",
                "clientType": "uasp_unicom_applet",
            },
            json={"productId": "", "type": 1, "ticket": self.sec_ticket1},
        )
        if (result := res["result"]) and result.get("data"):
            self.sec_token = result["data"].get("access_token")

    @async_task("安全管家获取积分票据")
    async def _sec_get_ticket_for_jf(self):
        if not self.sec_token:
            return
        res = await self.http.post(
            "https://uca.wo116114.com/api/v1/auth/getTicket?product_line=uasp&entry_point=h5&entry_point_id=edop_unicom_3a6cc75a",
            headers={
                "User-Agent": self.SEC_UA,
                "Content-Type": "application/json",
                "auth-sa-token": self.sec_token,
                "clientType": "uasp_unicom_applet",
            },
            json={"productId": "91311616", "phone": self.mobile},
        )
        if not ((result := res["result"]) and result.get("data")):
            return
        self.sec_ticket = result["data"].get("ticket")
        res2 = await self.http.post(
            "https://m.jf.10010.com/jf-external-application/page/query",
            headers={
                "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 unicom{version:iphone_c@12.0301}",
                "partnersid": "1702",
                "ticket": unquote(self.sec_ticket) if self.sec_ticket else "",
                "clienttype": "uasp_unicom_applet",
            },
            json={"activityId": "s747395186896173056", "partnersId": "1702"},
        )
        if sc := (
            res2.get("headers", {}).get("set-cookie")
            or res2.get("headers", {}).get("Set-Cookie")
        ):
            for cookie in sc if isinstance(sc, list) else [sc]:
                if cookie and cookie.startswith("_jea_id="):
                    self.sec_jea_id = cookie.split(";")[0].split("=")[1]
                    break

    async def _sec_operate_blacklist(self, phone_number, op_type):
        """安全管家: 操作黑名单 (0=添加, 1=删除)"""
        try:
            json_data = {
                "productId": "91015539",
                "type": 1,
                "operationType": op_type,
                "contents": [
                    {
                        "content": phone_number,
                        "contentTag": "",
                        "nickname": None,
                        "configTime": None,
                    }
                ],
            }
            if op_type == 0:
                json_data["blacklistSource"] = 0
            res = await self.http.post(
                "https://uca.wo116114.com/sjgj/woAssistant/umm/configs/v1/config?product_line=uasp&entry_point=h5&entry_point_id=wxdefbc1986dc757a6",
                headers={
                    "User-Agent": self.SEC_UA,
                    "auth-sa-token": self.sec_token,
                    "clientType": "uasp_unicom_applet",
                    "token": self.sec_token,
                    "Content-Type": "application/json",
                },
                json=json_data,
            )
            return res["result"]
        except Exception as e:
            self.logger.log(f"安全管家操作黑名单异常: {e}")
            return None

    async def _sec_add_to_blacklist(self):
        """安全管家: 添加黑名单"""
        phone = "13088888888"
        if (result := await self._sec_operate_blacklist(phone, 0)) and (
            result.get("code") in ["0000", 0] or result.get("msg") == "成功"
        ):
            return
        if result and "号码已存在" in result.get("msg", ""):
            if (del_r := await self._sec_operate_blacklist(phone, 1)) and (
                del_r.get("code") in ["0000", 0] or "成功" in str(del_r.get("msg", ""))
            ):
                await asyncio.sleep(1)
                await self._sec_operate_blacklist(phone, 0)

    @async_task_silent
    async def _sec_mark_phone_number(self):
        await self.http.post(
            "https://uca.wo116114.com/sjgj/unicomAssistant/uasp/configs/v1/addressBook/saveTagPhone?product_line=uasp&entry_point=h5&entry_point_id=wxdefbc1986dc757a6",
            headers={
                "User-Agent": self.SEC_UA,
                "auth-sa-token": self.sec_token,
                "clientType": "uasp_unicom_applet",
                "Content-Type": "application/json",
            },
            json={
                "tagPhoneNo": "13088330789",
                "tagIds": [26],
                "status": 0,
                "productId": "91311616",
            },
        )

    @async_task_silent
    async def _sec_sync_address_book(self):
        await self.http.post(
            "https://uca.wo116114.com/sjgj/unicomAssistant/uasp/configs/v1/addressBookBatchConfig?product_line=uasp&entry_point=h5&entry_point_id=edop_unicom_3a6cc75a",
            headers={
                "User-Agent": self.SEC_UA,
                "auth-sa-token": self.sec_token,
                "clientType": "uasp_unicom_applet",
                "Content-Type": "application/json",
            },
            json={
                "addressBookDTOList": [
                    {"addressBookPhoneNo": "13088888888", "addressBookName": "水水"}
                ],
                "productId": "91311616",
                "opType": "1",
            },
        )

    @async_task_silent
    async def _sec_set_interception_rules(self):
        await self.http.post(
            "https://uca.wo116114.com/sjgj/woAssistant/umm/configs/v1/config?product_line=uasp&entry_point=h5&entry_point_id=wxdefbc1986dc757a6",
            headers={
                "User-Agent": self.SEC_UA,
                "auth-sa-token": self.sec_token,
                "clientType": "uasp_unicom_applet",
                "Content-Type": "application/json",
            },
            json={
                "contents": [
                    {
                        "name": "rings-once",
                        "contentTag": "8",
                        "contentName": "响一声",
                        "content": "0",
                        "icon": "alerting",
                    }
                ],
                "operationType": 0,
                "type": 3,
                "productId": "91311616",
            },
        )

    @async_task_silent
    async def _sec_view_weekly_summary(self):
        """安全管家: 查看周报"""
        sec_headers = {
            "auth-sa-token": self.sec_token,
            "clientType": "uasp_unicom_applet",
            "Content-Type": "application/json",
        }
        await self.http.post(
            "https://uca.wo116114.com/sjgj/unicomAssistant/uasp/configs/v1/weeklySwitchStatus?product_line=uasp&entry_point=h5&entry_point_id=wxdefbc1986dc757a6",
            headers=sec_headers,
            json={"productId": "91311616"},
        )
        await self.http.post(
            "https://uca.wo116114.com/sjgj/unicomAssistant/uasp/report/v1/queryKeyData?product_line=uasp&entry_point=h5&entry_point_id=wxdefbc1986dc757a6",
            headers=sec_headers,
            json={"productId": "91311616"},
        )
        await self.http.post(
            "https://uca.wo116114.com/sjgj/unicomAssistant/uasp/report/v1/weeklySummary?product_line=uasp&entry_point=h5&entry_point_id=wxdefbc1986dc757a6",
            headers=sec_headers,
            json={"productId": "91311616"},
        )

    @async_task_silent
    async def _sec_sign_in(self, task_code):
        await self.http.post(
            "https://m.jf.10010.com/jf-external-application/jftask/sign",
            headers={
                "ticket": unquote(self.sec_ticket) if self.sec_ticket else "",
                "Cookie": f"_jea_id={self.sec_jea_id}" if self.sec_jea_id else "",
                "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 unicom{version:iphone_c@12.0301}",
                "partnersid": "1702",
                "clienttype": "uasp_unicom_applet",
                "Content-Type": "application/json",
            },
            json={"taskCode": task_code},
        )

    @async_task_silent
    async def _sec_receive_points(self, task_code):
        await self.http.post(
            "https://m.jf.10010.com/jf-external-application/jftask/receive",
            headers={
                "ticket": unquote(self.sec_ticket) if self.sec_ticket else "",
                "Cookie": f"_jea_id={self.sec_jea_id}" if self.sec_jea_id else "",
                "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 unicom{version:iphone_c@12.0301}",
                "partnersid": "1702",
                "clienttype": "uasp_unicom_applet",
                "Content-Type": "application/json",
            },
            json={"taskCode": task_code},
        )

    @async_task("安全管家执行任务")
    async def _sec_finish_task(self, task_code, task_name):
        await self.http.post(
            "https://m.jf.10010.com/jf-external-application/jftask/toFinish",
            headers={
                "ticket": unquote(self.sec_ticket) if self.sec_ticket else "",
                "Cookie": f"_jea_id={self.sec_jea_id}" if self.sec_jea_id else "",
                "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 unicom{version:iphone_c@12.0301}",
                "partnersid": "1702",
                "clienttype": "uasp_unicom_applet",
                "Content-Type": "application/json",
            },
            json={"taskCode": task_code},
        )
        task_handlers = {
            "联通助理-添加黑名单": self._sec_add_to_blacklist,
            "联通助理-号码标记": self._sec_mark_phone_number,
            "联通助理-同步通讯录": self._sec_sync_address_book,
            "联通助理-骚扰拦截设置": self._sec_set_interception_rules,
            "联通助理-查看周报": self._sec_view_weekly_summary,
        }
        if handler := task_handlers.get(task_name):
            await handler()

    @async_task("安全管家执行所有任务")
    async def _sec_execute_all_tasks(self):
        sec_headers = {
            "ticket": unquote(self.sec_ticket) if self.sec_ticket else "",
            "Cookie": f"_jea_id={self.sec_jea_id}" if self.sec_jea_id else "",
            "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 unicom{version:iphone_c@12.0301}",
            "partnersid": "1702",
            "clienttype": "uasp_unicom_applet",
            "Content-Type": "application/json",
        }
        res = await self.http.post(
            "https://m.jf.10010.com/jf-external-application/jftask/taskDetail",
            headers=sec_headers,
            json={},
        )
        if (
            not (result := res["result"])
            or not result.get("data")
            or not result["data"].get("taskDetail")
        ):
            return self.logger.log("安全管家: 查询任务列表失败")

        executable_names = {
            "联通助理-添加黑名单",
            "联通助理-号码标记",
            "联通助理-同步通讯录",
            "联通助理-骚扰拦截设置",
            "联通助理-查看周报",
        }
        for task in result["data"]["taskDetail"].get("taskList", []):
            task_code, task_name = task.get("taskCode", ""), task.get("taskName", "")
            if task_name not in executable_names and "签到" not in task_name:
                continue
            if (remaining := task.get("needCount", 1) - task.get("finishCount", 0)) > 0:
                for _ in range(remaining):
                    await asyncio.sleep(1)
                    try:
                        if "签到" in task_name:
                            await self._sec_sign_in(task_code)
                            await self._sec_receive_points(task_code)
                            break
                        else:
                            await self._sec_finish_task(task_code, task_name)
                            await asyncio.sleep(1)
                            await self._sec_receive_points(task_code)
                    except Exception:
                        break
            elif task.get("finishText") == "待领取":
                await asyncio.sleep(1)
                await self._sec_receive_points(task_code)

    @async_task("安全管家获取积分")
    async def _sec_get_user_info(self):
        res = await self.http.post(
            "https://m.jf.10010.com/jf-external-application/jftask/userInfo",
            headers={
                "ticket": unquote(self.sec_ticket) if self.sec_ticket else "",
                "Cookie": f"_jea_id={self.sec_jea_id}" if self.sec_jea_id else "",
                "User-Agent": "Mozilla/5.0 (Linux; Android 9; ONEPLUS A5000) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.7204.179 Mobile Safari/537.36; unicom{version:android@11.0000}",
                "partnersid": "1702",
                "clienttype": "uasp_unicom_applet",
                "Content-Type": "application/json",
            },
            json={},
        )
        if (
            not (result := res["result"])
            or result.get("code") != "0000"
            or not result.get("data")
        ):
            return self.logger.log(
                f"安全管家: 查询积分失败: {result.get('msg') if result else '无响应'}"
            )
        current_points = int(result["data"].get("availableScore", 0))
        if self.sec_old_points is None:
            self.sec_old_points = current_points
        elif (gained := current_points - self.sec_old_points) > 0:
            self.logger.log(f"安全管家: 本次获得{gained}积分", notify=True)

    async def shangdu_task(self):
        if "河南" not in self.province:
            return
        if (ticket := await self.shangdu_get_ticket()) and await self.shangdu_login(
            ticket
        ):
            await asyncio.sleep(1)
            await self.shangdu_signin()

    async def shangdu_get_ticket(self):
        if not getattr(self, "ecs_token", None):
            self.logger.log("商都福利: 缺少 ecs_token，请检查是否已执行 online 登录")
            return None
        try:
            res = await self.http.get(
                "https://m.client.10010.com/edop_ng/getTicketByNative",
                params={"token": self.ecs_token, "appId": "edop_unicom_4b80047a"},
            )
            if isinstance((r := res["result"]), dict) and r.get("rsp_code") == "0000":
                return r.get("ticket")
            self.logger.log(f"商都福利: Ticket 获取失败 {r}")
            return None
        except Exception as e:
            self.logger.log(f"商都福利获取Ticket异常: {e}")
            return None

    async def shangdu_login(self, ticket):
        sd_headers = {
            "Host": "app.shangdu.com",
            "Origin": "https://app.shangdu.com",
            "Referer": "https://app.shangdu.com/monthlyBenefit/index.html",
            "edop_flag": "0",
            "Accept": "application/json, text/plain, */*",
        }
        try:
            res = await self.http.get(
                f"https://app.shangdu.com/monthlyBenefit/v1/common/config?ticket={ticket}",
                headers=sd_headers,
            )
            if isinstance((r := res["result"]), dict) and r.get("code") == "0000":
                return True
            self.logger.log(f"商都福利: 登录激活失败 {r}")
            return False
        except Exception as e:
            self.logger.log(f"商都福利登录异常: {e}")
            return False

    async def shangdu_get_sign_status(self):
        sd_headers = {
            "Host": "app.shangdu.com",
            "Origin": "https://app.shangdu.com",
            "Referer": "https://app.shangdu.com/monthlyBenefit/index.html",
            "edop_flag": "0",
            "Content-Type": "application/json",
        }
        try:
            res = await self.http.post(
                "https://app.shangdu.com/monthlyBenefit/v1/signIn/queryCumulativeSignAxis",
                headers=sd_headers,
                json={},
            )
            return (
                res["result"].get("data", {}).get("todaySignFlag") == "1"
                if isinstance(res["result"], dict)
                and res["result"].get("code") == "0000"
                else None
            )
        except Exception:
            return None

    @async_task("商都福利签到")
    async def shangdu_signin(self):
        sd_headers = {
            "Host": "app.shangdu.com",
            "Origin": "https://app.shangdu.com",
            "Referer": "https://app.shangdu.com/monthlyBenefit/index.html",
            "edop_flag": "0",
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/json",
        }
        res = await self.http.post(
            "https://app.shangdu.com/monthlyBenefit/v1/signIn/userSignIn",
            headers=sd_headers,
            json={},
        )
        if not isinstance((result := res["result"]), dict):
            return
        code = result.get("code")
        if code == "0000":
            data = result.get("data", {})
            if data.get("value") == "0001":
                return self.logger.log("商都福利: 签到失败 (Cookie无效/未登录)")
            prize_name = (data.get("prizeResp") or {}).get("prizeName", "")
            if str(data.get("signFlag", "")) == "1":
                self.logger.log(
                    f"商都福利签到成功: 获得 {prize_name}"
                    if prize_name
                    else "商都福利: 今日已签到",
                    notify=bool(prize_name),
                )
            else:
                self.logger.log(f"商都福利签到成功 (signFlag={data.get('signFlag')})")
        elif code == "0019":
            await asyncio.sleep(1)
            if (is_signed := await self.shangdu_get_sign_status()) is True:
                self.logger.log("商都福利: 今日已签到")
            elif is_signed is False:
                self.logger.log(
                    "商都福利: 服务端异常(返回重复签到但实际未签)，尝试重试..."
                )
                await asyncio.sleep(2)
                await self._shangdu_signin_retry()
            else:
                self.logger.log("商都福利: 今日已签到 (状态查询失败)")
        else:
            self.logger.log(
                f"商都福利签到失败: {result.get('msg') or result.get('desc') or ''} (code={code})"
            )

    @async_task_silent
    async def _shangdu_signin_retry(self):
        sd_headers = {
            "Host": "app.shangdu.com",
            "Origin": "https://app.shangdu.com",
            "Referer": "https://app.shangdu.com/monthlyBenefit/index.html",
            "edop_flag": "0",
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/json",
        }
        res = await self.http.post(
            "https://app.shangdu.com/monthlyBenefit/v1/signIn/userSignIn",
            headers=sd_headers,
            json={},
        )
        if isinstance((result := res["result"]), dict):
            code = result.get("code")
            if code == "0000":
                prize_name = (result.get("data", {}).get("prizeResp") or {}).get(
                    "prizeName", ""
                )
                self.logger.log(
                    f"商都福利签到成功(重试): 获得 {prize_name}"
                    if prize_name
                    else "商都福利签到成功(重试)",
                    notify=bool(prize_name),
                )
            elif code == "0019":
                self.logger.log("商都福利: 重试仍返回重复签到，请检查")
            else:
                self.logger.log(
                    f"商都福利签到重试失败: {result.get('msg') or result.get('desc') or ''}"
                )

    # ====================  Woread (联通阅读)  ====================

    def _woread_encode(self, data, password=WOREAD_PASSWORD):
        try:
            text = (
                json.dumps(data, separators=(",", ":"))
                if isinstance(data, (dict, list))
                else str(data)
            )
            cipher = AES.new(
                password.encode("utf-8"), AES.MODE_CBC, WOREAD_IV.encode("utf-8")
            )
            return base64.b64encode(
                cipher.encrypt(pad(text.encode("utf-8"), AES.block_size))
                .hex()
                .encode("utf-8")
            ).decode("utf-8")
        except Exception as e:
            self.logger.log(f"联通阅读加密异常: {e}")
            return ""

    async def woread_auth(self):
        try:
            timestamp = str(int(datetime.now().timestamp() * 1000))
            md5_hash = hashlib.md5(
                f"{WOREAD_PRODUCT_ID}{WOREAD_SECRET_KEY}{timestamp}".encode("utf-8")
            ).hexdigest()
            res = await self.http.post(
                f"https://10010.woread.com.cn/ng_woread_service/rest/app/auth/{WOREAD_PRODUCT_ID}/{timestamp}/{md5_hash}",
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "okhttp/3.14.9",
                },
                json={
                    "sign": self._woread_encode(
                        {"timestamp": datetime.now().strftime("%Y%m%d%H%M%S")}
                    )
                },
            )
            if (result := res["result"]) and str(result.get("code")) == "0000":
                self.woread_accesstoken = result.get("data", {}).get("accesstoken", "")
                return True
            self.logger.log(
                f"联通阅读预登录失败: {result.get('message', '') if result else '请求失败'}"
            )
            return False
        except Exception as e:
            self.logger.log(f"联通阅读预登录异常: {e}")
            return False

    async def woread_login(self):
        try:
            if not await self.woread_auth():
                return False
            if not getattr(self, "token_online", None):
                self.logger.log("联通阅读: 缺少 token_online")
                return False
            inner_json = json.dumps(
                {
                    "tokenOnline": self._woread_encode_str(self.token_online),
                    "phone": self._woread_encode_str(self.mobile),
                    "timestamp": datetime.now().strftime("%Y%m%d%H%M%S"),
                },
                separators=(",", ":"),
            )
            res = await self.http.post(
                "https://10010.woread.com.cn/ng_woread_service/rest/account/login",
                headers={
                    "accesstoken": self.woread_accesstoken,
                    "Content-Type": "application/json",
                    "User-Agent": "okhttp/3.14.9",
                },
                json={"sign": self._woread_encode_str(inner_json)},
            )

            if (result := res["result"]) and str(result.get("code")) == "0000":
                data = result.get("data", {})
                self.woread_token, self.woread_verifycode = (
                    data.get("token", ""),
                    data.get("verifycode", ""),
                )
                self.woread_userid, self.woread_userindex = (
                    data.get("userid", ""),
                    data.get("userindex", ""),
                )
                self.logger.log("联通阅读: 登录成功")
                return True
            self.logger.log(
                f"联通阅读登录失败: {result.get('msg', '') or result.get('message', '') if result else '请求失败'}"
            )
            return False
        except Exception as e:
            self.logger.log(f"联通阅读登录异常: {e}")
            return False

    def _woread_encode_str(self, text):
        try:
            cipher = AES.new(
                WOREAD_PASSWORD.encode("utf-8"), AES.MODE_CBC, WOREAD_IV.encode("utf-8")
            )
            return base64.b64encode(
                cipher.encrypt(pad(text.encode("utf-8"), AES.block_size))
                .hex()
                .encode("utf-8")
            ).decode("utf-8")
        except Exception as e:
            self.logger.log(f"联通阅读加密异常: {e}")
            return ""

    async def woread_get_book_info(self):
        wr_headers = {
            "accesstoken": self.woread_accesstoken,
            "User-Agent": "okhttp/3.14.9",
        }
        try:
            res = await self.http.get(
                "https://10010.woread.com.cn/ng_woread_service/rest/basics/recommposdetail/14856",
                headers=wr_headers,
            )
            if not (result := res["result"]) or str(result.get("code")) != "0000":
                self.logger.log("联通阅读: 获取书籍列表失败")
                return False
            data = result.get("data", {})
            booklist, bindinfo = (
                data.get("booklist", {}).get("message", []),
                data.get("bindinfo", []),
            )
            if not booklist or not bindinfo:
                self.logger.log("联通阅读: 获取书籍列表为空")
                return False
            self.wr_catid, self.wr_cardid, self.wr_cntindex = (
                booklist[0].get("catindex", ""),
                bindinfo[0].get("recommposiindex", ""),
                booklist[0].get("cntindex", ""),
            )
            if not self.wr_cntindex:
                return False
            res2 = await self.http.post(
                "https://10010.woread.com.cn/ng_woread_service/rest/cnt/chalist",
                headers={**wr_headers, "Content-Type": "application/json"},
                json={
                    "sign": self._woread_encode(
                        {
                            "curPage": 1,
                            "limit": 30,
                            "index": self.wr_cntindex,
                            "sort": 0,
                            "finishFlag": 1,
                            **self._get_woread_param(),
                        }
                    )
                },
            )
            if (chapters := (res2["result"] or {}).get("list", [])) and (
                chapter_content := chapters[0].get("charptercontent", [])
            ):
                self.wr_chapterallindex, self.wr_chapterid = (
                    chapter_content[0].get("chapterallindex", ""),
                    chapter_content[0].get("chapterid", ""),
                )
                return True
            return False
        except Exception as e:
            self.logger.log(f"联通阅读获取书籍异常: {e}")
            return False

    def _get_woread_param(self):
        return {
            "timestamp": datetime.now().strftime("%Y%m%d%H%M%S"),
            "token": getattr(self, "woread_token", ""),
            "userid": getattr(self, "woread_userid", ""),
            "userId": getattr(self, "woread_userid", ""),
            "userIndex": getattr(self, "woread_userindex", ""),
            "userAccount": self.mobile,
            "verifyCode": getattr(self, "woread_verifycode", ""),
        }

    @async_task("联通阅读模拟阅读")
    async def woread_read_process(self):
        if not await self.woread_get_book_info():
            return self.logger.log("联通阅读: 无法获取书籍信息，跳过阅读")
        wr_headers = {
            "accesstoken": self.woread_accesstoken,
            "Content-Type": "application/json",
            "User-Agent": "okhttp/3.14.9",
        }
        await self.http.post(
            f"https://10010.woread.com.cn/ng_woread_service/rest/cnt/wordsDetail?catid={self.wr_catid}&cardid={self.wr_cardid}&cntindex={self.wr_cntindex}&chapterallindex={self.wr_chapterallindex}&chapterseno=1",
            headers=wr_headers,
            json={
                "sign": self._woread_encode(
                    {
                        "chapterAllIndex": self.wr_chapterallindex,
                        "cntIndex": self.wr_cntindex,
                        "cntTypeFlag": "1",
                        **self._get_woread_param(),
                    }
                )
            },
        )
        await asyncio.sleep(1)
        add_param = {
            "readTime": "2",
            "cntIndex": self.wr_cntindex,
            "cntType": "1",
            "catid": "0",
            "pageIndex": "",
            "cardid": self.wr_cardid,
            "cntindex": self.wr_cntindex,
            "cnttype": "1",
            "chapterallindex": self.wr_chapterallindex,
            "chapterseno": "1",
            "channelid": "",
            "chapterid": self.wr_chapterid,
            "readtype": 1,
            "isend": "0",
            **self._get_woread_param(),
        }
        res = await self.http.post(
            "https://10010.woread.com.cn/ng_woread_service/rest/history/addReadTime",
            headers=wr_headers,
            json={"sign": self._woread_encode(add_param)},
        )
        self.logger.log(
            "联通阅读: 模拟阅读成功"
            if (result := res["result"]) and str(result.get("code")) == "0000"
            else f"联通阅读: 模拟阅读失败: {result.get('msg', '') if result else ''}"
        )

    @async_task("联通阅读抽奖")
    async def woread_draw_new(self):
        wr_headers = {
            "accesstoken": self.woread_accesstoken,
            "Content-Type": "application/json",
            "User-Agent": "okhttp/3.14.9",
        }
        res = await self.http.post(
            "https://10010.woread.com.cn/ng_woread_service/rest/basics/doDraw",
            headers=wr_headers,
            json={
                "sign": self._woread_encode(
                    {"activeindex": "8051", **self._get_woread_param()}
                )
            },
        )
        if (result := res["result"]) and str(result.get("code")) == "0000":
            self.logger.log(
                f"联通阅读抽奖: {result.get('data', {}).get('prizedesc', '未知奖品')}",
                notify=True,
            )
        else:
            msg = (
                result.get("msg", "") or result.get("message", "")
                if result
                else "请求失败"
            )
            self.logger.log(
                f"联通阅读: {msg}"
                if "已抽" in msg or "次数" in msg
                else f"联通阅读抽奖失败: {msg}"
            )

    @async_task_silent
    async def woread_queryTicketAccount(self):
        wr_headers = {
            "accesstoken": self.woread_accesstoken,
            "Content-Type": "application/json",
            "User-Agent": "okhttp/3.14.9",
        }
        res = await self.http.post(
            "https://10010.woread.com.cn/ng_woread_service/rest/phone/vouchers/queryTicketAccount",
            headers=wr_headers,
            json={"sign": self._woread_encode(self._get_woread_param())},
        )
        if (result := res["result"]) and str(result.get("code")) == "0000":
            self.logger.log(
                f"联通阅读话费红包余额: {float(result.get('data', {}).get('usableNum', 0)) / 100:.2f}元",
                notify=True,
            )

    async def woread_task(self):
        if not await self.woread_login():
            return self.logger.log("联通阅读: 登录失败，跳过任务")
        await self.woread_read_process()
        await self.woread_draw_new()
        await self.woread_queryTicketAccount()

    async def user_task(self):
        if not await self.online():
            return
        for task in [
            self.sign_task,
            self.ttlxj_task,
            self.ltzf_task,
            self.market_task,
            self.wostore_cloud_task,
            self.security_butler_task,
            self.shangdu_task,
            self.woread_task,
        ]:
            await task()


async def main():
    start_time = datetime.now()
    print(f"开始运行时间: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    if not (cookies := os.environ.get("chinaUnicomCookie", "")):
        return print("未找到 chinaUnicomCookie 环境变量")
    tasks = [
        CustomUserService(cookie, index=i + 1).user_task()
        for i, cookie in enumerate(cookies.split("@"))
        if cookie.strip()
    ]
    if tasks:
        print(f"启动 {len(tasks)} 个账号任务 (并行模式)...")
        await asyncio.gather(*tasks)
    print(f"\n运行结束, 总用时: {datetime.now() - start_time}")


if __name__ == "__main__":
    asyncio.run(main())
