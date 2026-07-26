import asyncio
import base64
import hashlib
import hmac
import json
import os
import threading
import random
import re
import string
import time
import traceback
import uuid
from collections.abc import Mapping
from datetime import datetime
from urllib.parse import parse_qs, quote, unquote, urljoin, urlparse

import httpx
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from gmssl import sm2


def read_int_env(name, default=None, minimum=None):
    """模块启动时读取整数环境变量。未设置才用 default；空/非整数/低于最小值 raise。"""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError) as e:
        raise ValueError(f"环境变量 {name}={raw!r} 不是合法整数") from e
    if minimum is not None and value < minimum:
        raise ValueError(f"环境变量 {name}={raw!r} 低于最小值 {minimum}")
    return value


# 常量
APP_VERSION = "iphone_c@11.0503"
UA = f"Mozilla/5.0 (iPhone; CPU iPhone OS 16_1_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 unicom{{version:{APP_VERSION}}}"
APP_ID = "86b8be06f56ba55e9fa7dff134c6b16c62ca7f319da4a958dd0afa0bf9f36f1daa9922869a8d2313b6f2f9f3b57f2901f0021c4575e4b6949ae18b7f6761d465c12321788dcd980aa1a641789d1188bb"
WOCARE_CH = (
    "beea1c7edf7c4989b2d3621c4255132f",
    "f4cd4ffeb5554586acf65ba7110534f5",
    "wocareMBHServiceLife1",
    "1",
)
SEC_UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15"

# 通通农场常量
TTXC_BASE_URL = "https://epay.10010.com/cu-ca-game-front"
TTXC_APP_BASE_URL = "https://epay.10010.com/cu-ca-app-front"
TTXC_CHANNEL = "225"
TTXC_REFERER = "https://epay.10010.com/cu-ca-game-web/index.html?channel=qdqp"
TTXC_UA = "Mozilla/5.0 (Linux; Android 10; MI 8 Build/QKQ1.190828.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/143.0.7499.146 Mobile Safari/537.36; unicom{version:android@11.0802,desmobile:0};devicetype{deviceBrand:Xiaomi,deviceModel:MI 8}"
TTXC_GARBAGE_WAIT_SECONDS = read_int_env(
    "UNICOM_TTXC_GARBAGE_WAIT", default=28, minimum=0
)
TTXC_GROW_MAX_CHARGE_PER_LAND = read_int_env(
    "UNICOM_TTXC_GROW_MAX_CHARGE_PER_LAND", default=20, minimum=0
)
TTXC_HARVEST_WAIT_SECONDS = read_int_env(
    "UNICOM_TTXC_HARVEST_WAIT", default=3, minimum=0
)
MARKET_WAIT_MAX_SECONDS = read_int_env("UNICOM_MARKET_WAIT_MAX", default=300, minimum=0)
MARKET_API_RETRIES = read_int_env("UNICOM_MARKET_API_RETRIES", default=3, minimum=1)
MARKET_API_RETRY_BASE_SECONDS = 0.5
TTXC_NEWBIE_STEPS = [
    "G01",
    "G02",
    "G03",
    "G03_2",
    "G04",
    "G05",
    "G09",
    "G10",
    "G11",
    "G12",
]

# 云盘活动签名密钥（上传大比拼等 panservice 活动共用）
CLOUD_PAN_SIGN_SECRET = "s8Hf3LqP9xN2vM5bR7tY1wZ4cA6eG0K"

CLOUD_BATTLE_ACTIVITY_ID = "MzA="
CLOUD_BATTLE_TOUCHPOINT = "300200030001"
CLOUD_BATTLE_UPLOAD_URL = "https://tjupload.pan.wo.cn/openapi/client/upload2C"
BATTLE_UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko)  unicom{version:iphone_c@12.1300};ltst;OSVersion/27.0"
)
CLOUD_BATTLE_FILEINFO_IV = "wNSOYIB1k1DjY5lA"
CLOUD_BATTLE_FILE_NAME = os.environ.get("UNICOM_CLOUD_BATTLE_FILE", "文本.txt")
CLOUD_BATTLE_FILE_CONTENT = os.environ.get("UNICOM_CLOUD_BATTLE_CONTENT", "1")

SHANGDU_BASE = "https://app.shangdu.com"
SHANGDU_ENTRY = f"{SHANGDU_BASE}/monthlyBenefit/static/index.html"
SHANGDU_UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko)  unicom{version:iphone_c@12.1300};ltst;OSVersion/27.0"
SHANGDU_SIGN_SECRET = "Hwsm6r3afijk8CP9d5F4nZu9DDyeMKMJxRpUqJqxCZ4sZuiyRU"
SHANGDU_SM2_PRIVATE_KEY = (
    "03659DDCBCA7513BDD930D4E19B8C216ECB714F1A70ACA2C155BCDD5886283F5"
)
SHANGDU_LOTTERY_PRIZES = [
    "5元话费券",
    "印鸽魔哒熊 电动牙刷",
    "DIY掌中宝照片书",
    "免费领麻布风手提包",
    "免费领定制抱枕套",
    "联通云盘 黄金会员-月卡",
    "爱奇艺黄金VIP会员-月卡",
    "腾讯视频VIP会员-月卡",
]
SHANGDU_LOTTERY_FESTIVAL_PRIZES = ["30元话费券", *SHANGDU_LOTTERY_PRIZES]
SHANGDU_LOTTERY_MAX = read_int_env("SHANGDU_LOTTERY_MAX", default=None, minimum=0)

# 云手机积分 / 夏日刮一刮 / 打卡挑战赛
UPHONE_H5API = "https://uphone.wostore.cn/h5api"
UPHONE_WO_ADV = "https://uphone.wo-adv.cn"
UPHONE_H5FORPHONE = "https://h5forphone.wostore.cn/h5forphone"
UPHONE_CHECKIN_PAGE = "https://h5forphone.wostore.cn/changXiangVip/CLD13.html"
UPHONE_CHANNEL = "ST-Wode"
UPHONE_CHANNEL_H5 = "ST-Jingang002"
UPHONE_EDOP_APP_ID = "edop_unicom_68e8fa69"
UPHONE_ACT_SIGN = "Points_Sign_2507"
UPHONE_ACT_OBTAIN = "Points_Obtain_2507"
UPHONE_ACT_EXCHANGE = "Points_Exchange_2507"
UPHONE_ACT_SUMMER = "HD2026062200218"
UPHONE_GOODS_LOTTERY_10 = "2026031010"
UPHONE_LOTTERY_COST = read_int_env("UNICOM_UPHONE_LOTTERY_COST", default=100, minimum=1)
UPHONE_OBTAIN_SKIP = frozenset({"012-4", "TASK2026010601"})
# 夏日刮一刮仅领此任务换抽奖次数，避免回退到 0514-001 等日限任务
UPHONE_SUMMER_CLAIM_TASK = "2508-01"
# 打卡挑战赛：需手填 QQ/微信 的奖品类型，跳过自动领取
UPHONE_CHECKIN_SKIP_ACTIVITY_TYPES = frozenset({2, "2"})
UPHONE_APP_UA = (
    "ChinaUnicom4.x/12.13 (com.chinaunicom.mobilebusiness; build:1; iOS 27.0.0) "
    "Alamofire/4.7.3 unicom{version:iphone_c@12.1300}"
)
UPHONE_H5_UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko)  unicom{version:iphone_c@12.1300};ltst;OSVersion/27.0"
)


def require_int(value, field, minimum=None):
    """必填业务整数：仅接受非 bool 的 int，或可由 int() 完整解析的 str；可选 minimum 下限。"""
    if isinstance(value, bool) or value is None:
        raise ValueError(f"{field}={value!r} 不是合法整数")
    if isinstance(value, int):
        n = value
    elif isinstance(value, str):
        try:
            n = int(value)
        except ValueError as e:
            raise ValueError(f"{field}={value!r} 不是合法整数") from e
    else:
        raise ValueError(f"{field}={value!r} 不是合法整数")
    if minimum is not None and n < minimum:
        raise ValueError(f"{field}={value!r} 低于最小值 {minimum}")
    return n


def safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def response_summary(res):
    if isinstance(res, dict):
        meta = res.get("meta") or {}
        if meta.get("message"):
            return str(meta.get("message"))
        if res.get("msg"):
            return str(res.get("msg"))
    return str(res)[:120]


def format_exception_detail(e, action=None):
    parts = []
    if action:
        parts.append(f"环节={action}")
    parts.append(f"{type(e).__name__}: {e}")
    if e.__traceback__:
        frames = traceback.extract_tb(e.__traceback__)
        if frames:
            f = frames[-1]
            parts.append(f"位置={os.path.basename(f.filename)}:{f.lineno}@{f.name}")
            if f.line:
                parts.append(f"代码={f.line.strip()}")
    if e.__cause__:
        parts.append(f"原因={type(e.__cause__).__name__}: {e.__cause__}")
    return " | ".join(parts)


def api_response_err(r, action=None):
    parts = []
    if action:
        parts.append(action)
    if not r:
        parts.append("无响应")
        return " | ".join(parts)
    if r.get("code") == -1:
        parts.append("网络/请求异常")
        if r.get("error"):
            parts.append(str(r["error"]))
        return " | ".join(parts)
    http = r.get("code")
    if http not in (200, 201, 302):
        parts.append(f"HTTP={http}")
    if r.get("error"):
        parts.append("协议/JSON解析错误")
        parts.append(str(r["error"]))
        return " | ".join(parts)
    data = r.get("data")
    if isinstance(data, dict):
        for k in (
            "code",
            "status",
            "resultCode",
            "desc",
            "msg",
            "message",
            "resultMsg",
            "resultDesc",
        ):
            v = data.get(k)
            if v not in (None, "", {}):
                parts.append(f"{k}={v}")
        if len(parts) == (1 if action else 0):
            parts.append(f"body={str(data)[:150]}")
    elif data is not None:
        text = str(data).strip()
        if text:
            parts.append(f"body={text[:150]}")
    elif http in (200, 201):
        parts.append("响应体为空")
    return " | ".join(parts)


def require_dict_data(r, action=None):
    data = r.get("data") if r else None
    if isinstance(data, dict):
        return data
    raise ValueError(api_response_err(r, action))


def is_retryable_api_response(r) -> bool:
    """网络超时、5xx、无 JSON 体等可重试；业务错误不重试。"""
    if not r:
        return True
    code = r.get("code")
    if code == -1:
        return True
    if isinstance(code, int) and code >= 500:
        return True
    if r.get("error") and not isinstance(r.get("data"), dict):
        return True
    return False


NOTIFY_LINES = []


def notify_send(title, content):
    # notify.py 的一言接口无超时、推送线程 join 也无超时，必须隔离，否则会卡死青龙任务槽
    os.environ.setdefault("HITOKOTO", "false")

    def _send():
        try:
            from notify import send
            send(title, content)
        except Exception as e:
            print(f"推送失败: {e}")

    worker = threading.Thread(target=_send, daemon=True)
    worker.start()
    worker.join(timeout=30)
    if worker.is_alive():
        print("推送超时 30s，放弃等待")


def iter_set_cookies(headers: httpx.Headers | Mapping[str, object]):
    """逐条产出 Set-Cookie 值，避免按逗号拆分误伤 Expires 日期。"""
    if isinstance(headers, httpx.Headers):
        for item in headers.get_list("set-cookie") or headers.get_list("Set-Cookie") or []:
            if item:
                yield item.strip()
        return
    sc = headers.get("set-cookie") or headers.get("Set-Cookie")
    if not sc:
        return
    if isinstance(sc, list):
        for item in sc:
            if item:
                yield item.strip()
    else:
        yield str(sc).strip()


class Unicom:
    def __init__(self, cookie, idx=1):
        self.cookie, self.idx = cookie.strip(), idx
        self.mobile = self.province = self.province_code = self.ecs_token = ""
        self.market_token = self.market_login_id = self.market_cycle_start_time = ""
        self.xj_token = self.wocare_token = self.wocare_sid = ""
        self.sec_ticket = self.sec_token = self.sec_jea_id = self.sec_key = ""
        self.session_id = self.token_id = self.rpt_id = ""
        self.ttxc_token = self.ttxc_nick_name = self.ttxc_user_id = ""
        self.ttxc_newbie_list = []
        self.ttxc_charge_level = {}
        self.ttxc_no_energy = False
        self.battle_page_referer = ""
        self.last_ticket_url = ""
        self.uphone_cp_token = self.uphone_usr_token = self.uphone_device_id = ""

        # 生成UUID用于签到
        self.uuid = str(uuid.uuid4())

        self.client = httpx.AsyncClient(
            http2=False,
            follow_redirects=False,
            timeout=50.0,
            headers={"User-Agent": UA, "Connection": "keep-alive"},
        )

        # 设置cookie
        self.unicom_token_id = "".join(
            random.choices(string.ascii_letters + string.digits, k=32)
        )
        tid = self.unicom_token_id
        for n, v in [
            ("TOKENID_COOKIE", f"chinaunicom-{tid}"),
            ("UNICOM_TOKENID", tid),
            ("sdkuuid", tid),
        ]:
            self.client.cookies.set(n, v, domain=".10010.com")

    def log(self, msg):
        line = f"[{datetime.now():%H:%M:%S}] [账号{self.idx}] {msg}"
        print(line, flush=True)
        NOTIFY_LINES.append(line)

    def task_log(self, tag, msg):
        line = f"[{datetime.now():%H:%M:%S}] [账号{self.idx}] [{tag}] {msg}"
        print(line, flush=True)
        NOTIFY_LINES.append(line)

    def tlog(self, msg):
        tag = getattr(self, "_task_tag", None)
        if tag:
            self.task_log(tag, msg)
        else:
            self.log(msg)

    def format_exc(self, e, action=None):
        return format_exception_detail(e, action)

    def log_exc(self, e, action=None):
        self.log(f"异常: {self.format_exc(e, action)}")

    def tlog_exc(self, e, action=None):
        self.tlog(f"异常: {self.format_exc(e, action)}")

    async def close(self):
        await self.client.aclose()

    async def req(self, method, url, **kw):
        allow_redirects = kw.pop("allow_redirects", True)
        try:
            r = await self.client.request(
                method, url, follow_redirects=allow_redirects, **kw
            )
        except httpx.RequestError as e:
            path = urlparse(url).path or url
            return {
                "code": -1,
                "headers": {},
                "data": None,
                "error": format_exception_detail(e, f"{method} {path}"),
            }
        body = r.text
        stripped = body.strip()
        if stripped.startswith(("{", "[")):
            try:
                data = json.loads(body)
            except json.JSONDecodeError as e:
                path = urlparse(url).path or url
                return {
                    "code": r.status_code,
                    "headers": r.headers,
                    "data": None,
                    "error": format_exception_detail(e, f"{method} {path}"),
                }
        else:
            data = body
        return {"code": r.status_code, "headers": r.headers, "data": data}

    async def get_ticket(self, url):
        r = await self.req(
            "GET",
            "https://m.client.10010.com/mobileService/openPlatform/openPlatLineNew.htm",
            params={"to_url": url},
            allow_redirects=False,
        )
        if loc := r["headers"].get("location") or r["headers"].get("Location"):
            # 完整落地页 URL 留给调用方当 Referer（woauth2 授权有 referer 校验）
            self.last_ticket_url = loc
            return parse_qs(urlparse(loc).query).get("ticket", [""])[0]
        return ""

    # === 登录 ===
    async def login(self):
        r = await self.req(
            "POST",
            "https://m.client.10010.com/mobileService/onLine.htm",
            data={
                "token_online": self.cookie,
                "reqtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "appId": APP_ID,
                "version": APP_VERSION,
                "step": "bindlist",
                "isFirstInstall": 0,
                "deviceModel": "iPhone14,6",
                "uniqueIdentifier": "ios"
                + "".join(random.choices("0123456789abcdef", k=32)),
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        res = r["data"]
        if not isinstance(res, dict):
            self.log(f"登录失败: {api_response_err(r, '在线登录')}")
            return False
        if str(res.get("code")) == "0":
            self.mobile, self.ecs_token = (
                str(res.get("desmobile") or ""),
                str(res.get("ecs_token") or ""),
            )
            list_data = res.get("list") if isinstance(res.get("list"), list) else []
            city_info = (
                list_data[0] if list_data and isinstance(list_data[0], dict) else {}
            )
            self.province = str(city_info.get("proName") or "")
            pro_code = str(
                city_info.get("proCode") or city_info.get("standardProvinceCode") or ""
            )
            self.province_code = pro_code.lstrip("0") or pro_code
            self.log(
                f"登录成功: {self.mobile[:3]}****{self.mobile[-4:]} ({self.province})"
            )
            if self.ecs_token:
                self.client.cookies.set(
                    "ecs_token", self.ecs_token, domain=".10010.com"
                )

            # 云盘登录
            await self.cloudpan_login()

            return True
        self.log(f"登录失败: {api_response_err(r, '在线登录')}")
        return False

    async def cloudpan_login(self):
        """云盘登录获取userToken"""
        try:
            if not self.ecs_token:
                return

            # 获取ticket
            r = await self.req(
                "GET",
                "https://m.client.10010.com/edop_ng/getTicketByNative",
                params={"appId": "edop_unicom_d67b3e30", "token": self.ecs_token},
            )
            ticket = r["data"].get("ticket") if isinstance(r["data"], dict) else None
            if not ticket:
                return

            # 获取userToken
            timestamp = str(int(time.time() * 1000))
            rnd = str(random.randint(123456, 199999))
            sign = hashlib.md5(
                f"HandheldHallAutoLoginV2{timestamp}{rnd}wohome".encode()
            ).hexdigest()

            r = await self.req(
                "POST",
                "https://panservice.mail.wo.cn/wohome/dispatcher",
                headers={
                    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12; leijun Pro Build/SKQ1.22013.001)"
                },
                json={
                    "header": {
                        "key": "HandheldHallAutoLoginV2",
                        "resTime": timestamp,
                        "reqSeq": rnd,
                        "channel": "wohome",
                        "version": "",
                        "sign": sign,
                    },
                    "body": {"clientId": "1001000003", "ticket": ticket},
                },
            )

            if isinstance(r["data"], dict):
                # 尝试两种响应格式
                token = r["data"].get("body", {}).get("token", "") or r["data"].get(
                    "RSP", {}
                ).get("DATA", {}).get("token", "")
                if token:
                    self.cloud_disk = {"userToken": token}
                else:
                    self.log(f"云盘登录失败: {api_response_err(r, '获取userToken')}")
        except Exception as e:
            self.log_exc(e, "云盘登录")

    # === 1. 首页签到 ===
    async def sign_get_task_ip(self):
        """上报任务 IP；本地 orderId 始终可用。接口常返回非标准 JSON，失败不刷屏。"""
        order_id = "".join(random.choices(string.ascii_uppercase + string.digits, k=32))
        r = await self.req(
            "POST",
            "https://m.client.10010.com/taskcallback/topstories/gettaskip",
            data={"mobile": self.mobile, "orderId": order_id},
        )
        # 协议/JSON 脏响应极常见且不影响 completeTask，静默；仅真实断网首次提示
        if r.get("code") == -1 and not getattr(self, "_gettaskip_net_warned", False):
            self._gettaskip_net_warned = True
            self.tlog(f"gettaskip网络失败(后续忽略): {api_response_err(r, 'gettaskip')}")
        return order_id

    async def sign_get_continuous(self):
        r = await self.req(
            "GET",
            "https://activity.10010.com/sixPalaceGridTurntableLottery/signin/getContinuous",
            params={"taskId": "", "channel": "wode", "imei": self.uuid},
        )
        res = require_dict_data(r, "查询签到状态")
        if str(res.get("code")) != "0000":
            err = api_response_err(r, "查询签到状态")
            self.tlog(f"查询签到状态失败: {err}")
            return
        signed = res.get("data", {}).get("todayIsSignIn", "n") == "y"
        self.tlog(f"今天{'已' if signed else '未'}签到")
        if not signed:
            await asyncio.sleep(1)
            await self.sign_day_sign()

    async def sign_day_sign(self):
        r = await self.req(
            "POST",
            "https://activity.10010.com/sixPalaceGridTurntableLottery/signin/daySign",
            data={},
        )
        res = require_dict_data(r, "每日签到")
        code = str(res.get("code", ""))
        if code == "0000":
            data = res.get("data", {}) or {}
            self.tlog(
                f"签到成功: [{data.get('statusDesc', '')}]{data.get('redSignMessage', '')}"
            )
        elif code == "0002" and "已经签到" in str(res.get("desc", "")):
            self.tlog("签到成功: 今日已完成签到！")
        else:
            self.tlog(f"签到失败[{code}]: {res.get('desc', '')}")

    async def sign_get_telephone(self, is_initial=False):
        r = await self.req(
            "POST", "https://act.10010.com/SigninApp/convert/getTelephone", data={}
        )
        res = require_dict_data(r, "查询话费红包")
        if str(res.get("status")) != "0000" or not res.get("data"):
            self.tlog(f"查询话费红包失败: {api_response_err(r, '查询话费红包')}")
            return None
        tel_val = res["data"].get("telephone", 0)
        try:
            amount = float(tel_val)
        except (TypeError, ValueError):
            amount = 0.0
        if is_initial:
            self.sign_initial_amount = amount
            self.tlog(f"话费红包: 运行前总额 {amount:.2f}元")
        else:
            if hasattr(self, "sign_initial_amount"):
                self.tlog(
                    f"话费红包: 本次运行增加 {amount - self.sign_initial_amount:.2f}元"
                )
            msg = f"话费红包: 总额 {amount:.2f}元"
            try:
                exp_num = float(res["data"].get("needexpNumber", 0) or 0)
            except (TypeError, ValueError):
                exp_num = 0.0
            if exp_num > 0:
                msg += f"，其中 {res['data'].get('needexpNumber', '0')}元 将于 {res['data'].get('month', '')}月底到期"
            self.tlog(msg)
        return amount

    async def sign_do_task_from_list(self, task):
        url = task.get("url") or ""
        if url != "1" and url.startswith("http"):
            await self.req(
                "GET", url, headers={"Referer": "https://img.client.10010.com/"}
            )
            self.tlog(f"任务中心: 浏览页面 [{task.get('taskName')}]")
            await asyncio.sleep(random.uniform(5, 7))
        order_id = await self.sign_get_task_ip()
        r = await self.req(
            "GET",
            "https://activity.10010.com/sixPalaceGridTurntableLottery/task/completeTask",
            params={
                "taskId": task.get("id"),
                "orderId": order_id,
                "systemCode": "QDQD",
            },
        )
        res = require_dict_data(r, "完成签到任务")
        code = str(res.get("code", ""))
        if code == "0000":
            self.tlog(f"任务中心: 任务 [{task.get('taskName')}] 已完成")
        else:
            self.tlog(
                f"任务中心: 任务 [{task.get('taskName')}] 完成失败[{code}]: {res.get('desc', '未知错误')}"
            )

    async def sign_get_task_reward(self, task_id, task_type=None, record_id=None):
        params = {"taskId": task_id}
        if task_type is not None:
            params["taskType"] = task_type
        if record_id is not None:
            params["id"] = record_id
        headers = (
            {"Referer": "https://img.client.10010.com/"}
            if task_type is not None
            else None
        )
        r = await self.req(
            "GET",
            "https://activity.10010.com/sixPalaceGridTurntableLottery/task/getTaskReward",
            params=params,
            headers=headers or {},
        )
        res = require_dict_data(r, "领取任务奖励")
        code = str(res.get("code", ""))
        data = res.get("data", {}) or {}
        if code == "0000" and str(data.get("code", "")) == "0000":
            prize = (
                f"[{data.get('prizeName', '')}] {data.get('prizeNameRed', '')}".strip()
            )
            self.tlog(f"领取奖励: {prize or data.get('statusDesc', '领取成功')}")
        else:
            self.tlog(
                f"领取奖励失败[{data.get('code') or code}]: {data.get('desc') or res.get('desc', '')}"
            )

    async def sign_get_task_list(self):
        url = "https://activity.10010.com/sixPalaceGridTurntableLottery/task/taskList"
        headers = {"Referer": "https://img.client.10010.com/"}
        for i in range(30):
            r = await self.req("GET", url, params={"type": "2"}, headers=headers)
            res = require_dict_data(r, "查询任务列表")
            code = str(res.get("code", ""))
            if code == "0329" or "火爆" in str(res.get("desc", "")):
                self.tlog("系统繁忙(0329)，停止后续尝试")
                break
            if code != "0000":
                self.tlog(f"任务中心: 获取任务列表失败[{code}]: {res.get('desc', '')}")
                return
            tag_list = res.get("data", {}).get("tagList", []) or []
            task_list = res.get("data", {}).get("taskList", []) or []
            all_tasks = task_list + [
                t for tag in tag_list for t in tag.get("taskDTOList", [])
            ]
            all_tasks = [t for t in all_tasks if t]
            if not all_tasks:
                if i == 0:
                    self.tlog("任务中心: 当前无任何任务。")
                break
            do_task = next(
                (
                    t
                    for t in all_tasks
                    if t.get("taskState") == "1" and t.get("taskType") == "5"
                ),
                None,
            )
            if do_task:
                self.tlog(f"任务中心: 开始执行任务 [{do_task.get('taskName')}]")
                await self.sign_do_task_from_list(do_task)
                await asyncio.sleep(3)
                continue
            claim_task = next((t for t in all_tasks if t.get("taskState") == "0"), None)
            if claim_task:
                self.tlog(
                    f"任务中心: 发现可领取奖励的任务 [{claim_task.get('taskName')}]"
                )
                await self.sign_get_task_reward(claim_task.get("id"))
                await asyncio.sleep(2)
                continue
            if i == 0:
                self.tlog("任务中心: 没有可执行或可领取的任务。")
            else:
                self.tlog("任务中心: 所有任务处理完毕。")
            break

    async def sign_get_month_sign_reward(self, task):
        task_name = task.get("taskName") or "月签奖励"
        r = await self.req(
            "GET",
            "https://activity.10010.com/sixPalaceGridTurntableLottery/task/getTaskReward",
            params={
                "taskId": task.get("taskId"),
                "taskType": "30",
                "id": task.get("id"),
            },
            headers={"Referer": "https://img.client.10010.com/"},
        )
        res = require_dict_data(r, "领取月签奖励")
        code = str(res.get("code", ""))
        data = res.get("data", {}) or {}
        if code == "0000" and str(data.get("code", "")) == "0000":
            prize_name = data.get("prizeName", "")
            prize_red = data.get("prizeNameRed", "")
            reward = (
                f"[{prize_name}] {prize_red}".strip()
                if prize_name or prize_red
                else data.get("statusDesc", "领取成功")
            )
            self.tlog(f"月签有礼: [{task_name}] {reward}")
        else:
            msg = data.get("desc") or res.get("desc") or res.get("msg") or "未知错误"
            self.tlog(
                f"月签有礼: [{task_name}] 领取失败[{data.get('code') or code}]: {msg}"
            )

    async def sign_month_sign_gift(self):
        r = await self.req(
            "GET",
            "https://activity.10010.com/sixPalaceGridTurntableLottery/floor/getMonthSign",
            headers={"Referer": "https://img.client.10010.com/"},
        )
        res = require_dict_data(r, "查询月签有礼")
        if str(res.get("code")) != "0000":
            self.tlog(f"月签有礼: 查询失败[{res.get('code')}]: {res.get('desc', '')}")
            return
        task_list = res.get("data", {}).get("taskList", []) or []
        if not task_list:
            self.tlog("月签有礼: 暂无月签任务")
            return
        claim_tasks = [
            t
            for t in task_list
            if str(t.get("taskStatus")) == "1" and t.get("taskId") and t.get("id")
        ]
        claimed_count = sum(1 for t in task_list if str(t.get("taskStatus")) == "2")
        if not claim_tasks:
            self.tlog(
                f"月签有礼: 暂无可领取奖励，已领取 {claimed_count}/{len(task_list)}"
            )
            return
        for task in claim_tasks:
            await self.sign_get_month_sign_reward(task)
            await asyncio.sleep(1)

    async def sign_query_my_prizes(self):
        r = await self.req(
            "POST",
            "https://act.10010.com/SigninApp/convert/phoneDetails",
            data={"log_type": "1", "number": "1", "list_num": ""},
            headers={"Origin": "https://img.client.10010.com"},
        )
        res = require_dict_data(r, "查询账户明细")
        if str(res.get("status")) != "0000":
            return
        data = res.get("data", {}).get("detailedBO", []) or []
        logged = 0
        for item in data:
            if logged >= 5:
                break
            remark = item.get("remark", "")
            buss_name = item.get("from_bussname", "")
            if "兑换" not in remark and "兑换" not in buss_name:
                continue
            if logged == 0:
                self.tlog("账户明细: 最近兑换记录")
            self.tlog(
                f"  {item.get('order_time', '')} | {remark} (变动:{item.get('booksNumber') or item.get('books_number') or '0'})"
            )
            logged += 1

    async def sign_task(self):
        self._task_tag = "签到区"
        self.tlog("开始")
        await self.sign_get_telephone(is_initial=True)
        await self.sign_get_continuous()
        await self.sign_month_sign_gift()
        await self.sign_get_task_list()
        await self.sign_get_telephone()
        await self.sign_query_my_prizes()

    # === 2. 权益超市 ===
    def market_auth_headers(self):
        return {
            "Authorization": f"Bearer {self.market_token}",
            "Content-Type": "application/json",
        }

    @staticmethod
    def market_current_date():
        """对齐 HAR：currentTime 不补零，如 2026-7-7"""
        now = datetime.now()
        return f"{now.year}-{now.month}-{now.day}"

    @staticmethod
    def market_is_open():
        """对齐前端 getDailyTimeRange：每天 10:00~24:00 可领"""
        now = datetime.now()
        return now.hour * 60 + now.minute >= 600

    async def market_wait_until_open(self):
        now = datetime.now()
        start = now.replace(hour=10, minute=0, second=0, microsecond=0)
        if now >= start:
            return True
        wait = (start - now).total_seconds()
        max_wait = MARKET_WAIT_MAX_SECONDS
        if wait > max_wait:
            self.tlog(f"未到10点(距离开抢{wait:.0f}秒)，跳过优享权益")
            return False
        self.tlog(f"等待开抢 {wait:.0f}秒")
        await asyncio.sleep(wait)
        return True

    async def market_req_dict(self, action, method, url, **kw):
        """权益超市请求：要求 data 为 dict；网络/5xx 短重试，失败软返回 None。"""
        last_r = None
        for attempt in range(MARKET_API_RETRIES):
            r = await self.req(method, url, **kw)
            last_r = r
            data = r.get("data") if r else None
            if isinstance(data, dict):
                return data, r
            err = api_response_err(r, action)
            if attempt + 1 < MARKET_API_RETRIES and is_retryable_api_response(r):
                self.tlog(
                    f"优享权益: {action} 重试{attempt + 1}/{MARKET_API_RETRIES - 1} {err}"
                )
                await asyncio.sleep(MARKET_API_RETRY_BASE_SECONDS * (attempt + 1))
                continue
            return None, last_r
        return None, last_r

    async def market_fetch_select_info(self):
        """对齐 HAR：premium 优享会员 vipType=0"""
        res, r = await self.market_req_dict(
            "selectInfo",
            "POST",
            "https://backward.bol.wo.cn/prod-api/market/contactVip/selectInfo/v2?vipType=0",
            headers=self.market_auth_headers(),
            json={},
        )
        if res is None:
            self.tlog(f"优享权益: 会员状态查询失败 {api_response_err(r, 'selectInfo')}")
            return None
        data = res.get("data")
        if res.get("code") != 200 or not data:
            self.tlog(f"优享权益: 会员状态查询失败 {api_response_err(r, 'selectInfo')}")
            return None
        if isinstance(data, list):
            first = data[0]
            if not isinstance(first, dict):
                self.tlog(
                    f"优享权益: selectInfo data[0] 须为 dict，实际为 {type(first).__name__}"
                )
                return None
            info = first
        elif isinstance(data, dict):
            info = data
        else:
            self.tlog(
                f"优享权益: selectInfo data 须为非空 dict 或非空 list，实际为 {type(data).__name__}"
            )
            return None
        try:
            state_ok = require_int(info.get("state"), "selectInfo.state") == 1
        except ValueError as e:
            self.tlog(f"优享权益: 会员状态字段异常 {e}")
            return None
        if not state_ok:
            self.tlog("优享权益: 非有效优享会员，跳过")
            return None
        self.market_cycle_start_time = str(info.get("cycleStartTime") or "")
        return info

    async def market_fetch_youchoice_activity(self):
        payload = {
            "majorId": 3,
            "subCodeList": ["COMMUNICATE_GOODS", "YOUCHOICEONE"],
            "currentTime": self.market_current_date(),
            "withUserStatus": 1,
        }
        if self.market_cycle_start_time:
            payload["cycleStartTime"] = self.market_cycle_start_time
        res, r = await self.market_req_dict(
            "getActivitiesDetail/v2",
            "POST",
            "https://backward.bol.wo.cn/prod-api/promotion/activity/roll/getActivitiesDetail/v2",
            headers=self.market_auth_headers(),
            json=payload,
        )
        if res is None:
            self.tlog(
                f"优享权益: 活动查询失败 {api_response_err(r, 'getActivitiesDetail/v2')}"
            )
            return None
        data = res.get("data")
        if res.get("code") != 200 or not data:
            self.tlog(
                f"优享权益: 活动查询失败 {api_response_err(r, 'getActivitiesDetail/v2')}"
            )
            return None
        if not isinstance(data, list):
            self.tlog(
                f"优享权益: getActivitiesDetail/v2 data 须为 list，实际为 {type(data).__name__}"
            )
            return None
        for act in data:
            if not isinstance(act, dict):
                self.tlog(
                    f"优享权益: getActivitiesDetail/v2 data 元素须为 dict，实际为 {type(act).__name__}"
                )
                return None
            if act.get("activityCode") == "YOUCHOICEONE":
                return act
        return data[0]

    def market_build_try_order(self, detail_list):
        """优先当日惊喜[0]；其后按 n-1..1 倒序尝试基础权益，跳过 status=3。

        惊喜售罄/拦截/失败时仍继续后面的基础商品，不再只试惊喜一项。
        """
        detail_list = detail_list or []
        if not detail_list:
            return []
        order = []
        first = detail_list[0]
        surprise = require_int(first.get("isSurprise"), "isSurprise") == 1
        if surprise:
            if require_int(first.get("status"), "status") != 3:
                order.append(first)
            for idx in range(len(detail_list) - 1, 0, -1):
                item = detail_list[idx]
                if require_int(item.get("status"), "status") == 3:
                    continue
                order.append(item)
            return order
        # 无惊喜位：整表倒序
        for idx in range(len(detail_list) - 1, -1, -1):
            item = detail_list[idx]
            if require_int(item.get("status"), "status") == 3:
                continue
            order.append(item)
        return order

    @staticmethod
    def market_should_try_next(msg: str) -> bool:
        """领取失败文案是否应继续尝试下一商品。"""
        if not msg:
            return False
        keywords = (
            "已领取",
            "已经抢过",
            "本周",
            "售罄",
            "抢完",
            "已抢空",
            "抢光",
            "库存不足",
            "无库存",
            "已领完",
            "领完",
            "明天十点",
            "明日再来",
        )
        return any(k in msg for k in keywords)

    def market_item_blocked_reason(self, act, item):
        """对齐前端 handleReceiveRights 的拦截条件"""
        if not self.market_is_open():
            return "本场活动暂未开启"
        times = require_int(act.get("userAvailableTimes"), "userAvailableTimes")
        left = require_int(item.get("leftQuantity"), "leftQuantity")
        status = require_int(item.get("status"), "status")
        cycle = str(item.get("cycle") or "")
        if times > 0 and left <= 0:
            return "已抢空，明天十点再来"
        if times <= 0:
            if cycle == "WEEK" and status == 2:
                return "本周已领取过该权益"
            return "今天已经抢过啦"
        if times <= 0 and left <= 0:
            return "今天已经抢过啦"
        if times > 0 and status == 2 and left > 0 and cycle == "WEEK":
            return "本周已领取过该权益"
        if status == 3:
            return "本周期已领取一次"
        if status == 2:
            return "已抢到"
        if left <= 0:
            return "已抢空"
        return ""

    async def market_unlock_surprise(self, act):
        """对齐 HAR openNew：解锁使用 detailList[0]"""
        detail_list = act.get("detailList") or []
        if not detail_list:
            return False
        first = detail_list[0]
        if (
            require_int(act.get("isUnlock"), "isUnlock") == 1
            or require_int(first.get("isSurprise"), "isSurprise") != 1
        ):
            return True
        if not self.mobile:
            self.tlog("优享权益: 缺少手机号，无法解锁惊喜权益")
            return False
        ts = int(time.time() * 1000)
        xbsosjl = "".join(random.choices(string.ascii_letters + string.digits, k=12))
        res, r = await self.market_req_dict(
            "unlockSurprise",
            "POST",
            f"https://backward.bol.wo.cn/prod-api/promotion/activity/roll/unlock/surpriseInterest"
            f"?xbsosjl={xbsosjl}&timeVerRan={ts}&diceid={self.market_login_id}",
            headers=self.market_auth_headers(),
            json={
                "timeVerRan": ts,
                "mobile": self.mobile,
                "id": first.get("id"),
                "activityId": first.get("activityId") or act.get("activityId"),
            },
        )
        if res is None:
            self.tlog(
                f"优享权益: 惊喜解锁失败 {api_response_err(r, 'unlockSurprise')}"
            )
            return False
        if res.get("code") == 200:
            self.tlog(f"优享权益: 惊喜解锁成功 {res.get('msg', '')}")
            await asyncio.sleep(1.5)
            return True
        self.tlog(
            f"优享权益: 惊喜解锁失败 {res.get('msg') or api_response_err(r, 'unlockSurprise')}"
        )
        return False

    async def market_receive_rights(self, act, item):
        payload = {
            "channelId": item.get("channelId"),
            "activityId": act.get("activityId"),
            "productId": item.get("id"),
            "productCode": item.get("productCode", ""),
            "currentTime": self.market_current_date(),
            "accountType": item.get("accountType", "4"),
        }
        r = await self.req(
            "POST",
            "https://backward.bol.wo.cn/prod-api/promotion/activity/roll/receiveRightsVip",
            headers=self.market_auth_headers(),
            json=payload,
        )
        return require_dict_data(r, "receiveRightsVip")

    async def market_man_machine(self, activity_id):
        if not activity_id:
            return False
        r = await self.req(
            "POST",
            f"https://backward.bol.wo.cn/prod-api/promotion/activity/roll/receive/manMachine?activityId={activity_id}",
            headers=self.market_auth_headers(),
            json={},
        )
        res = require_dict_data(r, "manMachine")
        return res.get("code") == 200

    async def market_login(self):
        try:
            ticket = await self.get_ticket("https://contact.bol.wo.cn/")
            if not ticket:
                self.tlog("登录失败: 获取ticket为空")
                return False
            r = await self.req(
                "POST",
                f"https://backward.bol.wo.cn/prod-api/auth/marketUnicomLogin?ticket={ticket}&channel=unicomTab",
                headers={"Content-Type": "application/json"},
                json={},
            )
            if (res := r["data"]) and res.get("code") == 200:
                self.market_token = res.get("data", {}).get("token", "")
                if self.market_token:
                    # 解析JWT获取login_id
                    try:
                        payload = self.market_token.split(".")[1]
                        payload += "=" * (-len(payload) % 4)
                        jwt = json.loads(base64.urlsafe_b64decode(payload).decode())
                        self.market_login_id = jwt.get("loginId", "")
                    except Exception as e:
                        self.tlog_exc(e, "解析权益超市JWT")
                    self.tlog("登录成功")
                    return True
                self.tlog(
                    f"登录失败: 响应无token | {api_response_err(r, '权益超市登录')}"
                )
                return False
            self.tlog(f"登录失败: {api_response_err(r, '权益超市登录')}")
        except Exception as e:
            self.tlog_exc(e, "权益超市登录")
        return False

    async def market_privilege(self):
        """优享权益（权益天天领）"""
        try:
            if not self.market_token:
                return
            if not await self.market_wait_until_open():
                return
            if not self.market_is_open():
                self.tlog("优享权益: 本场活动暂未开启")
                return

            await asyncio.sleep(max(0, (self.idx - 1) * 0.15))

            if not await self.market_fetch_select_info():
                return

            act = await self.market_fetch_youchoice_activity()
            if not act:
                return
            if require_int(act.get("userAvailableTimes"), "userAvailableTimes") <= 0:
                self.tlog("优享权益: 今日已领")
                return

            detail_list = act.get("detailList") or []
            items = self.market_build_try_order(detail_list)
            if not items:
                self.tlog("优享权益: 无可尝试商品")
                return
            if detail_list:
                first = detail_list[0]
                if (
                    require_int(first.get("isSurprise"), "isSurprise") == 1
                    and require_int(first.get("status"), "status") == 3
                ):
                    self.tlog("优享权益: 当日惊喜本周期已领，按倒序尝试基础权益")
                elif require_int(first.get("isSurprise"), "isSurprise") == 1:
                    base_n = max(0, len(items) - 1)
                    self.tlog(
                        f"优享权益: 优先尝试惊喜 [{first.get('productName', '')}]"
                        f"，失败后可尝试 {base_n} 个基础权益"
                    )
                else:
                    self.tlog(f"优享权益: 按规则尝试 {len(items)} 个商品")

            need_surprise_unlock = (
                require_int(act.get("isUnlock"), "isUnlock") != 1
                and detail_list
                and require_int(detail_list[0].get("isSurprise"), "isSurprise") == 1
            )
            if need_surprise_unlock:
                unlocked = await self.market_unlock_surprise(act)
                act = await self.market_fetch_youchoice_activity() or act
                detail_list = act.get("detailList") or detail_list
                items = self.market_build_try_order(detail_list)
                if not unlocked:
                    # 解锁失败：去掉惊喜项，只领基础权益
                    first = detail_list[0] if detail_list else None
                    if first and require_int(first.get("isSurprise"), "isSurprise") == 1:
                        fid = first.get("id")
                        items = [
                            it
                            for it in items
                            if it is not first and it.get("id") != fid
                        ]
                    self.tlog("优享权益: 惊喜解锁失败，改为尝试基础权益")
                if not items:
                    self.tlog("优享权益: 无可尝试商品")
                    return

            for i, item in enumerate(items):
                name = item.get("productName", "")
                reason = self.market_item_blocked_reason(act, item)
                if reason:
                    self.tlog(f"优享权益: [{name}] 跳过({reason})")
                    continue

                try:
                    res = await self.market_receive_rights(act, item)
                except ValueError as e:
                    self.tlog(f"优享权益: [{name}] 领取请求失败 {e}")
                    continue
                code = safe_int(res.get("code"), -1)
                if code == 200:
                    self.tlog(f"优享权益: [{name}] 成功")
                    return
                if code == -2:
                    self.tlog(f"优享权益: [{name}] 需人机验证，尝试 manMachine")
                    try:
                        if await self.market_man_machine(act.get("activityId")):
                            res = await self.market_receive_rights(act, item)
                            if safe_int(res.get("code")) == 200:
                                self.tlog(f"优享权益: [{name}] 成功")
                                return
                    except ValueError as e:
                        self.tlog(f"优享权益: [{name}] 人机/重试失败 {e}")
                    self.tlog(f"优享权益: [{name}] 人机验证后仍未成功，尝试下一商品")
                    continue
                msg = str(res.get("msg", ""))
                self.tlog(f"优享权益: [{name}] 失败 {msg or res}")
                if self.market_should_try_next(msg):
                    if i + 1 < len(items):
                        nxt = items[i + 1].get("productName", "")
                        self.tlog(f"优享权益: 按规则继续下一商品 [{nxt}]")
                    continue
                # 明确不可再领（次数用尽等）时停止
                if any(
                    k in msg
                    for k in ("今天已经抢过", "今日已领", "没有领取次数", "次数不足")
                ):
                    break
            else:
                self.tlog("优享权益: 已尝试全部可领商品，均未成功")
        except Exception as e:
            self.tlog_exc(e, "优享权益")

    async def market_raffle(self):
        """抽奖"""
        try:
            if not self.market_token:
                return
            r = await self.req(
                "POST",
                "https://backward.bol.wo.cn/prod-api/promotion/home/raffleActivity/getUserRaffleCount?id=12&channel=unicomTab",
                headers={"Authorization": f"Bearer {self.market_token}"},
                json={},
            )
            res = require_dict_data(r, "查询抽奖次数")
            if res.get("code") != 200:
                self.tlog(
                    f"查询抽奖次数失败: code={res.get('code')} {response_summary(res)}"
                )
                return
            count = require_int(res.get("data"), "raffleCount", minimum=0)
            self.tlog(f"抽奖次数: {count}")

            for _ in range(count):
                await asyncio.sleep(2)
                ts = int(time.time() * 1000)
                r = await self.req(
                    "POST",
                    f"https://backward.bol.wo.cn/prod-api/promotion/home/raffleActivity/userRaffle?id=12&channel=unicomTab&timeVerRan={ts}",
                    headers={"Authorization": f"Bearer {self.market_token}"},
                    json={},
                )
                res = require_dict_data(r, "抽奖")
                if res.get("code") != 200:
                    self.tlog(
                        f"抽奖失败: code={res.get('code')} {response_summary(res)}"
                    )
                    break
                data = res.get("data", {})
                if data.get("isWinning") and (prize := data.get("prizesName")):
                    self.tlog(f"抽奖: {prize}")
                else:
                    self.tlog("抽奖: 未中奖")
        except Exception as e:
            self.tlog_exc(e, "抽奖")

    async def market_task(self):
        self._task_tag = "权益超市"
        self.tlog("开始")
        if await self.market_login():
            await self.market_privilege()
            await self.market_raffle()

    # === 3. 天天领现金 ===
    TTLXJ_PAGE = (
        "https://epay.10010.com/ci-mcss-party-web/clockIn/"
        "?bizFrom=225&bizChannelCode=225&channelType=QBSZ"
    )

    def ttlxj_bizinfo(self):
        """party 域接口的鉴权头。

        除 bizChannelInfo 外，业务接口还必须带 auth/check 换回的 authInfo + tokenid，
        否则服务端回 11019006 这类 popup 拒绝信封（无业务数据）。
        """
        ref = self.TTLXJ_PAGE + (f"&rptid={self.rpt_id}" if self.rpt_id else "")
        h = {
            "bizchannelinfo": json.dumps(
                {
                    "bizChannelCode": "225",
                    "disriBiz": "party",
                    "unionSessionId": "",
                    "stType": "",
                    "stDesmobile": "",
                    "source": "",
                    "rptId": self.rpt_id,
                    "ticket": "",
                    "tongdunTokenId": "",
                    "xindunTokenId": "",
                }
            ),
            "Referer": ref,
            "Origin": "https://epay.10010.com",
            "Accept": "application/json, text/plain, */*",
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        }
        if self.token_id:
            h["tokenid"] = self.token_id
            h["authInfo"] = json.dumps(
                {
                    "accessToken": None,
                    "mobile": "",
                    "sessionId": self.session_id or self.token_id,
                    "stOpenDate": None,
                    "tokenId": self.token_id,
                    "userId": "",
                }
            )
        return h

    async def ttlxj_task(self):
        self._task_tag = "天天领现金"
        self.tlog("开始")
        ticket_info = await self.get_ticket(
            "https://epay.10010.com/ci-mps-st-web/?webViewNavIsHidden=webViewNavIsHidden"
        )
        if not ticket_info:
            self.tlog("获取ticket失败")
            return

        # 先载入带 ticket 的落地页，再以它作 Referer 换 rptid；
        # 缺 Referer 时 authorize 返回 HTTP 200 但体内 status=400 bad referer
        st_referer = self.last_ticket_url or (
            "https://epay.10010.com/ci-mps-st-web/?webViewNavIsHidden=webViewNavIsHidden"
        )
        await self.req("GET", st_referer)

        # 授权
        r = await self.req(
            "POST",
            "https://epay.10010.com/woauth2/v2/authorize",
            headers={
                "Referer": st_referer,
                "Origin": "https://epay.10010.com",
                "Accept": "application/json",
            },
            json={
                "response_type": "rptid",
                "client_id": "73b138fd-250c-4126-94e2-48cbcc8b9cbe",
                "redirect_uri": "https://epay.10010.com/ci-mps-st-web/",
                "login_hint": {
                    "credential_type": "st_ticket",
                    "credential": ticket_info,
                    "st_type": "02",
                    "force_logout": True,
                    "source": "app_sjyyt",
                },
                "device_info": {
                    "token_id": f"chinaunicom-pro-{int(time.time() * 1000)}-{''.join(random.choices(string.ascii_letters + string.digits, k=13))}",
                    "trace_id": "".join(
                        random.choices(string.ascii_letters + string.digits, k=32)
                    ),
                },
            },
        )
        # authorize 失败时 HTTP 仍为 200，判据在响应体的 status/rptid
        auth_res = r["data"] if isinstance(r["data"], dict) else {}
        if r["code"] != 200 or safe_int(auth_res.get("status"), -1) != 200:
            self.tlog(
                f"授权失败: {auth_res.get('message') or auth_res.get('ext_code') or ''} "
                f"{api_response_err(r, 'authorize')}"
            )
            return
        # 注意：authorize 返回的 rptid 属于 ci-mps-st-web 客户端，拿去 party 域
        # 会被判 invalid audience；clockIn 用的 rptid 要走下面的 woauth2/login 重定向拿。
        # 这里 authorize 的作用只是建立 woauth2 会话 cookie。

        # 先加载活动页，让服务端把 clockIn 作为 referWoauthUrl 写进会话，
        # 否则下一步 auth/check 返回的 woauth_login_url 不带 redirect_url
        await self.req("GET", self.TTLXJ_PAGE)

        # 认证检查
        r = await self.req(
            "POST",
            "https://epay.10010.com/ps-pafs-auth-front/v1/auth/check",
            headers=self.ttlxj_bizinfo(),
            json={},
        )

        res = r["data"]
        if not isinstance(res, dict):
            self.tlog(f"认证失败: {api_response_err(r, 'auth/check')}")
            return
        if str(res.get("code")) == "0000":
            data = res.get("data")
            auth = data.get("authInfo") if isinstance(data, dict) else None
            if not isinstance(auth, dict):
                self.tlog(f"认证失败: {api_response_err(r, 'auth/check')}")
                return
            self.session_id, self.token_id = (
                auth.get("sessionId"),
                auth.get("tokenId"),
            )
        elif str(res.get("code")) == "2101000100":
            # 需要登录获取rptId
            data = res.get("data")
            if not isinstance(data, dict):
                self.tlog(f"认证失败: {api_response_err(r, 'auth/check')}")
                return
            login_url = data.get("woauth_login_url")
            if login_url:
                # 服务端通常已把 redirect_url 填好；只有留空时才由我们补上活动页，
                # 否则直接拼接会污染已编码的 redirect_url 参数
                full_url = (
                    f"{login_url}{quote(self.TTLXJ_PAGE, safe='')}"
                    if login_url.endswith("redirect_url=")
                    else login_url
                )
                r = await self.req("GET", full_url, allow_redirects=False)
                if loc := r["headers"].get("location") or r["headers"].get("Location"):
                    if rptid := parse_qs(urlparse(loc).query).get("rptid", [""])[0]:
                        self.rpt_id = rptid
                        # 重新认证
                        r = await self.req(
                            "POST",
                            "https://epay.10010.com/ps-pafs-auth-front/v1/auth/check",
                            headers=self.ttlxj_bizinfo(),
                            json={},
                        )
                        res = r["data"]
                        if not isinstance(res, dict) or str(res.get("code")) != "0000":
                            self.tlog(f"认证失败: {api_response_err(r, 'auth/check')}")
                            return
                        data = res.get("data")
                        auth = data.get("authInfo") if isinstance(data, dict) else None
                        if not isinstance(auth, dict):
                            self.tlog(f"认证失败: {api_response_err(r, 'auth/check')}")
                            return
                        self.session_id, self.token_id = (
                            auth.get("sessionId"),
                            auth.get("tokenId"),
                        )
                    else:
                        self.tlog("登录重定向缺少rptid")
                        return
                else:
                    self.tlog(f"登录重定向缺少Location: {api_response_err(r, 'woauth2/login')}")
                    return
            else:
                self.tlog("认证响应缺少woauth_login_url")
                return
        else:
            self.tlog(f"认证失败: {api_response_err(r, 'auth/check')}")
            return

        # 查询打卡状态
        r = await self.req(
            "POST",
            "https://epay.10010.com/ci-mcss-party-front/v1/ttlxj/userDrawInfo",
            headers=self.ttlxj_bizinfo(),
        )
        if (res := r["data"]) and str(res.get("code")) == "0000":
            data = res.get("data", {})
            # 会话无效时服务端回的是 popup 拒绝信封（无 day 日历字段），须先识别
            if str(data.get("returnCode")) != "0":
                self.tlog(
                    f"查询打卡状态被拒[{data.get('returnCode')}]: "
                    f"{data.get('returnMsg') or json.dumps(data, ensure_ascii=False)[:150]}"
                )
                return
            day_key = f"day{data.get('dayOfWeek')}"
            if data.get(day_key) == "1":
                draw_type = "C" if (datetime.now().weekday() + 1) % 7 == 0 else "B"
                r = await self.req(
                    "POST",
                    "https://epay.10010.com/ci-mcss-party-front/v1/ttlxj/unifyDrawNew",
                    headers=self.ttlxj_bizinfo(),
                    data={
                        "drawType": draw_type,
                        "bizFrom": "225",
                        "activityId": "TTLXJ20210330",
                    },
                )
                if (
                    (res := r["data"])
                    and str(res.get("code")) == "0000"
                    and str(res.get("data", {}).get("returnCode")) == "0"
                ):
                    amt = res["data"].get("amount")
                    self.tlog(
                        f"{res['data'].get('awardTipContent', '').replace('xx', str(amt))}"
                    )
                else:
                    self.tlog(f"抽奖失败: {api_response_err(r, 'unifyDrawNew')}")
            else:
                # 实测：可抽时 day{dayOfWeek}=="1"，抽完即翻为 "0"
                self.tlog(
                    f"今日已抽过 {day_key}={data.get(day_key)!r} "
                    f"周内已抽={data.get('weekDrawTimes')} 累计={data.get('countAmount')}元"
                )

    # === 4. 联通祝福 ===
    def wocare_decode(self, result):
        """解码wocare响应的messageContent字段"""
        if not isinstance(result, dict) or "messageContent" not in result:
            return result
        try:
            content = (
                result["messageContent"]
                .replace("\n", "")
                .replace("\r", "")
                .replace(" ", "")
            )
            content = content.replace("-", "+").replace("_", "/")
            missing = len(content) % 4
            if missing:
                content += "=" * (4 - missing)
            decoded = json.loads(base64.b64decode(content).decode("utf-8"))
        except (AttributeError, TypeError, ValueError, UnicodeError) as e:
            raise ValueError("联通祝福响应解码失败") from e
        if not isinstance(decoded, dict):
            raise ValueError(
                f"联通祝福响应解码失败: decoded 非dict (type={type(decoded).__name__})"
            )
        result.update(decoded)
        return result

    def wocare_body(self, api, data):
        ts = datetime.now().strftime("%Y%m%d%H%M%S%f")[:-3]
        body = {
            "version": WOCARE_CH[3],
            "apiCode": api,
            "channelId": WOCARE_CH[0],
            "transactionId": ts + "".join(random.choices(string.digits, k=6)),
            "timeStamp": ts,
            "messageContent": base64.b64encode(
                json.dumps(data, separators=(",", ":")).encode()
            ).decode(),
        }
        sign_str = (
            "&".join(f"{k}={body[k]}" for k in sorted(body))
            + f"&sign={WOCARE_CH[1]}"
        )
        body["sign"] = hashlib.md5(sign_str.encode()).hexdigest()
        return body

    async def wocare_post(self, api, data, retries=3):
        # wocare 服务端 7 月起变慢，默认 50s 超时会拖死任务，改短超时+重试
        for i in range(retries):
            r = await self.req(
                "POST",
                f"https://wocare.unisk.cn/api/v1/{api}",
                data=self.wocare_body(api, data),
                timeout=15,
            )
            if is_retryable_api_response(r) and i < retries - 1:
                # 措辞避开"失败/异常"，否则重试成功也会被推送过滤器当成故障
                self.tlog(
                    f"{api} 第{i + 1}/{retries}次未响应，重试: {api_response_err(r, api)}"
                )
                await asyncio.sleep(1.5 * (i + 1))
                continue
            return self.wocare_decode(require_dict_data(r, api))

    async def ltzf_task(self):
        self._task_tag = "联通祝福"
        self.tlog("开始")
        ticket = await self.get_ticket(
            f"https://wocare.unisk.cn/mbh/getToken?channelType={WOCARE_CH[2]}&homePage=home&duanlianjieabc=qAz2m"
        )
        if not ticket:
            self.tlog("获取ticket失败")
            return

        # 获取sid和token
        r = await self.req(
            "GET",
            "https://wocare.unisk.cn/mbh/getToken",
            params={
                "channelType": WOCARE_CH[2],
                "type": "02",
                "ticket": ticket,
                "version": APP_VERSION,
                "timestamp": datetime.now().strftime("%Y%m%d%H%M%S%f")[:-3],
                "desmobile": self.mobile,
                "num": 0,
                "postage": "".join(
                    random.choices(string.ascii_letters + string.digits, k=32)
                ),
                "homePage": "home",
                "duanlianjieabc": "qAz2m",
                "userNumber": self.mobile,
            },
            allow_redirects=False,
        )

        if r["code"] == 302 and (
            loc := r["headers"].get("location") or r["headers"].get("Location")
        ):
            self.wocare_sid = parse_qs(urlparse(loc).query).get("sid", [""])[0]
            if not self.wocare_sid:
                self.wocare_sid = parse_qs(urlparse(loc).query).get("uuid", [""])[0]
            if not self.wocare_sid:
                self.tlog("重定向缺少sid/uuid")
                return

            # 登录
            res = await self.wocare_post(
                "loginmbh",
                {
                    "sid": self.wocare_sid,
                    "channelType": WOCARE_CH[2],
                    "apiCode": "loginmbh",
                },
            )
            if str(res.get("resultCode")) == "0000":
                self.wocare_token = (res.get("data") or {}).get("token")
                if not self.wocare_token:
                    self.tlog("登录响应缺少token")
                    return
                self.tlog("登录成功")

                # 获取动态Banner列表
                res = await self.wocare_post(
                    "getSpecificityBanner",
                    {
                        "token": self.wocare_token,
                        "apiCode": "getSpecificityBanner",
                    },
                )
                if str(res.get("resultCode")) != "0000":
                    self.tlog(
                        f"接口失败: getSpecificityBanner resultCode={res.get('resultCode')} {res.get('resultMsg') or res.get('resultDesc') or ''}"
                    )
                    return

                raw_data = res.get("data")
                if raw_data is None:
                    raw_data = []
                elif not isinstance(raw_data, list):
                    self.tlog(
                        f"接口失败: getSpecificityBanner 响应data格式错误(type={type(raw_data).__name__})"
                    )
                    return

                banner_list = [
                    b
                    for b in raw_data
                    if isinstance(b, dict)
                    and str(b.get("activityStatus")) == "0"
                    and str(b.get("isDeleted")) == "0"
                ]

                if not banner_list:
                    self.tlog("未返回可用动态活动，停止")
                    return

                # 执行任务和抽奖
                for activity in banner_list:
                    await asyncio.sleep(1)
                    try:
                        res = await self.wocare_post(
                            "loadInit",
                            {
                                "token": self.wocare_token,
                                "channelType": WOCARE_CH[2],
                                "type": activity["id"],
                                "apiCode": "loadInit",
                            },
                        )
                        if str(res.get("resultCode")) == "0000":
                            data = res.get("data", {}) or {}
                            group_id = data.get("zActiveModuleGroupId") or 0
                            aid = activity["id"]

                            # 计算抽奖次数
                            if aid == 2:
                                is_partake = (data.get("data") or {}).get("isPartake") or 0
                                count = 0 if is_partake else 1
                            elif aid == 3:
                                count = int(data.get("raffleCountValue", 0) or 0)
                            elif aid == 4:
                                count = int(data.get("mhRaffleCountValue", 0) or 0)
                            else:
                                count = 0

                            if count > 0:
                                self.tlog(f"{activity.get('name', '')}: 可抽奖{count}次")
                                # 执行抽奖；触发"频繁"风控时该次不计数，重试同一次
                                done = retry = 0
                                while done < count:
                                    await asyncio.sleep(random.uniform(3, 5))
                                    res = await self.wocare_post(
                                        "luckDraw",
                                        {
                                            "token": self.wocare_token,
                                            "channelType": WOCARE_CH[2],
                                            "zActiveModuleGroupId": group_id,
                                            "type": aid,
                                            "apiCode": "luckDraw",
                                        },
                                    )
                                    if str(res.get("resultCode")) == "0000":
                                        draw_data = res.get("data", {}) or {}
                                        draw_code = str(draw_data.get("resultCode", "-1"))
                                        if draw_code == "0000":
                                            prize = (
                                                draw_data.get("data") or {}
                                            ).get("prize") or {}
                                            if pn := prize.get("prizeName"):
                                                pd = prize.get("prizeDesc", "")
                                                self.tlog(
                                                    f"{activity.get('name', '')}: {pn}[{pd}]"
                                                )
                                        else:
                                            msg = (
                                                draw_data.get("resultMsg")
                                                or draw_data.get("resultDesc")
                                                or res.get("resultMsg")
                                                or res.get("resultDesc")
                                                or ""
                                            )
                                            if "频繁" in msg and retry < 3:
                                                retry += 1
                                                self.tlog(
                                                    f"{activity.get('name', '')}: {msg}，5秒后重试"
                                                )
                                                await asyncio.sleep(5)
                                                continue
                                            if msg.lower() == "success":
                                                self.tlog(
                                                    f"{activity.get('name', '')}: 未中奖"
                                                )
                                            else:
                                                self.tlog(
                                                    f"{activity.get('name', '')}: {msg if msg else '抽奖完成'}"
                                                )
                                    done += 1
                                    retry = 0
                            else:
                                self.tlog(f"{activity.get('name', '')}: 今日已无抽奖机会")
                    except (ValueError, AttributeError, TypeError, KeyError) as e:
                        # 单个 banner 的畸形响应不能拖垮后面的 banner
                        self.tlog_exc(e, activity.get("name") or "banner")
                        continue
            else:
                self.tlog(
                    f"登录失败: loginmbh resultCode={res.get('resultCode')} {res.get('resultMsg') or res.get('resultDesc') or ''}"
                )
        else:
            self.tlog(f"获取sid失败: {api_response_err(r, 'getToken')}")

    # === 5. 新疆联通 ===
    async def xj_task(self):
        self._task_tag = "新疆联通"
        if "新疆" not in self.province:
            return
        self.tlog("开始")
        ticket = await self.get_ticket(
            "https://zy100.xj169.com/touchpoint/openapi/jumpHandRoom1G?source=155&type=02"
        )
        if not ticket:
            return

        # 获取token
        r = await self.req(
            "POST",
            "https://zy100.xj169.com/touchpoint/openapi/getTokenAndCity",
            headers={
                "Referer": f"https://zy100.xj169.com/touchpoint/openapi/jumpHandRoom1G?source=155&type=02&ticket={ticket}",
                "X-Requested-With": "XMLHttpRequest",
                "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
            },
            data={"ticket": ticket},
        )

        token = None
        if (res := r["data"]) and isinstance(res, dict):
            if res.get("code") == 0:
                token = res.get("data", {}).get("token")

        if not token:
            return
        self.tlog("登录成功")

        # 获取活动ID
        month_abbr = [
            "Jan",
            "Feb",
            "Mar",
            "Apr",
            "May",
            "Jun",
            "Jul",
            "Aug",
            "Sep",
            "Oct",
            "Nov",
            "Dec",
        ]
        now = datetime.now()
        month_activity_id = f"{month_abbr[now.month - 1]}{now.year}Act"

        # 获取commHighFlag
        xj_comm_high_flag = ""
        r = await self.req(
            "POST",
            "https://zy100.xj169.com/touchpoint/openapi/themeAct/commonHightRest",
            headers={
                "userToken": token,
                "X-Requested-With": "XMLHttpRequest",
                "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
            },
            data={"activityId": month_activity_id},
        )
        if (
            (res := r["data"])
            and isinstance(res, dict)
            and res.get("code") in [0, "SUCCESS"]
        ):
            xj_comm_high_flag = res.get("data", "")

        # 每月主题抽奖
        r = await self.req(
            "POST",
            f"https://zy100.xj169.com/touchpoint/openapi/themeAct/draw_{month_activity_id}",
            headers={
                "userToken": token,
                "X-Requested-With": "XMLHttpRequest",
                "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
            },
            data={
                "activityId": month_activity_id,
                "prizeId": "",
                "commHighFlag": xj_comm_high_flag,
            },
        )
        if (res := r["data"]) and isinstance(res, dict):
            msg, data = res.get("msg"), res.get("data")
            if msg == "thanks1":
                self.tlog(f"每月抽奖: {data}")
            elif res.get("code") in [0, "SUCCESS"]:
                self.tlog(f"每月抽奖: {msg or data}")
            elif data and (
                "已经打过卡" in str(data)
                or "机会已用完" in str(data)
                or "已达上限" in str(data)
            ):
                self.tlog(f"每月抽奖: {data}")
            else:
                self.tlog(f"每月抽奖: {data or msg}")

        # 每日打卡抽奖
        await asyncio.sleep(1)
        r = await self.req(
            "POST",
            f"https://zy100.xj169.com/touchpoint/openapi/themeAct/draw_{month_activity_id}",
            headers={
                "userToken": token,
                "X-Requested-With": "XMLHttpRequest",
                "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
            },
            data={
                "activityId": f"daka{month_activity_id}",
                "prizeId": "daka_sftczxqb_twenty",
                "commHighFlag": xj_comm_high_flag,
            },
        )
        if (res := r["data"]) and isinstance(res, dict):
            msg, data = res.get("msg"), res.get("data")
            if msg == "thanks1":
                self.tlog(f"每日打卡: {data}")
            elif res.get("code") in [0, "SUCCESS"]:
                self.tlog(f"每日打卡: {msg or data}")
            elif res.get("msgType") == "200":
                self.tlog("每日打卡: 已打过卡")
            elif data and ("已经打过卡" in str(data) or "机会已用完" in str(data)):
                self.tlog(f"每日打卡: {data}")
            else:
                self.tlog(f"每日打卡: {data or msg}")

    # === 6. 安全管家 ===
    async def sec_task(self):
        self._task_tag = "安全管家"
        self.tlog("开始")
        if not self.ecs_token or not self.mobile:
            return

        # 获取ticket
        ts = datetime.now().strftime("%Y%m%d%H%M%S")
        r = await self.req(
            "GET",
            f"https://m.client.10010.com/edop_ng/getTicketByNative?token={self.ecs_token}&appId=edop_unicom_3a6cc75a",
            headers={
                "Cookie": f"PvSessionId={ts}{''.join(random.choices(string.ascii_letters + string.digits, k=32))};c_mobile={self.mobile};c_version=iphone_c@11.0800;ecs_token={self.ecs_token}",
                "User-Agent": "ChinaUnicom4.x/12.3.1 (com.chinaunicom.mobilebusiness; build:77; iOS 16.6.0) Alamofire/4.7.3",
            },
        )
        ticket1 = require_dict_data(r, "安全管家ticket").get("ticket")
        if not ticket1:
            return

        # 获取token
        r = await self.req(
            "POST",
            "https://uca.wo116114.com/api/v1/auth/ticket?product_line=uasp&entry_point=h5&entry_point_id=edop_unicom_3a6cc75a",
            headers={
                "clientType": "uasp_unicom_applet",
                "Content-Type": "application/json",
            },
            json={"productId": "", "type": 1, "ticket": ticket1},
        )
        res = require_dict_data(r, "安全管家auth/ticket")
        if not res.get("data"):
            return
        self.sec_token = res["data"].get("access_token")
        if not self.sec_token:
            return

        # 获取积分ticket
        r = await self.req(
            "POST",
            "https://uca.wo116114.com/api/v1/auth/getTicket?product_line=uasp&entry_point=h5&entry_point_id=edop_unicom_3a6cc75a",
            headers={
                "auth-sa-token": self.sec_token,
                "clientType": "uasp_unicom_applet",
                "Content-Type": "application/json",
            },
            json={"productId": "91311616", "phone": self.mobile},
        )
        res = require_dict_data(r, "安全管家getTicket")
        if not res.get("data"):
            return
        self.sec_ticket = res["data"].get("ticket")

        # 获取密钥
        sec_jea_id = ""
        t = unquote(self.sec_ticket) if self.sec_ticket else ""
        r = await self.req(
            "GET",
            "https://m.jf.10010.com/jf-external-application/jftask/getSecretKey",
            headers={
                "ticket": t,
                "partnersid": "1702",
                "clienttype": "uasp_unicom_applet",
                "Accept": "application/json, text/plain, */*",
                "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15",
                "pageId": "s768590754920323072",
            },
        )
        for cookie in iter_set_cookies(r["headers"]):
            if "_jea_id=" in cookie:
                sec_jea_id = cookie.split("_jea_id=")[1].split(";")[0]
                break
        res = require_dict_data(r, "获取密钥")
        if str(res.get("code")) != "0000":
            self.tlog(f"获取密钥失败: {res}")
            return
        self.sec_key = res.get("data", {}).get("secretKey")
        if not self.sec_key:
            return
        self.sec_jea_id = sec_jea_id

        # 执行任务
        def sec_headers():
            ts, nonce = (
                str(int(time.time() * 1000)),
                "".join(random.choices(string.ascii_lowercase + string.digits, k=8)),
            )
            sig = hmac.new(
                self.sec_key.encode(), f"{nonce}{ts}".encode(), hashlib.sha256
            ).hexdigest()
            return {
                "ticket": t,
                "User-Agent": SEC_UA,
                "partnersid": "1702",
                "clienttype": "uasp_unicom_applet",
                "Cookie": f"_jea_id={self.sec_jea_id}",
                "X-Request-Timestamp": ts,
                "X-Request-Nonce": nonce,
                "X-Request-Signature": sig,
            }

        # 签到任务
        r = await self.req(
            "POST",
            "https://m.jf.10010.com/jf-external-application/jftask/taskDetail",
            headers=sec_headers(),
            json={},
        )
        if (res := r["data"]) and res.get("data", {}).get("taskDetail"):
            for task in res["data"]["taskDetail"].get("taskList", []):
                if "签到" in task.get("taskName", "") and task.get(
                    "needCount", 1
                ) > task.get("finishCount", 0):
                    await self.req(
                        "POST",
                        "https://m.jf.10010.com/jf-external-application/uasptask/sign",
                        headers=sec_headers(),
                        json={"taskCode": task.get("taskCode")},
                    )
                    await self.req(
                        "POST",
                        "https://m.jf.10010.com/jf-external-application/jftask/receive",
                        headers=sec_headers(),
                        json={"taskCode": task.get("taskCode")},
                    )
                    self.tlog("签到完成")
                    break

        # 助理代接
        await asyncio.sleep(1)
        await self.req(
            "POST",
            "https://ims.wo116114.com/api/Assistant/assis_save",
            headers={
                "auth-sa-token": self.sec_token,
                "Content-Type": "application/json",
            },
            json={
                "page_type": 1,
                "old_ainumber": "XF0",
                "level": 3,
                "dialog": "0",
                "opertype": 1,
                "videoimage": "",
                "speechtype": "06",
                "ainumber": "BD1",
            },
        )

        # 号段拦截（每月任务）
        await asyncio.sleep(1)
        url = "https://uca.wo116114.com/sjgj/woAssistant/umm/configs/v1/config?product_line=uasp&entry_point=h5&entry_point_id=wxdefbc1986dc757a6"
        item = {
            "checked": True,
            "content": "1",
            "contentName": "拦截400开头的10位特服号码",
            "contentTag": "1",
        }
        base = {"productId": "91351080", "type": 7, "operationType": 0}

        async def sec_uca_post(data):
            return await self.req(
                "POST",
                url,
                headers={
                    "auth-sa-token": self.sec_token,
                    "Content-Type": "application/json",
                },
                json=data,
            )

        await sec_uca_post({**base, "contents": [item]})
        await asyncio.sleep(2)
        item["checked"] = False
        item["content"] = "0"
        await sec_uca_post({**base, "contents": [item]})
        await asyncio.sleep(2)
        item["checked"] = True
        item["content"] = "1"
        await sec_uca_post({**base, "contents": [item]})

        self.tlog("代接/拦截完成")

    # === 7. 通通农场（通通乡村）===
    def ttxc_headers(self, auth=True, ecs=False):
        headers = {
            "User-Agent": TTXC_UA,
            "Content-Type": "application/json",
            "Accept": "*/*",
            "Origin": "https://epay.10010.com",
            "Referer": TTXC_REFERER,
            "X-Requested-With": "com.sinovatech.unicom.ui",
        }
        if auth and self.ttxc_token:
            headers["Authorization"] = self.ttxc_token
        if ecs and self.ecs_token:
            self.client.cookies.set("ecs_token", self.ecs_token, domain=".10010.com")
        return headers

    async def ttxc_post(self, path, payload=None, auth=True, with_user=True, ecs=False):
        data = dict(payload or {})
        if with_user:
            data.setdefault("userId", self.ttxc_user_id or "")
        data.setdefault("channel", TTXC_CHANNEL)
        r = await self.req(
            "POST",
            f"{TTXC_BASE_URL}{path}",
            json=data,
            headers=self.ttxc_headers(auth=auth, ecs=ecs),
        )
        return require_dict_data(r, path)

    def ttxc_snapshot_cookies(self):
        return [(c.name, c.value, c.domain) for c in self.client.cookies.jar]

    def ttxc_restore_cookies(self, saved):
        for name, value, domain in saved:
            self.client.cookies.set(name, value, domain=domain or ".10010.com")

    async def ttxc_finish_woauth(self, login_url, saved_cookies=None):
        headers = {"Referer": "https://epay.10010.com/", "User-Agent": TTXC_UA}
        r = await self.req("GET", login_url, headers=headers)
        if r["code"] != 200:
            return False
        text = r["data"] if isinstance(r["data"], str) else ""
        match = re.search(r'var token = "([^"]+)"', text)
        if not match:
            return False
        next_url = (
            "https://epay.10010.com/woauth2/after-collected-device-digest"
            f"?deviceDigestTraceId=&deviceDigestTokenId=&token={quote(match.group(1))}&source=app_sjyyt"
        )
        referer = login_url
        for _ in range(6):
            r = await self.req(
                "GET",
                next_url,
                allow_redirects=False,
                headers={"Referer": referer, "User-Agent": TTXC_UA},
            )
            location = r["headers"].get("location") or r["headers"].get("Location")
            if not location:
                ok = r["code"] == 200
                if ok and saved_cookies:
                    self.ttxc_restore_cookies(saved_cookies)
                    if self.ecs_token:
                        self.client.cookies.set(
                            "ecs_token", self.ecs_token, domain=".10010.com"
                        )
                return ok
            referer, next_url = next_url, location
        return False

    async def ttxc_init_ttgame(self):
        if not self.ecs_token:
            return False
        self.client.cookies.set("ecs_token", self.ecs_token, domain=".10010.com")
        url = f"{TTXC_APP_BASE_URL}/v1/login/ttGame?channel={TTXC_CHANNEL}&rptId="
        last = {}
        for attempt in range(1, 4):
            if self.ecs_token:
                self.client.cookies.set(
                    "ecs_token", self.ecs_token, domain=".10010.com"
                )
            r = await self.req(
                "POST",
                url,
                json={"unicomTokenId": self.unicom_token_id},
                headers=self.ttxc_headers(auth=False, ecs=True),
            )
            last = r["data"] if isinstance(r["data"], dict) else {}
            if last.get("code") == "0000":
                return True
            if last.get("code") == "4003" and last.get("data"):
                saved = self.ttxc_snapshot_cookies()
                if await self.ttxc_finish_woauth(last.get("data"), saved):
                    r = await self.req(
                        "POST",
                        url,
                        json={"unicomTokenId": self.unicom_token_id},
                        headers=self.ttxc_headers(auth=False, ecs=True),
                    )
                    last = r["data"] if isinstance(r["data"], dict) else {}
                    if last.get("code") == "0000":
                        return True
            if attempt < 3:
                await asyncio.sleep(2)
        self.tlog(f"初始化失败[{last.get('code')}]: {last.get('msg', '')}")
        return False

    async def ttxc_login(self, update_nick=True):
        if not self.ecs_token:
            self.tlog("缺少 ecs_token，跳过")
            return False
        if not await self.ttxc_init_ttgame():
            return False
        data = await self.ttxc_post(
            "/user/v1/login", auth=False, with_user=False, ecs=True
        )
        if data.get("code") != 0:
            self.tlog(f"登录失败[{data.get('code')}]: {data.get('msg', '')}")
            return False
        user = data.get("data") or {}
        self.ttxc_user_id = user.get("userId", "")
        self.ttxc_token = data.get("token", "")
        self.ttxc_charge_level = user.get("chargeLevel") or {}
        self.ttxc_newbie_list = user.get("newbieList")
        self.ttxc_nick_name = user.get("nickName") or ""
        if not self.ttxc_user_id or not self.ttxc_token:
            self.tlog("登录响应缺少 userId/token")
            return False
        carbon = self.ttxc_charge_level.get("carbonNum", 0)
        eco = self.ttxc_charge_level.get("ecologyAmount", 0)
        self.tlog(f"登录成功，碳能量{carbon}g，生态值{eco}")
        if update_nick and not self.ttxc_nick_name and self.ttxc_newbie_done():
            await self.ttxc_update_nick()
        return True

    async def ttxc_update_nick(self):
        nick = (self.mobile or "")[-4:] or str(random.randint(1000, 9999))
        data = await self.ttxc_post("/user/v1/updateNick", {"nickName": nick})
        if data.get("code") == 0:
            self.ttxc_nick_name = nick
            self.tlog(f"已设置昵称 {nick}")
            return True
        self.tlog(f"设置昵称失败[{data.get('code')}]: {data.get('msg', '')}")
        return False

    def ttxc_newbie_done(self):
        steps = getattr(self, "ttxc_newbie_list", None)
        return not isinstance(steps, list) or all(
            step in steps for step in TTXC_NEWBIE_STEPS
        )

    async def ttxc_newbie_mark(self, step):
        target = []
        for item in TTXC_NEWBIE_STEPS:
            target.append(item)
            if item == step:
                break
        data = await self.ttxc_post(
            "/user/v1/newbie", {"newbieList": target, "type": 1}
        )
        if data.get("code") == 0:
            self.ttxc_newbie_list = data.get("data") or target
            return True
        self.tlog(f"新手步骤{step}失败[{data.get('code')}]: {data.get('msg', '')}")
        return False

    def ttxc_newbie_need(self, step):
        steps = getattr(self, "ttxc_newbie_list", None)
        return isinstance(steps, list) and step not in steps

    async def ttxc_first_newbie_land(self, lands=None):
        lands = lands if lands is not None else await self.ttxc_get_lands()
        active = next(
            (
                land
                for land in lands
                if land.get("status") in [2, 3]
                and (land.get("plant") or {}).get("plantId")
            ),
            None,
        )
        if active:
            return active
        return next((land for land in lands if land.get("status") == 1), None)

    async def ttxc_newbie_charge_land(self):
        lands = await self.ttxc_get_lands()
        active = [
            land
            for land in lands
            if land.get("status") == 3 and (land.get("plant") or {}).get("plantId")
        ]
        return next(
            (
                land
                for land in active
                if str((land.get("plant") or {}).get("curLevel")) in ["0", "1"]
            ),
            None,
        ) or (active[0] if active else None)

    async def ttxc_harvest_land(self, land, newbie=False):
        if not land:
            return None
        plant = land.get("plant") or {}
        plant_id, land_index = plant.get("plantId"), land.get("landIndex")
        if not plant_id or not land_index:
            return None
        if land.get("status") == 2 and TTXC_HARVEST_WAIT_SECONDS > 0:
            await asyncio.sleep(TTXC_HARVEST_WAIT_SECONDS)
        path = "/plant/v1/newHarvest" if newbie else "/plant/v1/harvest"
        data = await self.ttxc_post(
            path, {"landIndex": land_index, "plantId": plant_id}
        )
        if data.get("code") == 0:
            self.tlog(f"地块{land_index}收获成功")
            return data.get("data") or {
                "landIndex": land_index,
                "status": 1,
                "plant": None,
            }
        self.tlog(
            f"地块{land_index}收获失败[{data.get('code')}]: {data.get('msg', '')}"
        )
        return None

    async def ttxc_newbie_task(self):
        if self.ttxc_newbie_done():
            return False
        need_farm = any(
            self.ttxc_newbie_need(step)
            for step in ["G03", "G03_2", "G04", "G05", "G09", "G10"]
        )
        lands = await self.ttxc_get_lands() if need_farm else []
        plant_id, current = "", None
        if need_farm:
            current = await self.ttxc_first_newbie_land(lands)
            await self.ttxc_post("/client/v1/plant/type", {})
            plant_id = await self.ttxc_get_plant_id()
            if not plant_id:
                self.tlog("新手任务缺少作物ID")
                return False
        if self.ttxc_newbie_need("G03") and not await self.ttxc_newbie_mark("G03"):
            return False
        if self.ttxc_newbie_need("G03_2"):
            has_crop = (
                current
                and current.get("status") in [2, 3]
                and (current.get("plant") or {}).get("plantId")
            )
            if not has_crop:
                data = await self.ttxc_post(
                    "/client/v1/plant/buy", {"plantId": plant_id, "gameCfgId": ""}
                )
                if data.get("code") != 0:
                    self.tlog(
                        f"新手购买作物失败[{data.get('code')}]: {data.get('msg', '')}"
                    )
                    return False
            if not await self.ttxc_newbie_mark("G03_2"):
                return False
        if self.ttxc_newbie_need("G04"):
            if not current or not current.get("landIndex"):
                self.tlog("新手任务缺少可种植地块")
                return False
            if not (
                current.get("status") in [2, 3]
                and (current.get("plant") or {}).get("plantId")
            ):
                data = await self.ttxc_post(
                    "/plant/v1/planting",
                    {"landIndex": current.get("landIndex"), "plantId": plant_id},
                )
                if data.get("code") != 0:
                    self.tlog(
                        f"新手种植失败[{data.get('code')}]: {data.get('msg', '')}"
                    )
                    return False
                current = data.get("data") or {
                    "landIndex": current.get("landIndex"),
                    "status": 3,
                    "plant": {"plantId": plant_id},
                }
            if not await self.ttxc_newbie_mark("G04"):
                return False
        if self.ttxc_newbie_need("G05"):
            current = (
                current
                if current and current.get("plant")
                else await self.ttxc_first_newbie_land()
            )
            current = await self.ttxc_charge_land(current)
            if not current or not await self.ttxc_newbie_mark("G05"):
                return False
        if self.ttxc_newbie_need("G09"):
            plant = (current or {}).get("plant") or {}
            level = str(plant.get("curLevel") or "")
            if not (
                current
                and current.get("status") == 3
                and plant.get("plantId")
                and level in ["", "0", "1"]
            ):
                current = await self.ttxc_newbie_charge_land()
            current = await self.ttxc_charge_land(current, mock=1)
            if not current or not await self.ttxc_newbie_mark("G09"):
                return False
        if self.ttxc_newbie_need("G10"):
            current = (
                current
                if current and current.get("plant")
                else await self.ttxc_first_newbie_land()
            )
            if not await self.ttxc_harvest_land(
                current, newbie=True
            ) or not await self.ttxc_newbie_mark("G10"):
                return False
        if self.ttxc_newbie_need("G11") and not await self.ttxc_newbie_mark("G11"):
            return False
        if self.ttxc_newbie_need("G12"):
            if not self.ttxc_nick_name and not await self.ttxc_update_nick():
                return False
            if not await self.ttxc_newbie_mark("G12"):
                return False
        self.tlog("新手任务已完成")
        return True

    async def ttxc_sign(self):
        info = await self.ttxc_post("/client/v1/sign/info", {})
        code = (info.get("data") or {}).get("signinCode")
        if not code:
            self.tlog("获取签到码失败")
            return
        user = await self.ttxc_post("/client/v1/sign/user", {"code": code})
        last_time = str((user.get("data") or {}).get("lastSigninTime") or "")
        if last_time[:10] == datetime.now().strftime("%Y-%m-%d"):
            self.tlog("今日已签到")
            return
        data = await self.ttxc_post("/client/v1/sign/signIn", {"code": code})
        if data.get("code") == 0:
            sign_data = data.get("data") or {}
            keep_value = safe_int(
                sign_data.get("keepSigninValue")
                or sign_data.get("lastKeepSigninValue")
                or sign_data.get("totalSigninValue")
            )
            award_items = (info.get("data") or {}).get("awards") or []
            energy = 0
            for item in award_items:
                if (
                    item.get("awardType") == "KEEP"
                    and safe_int(item.get("signinValue")) == keep_value
                ):
                    energy = safe_int(item.get("carbonEnergyAmount"))
                    break
            if not energy:
                charge_level = data.get("chargeLevel") or {}
                before = safe_int((self.ttxc_charge_level or {}).get("carbonNum"))
                after = safe_int(charge_level.get("carbonNum"))
                energy = max(after - before, 0)
            if data.get("chargeLevel"):
                self.ttxc_charge_level = (
                    data.get("chargeLevel") or self.ttxc_charge_level
                )
            self.tlog(f"签到成功 +{energy}g" if energy else "签到成功")
        else:
            self.tlog(f"签到失败[{data.get('code')}]: {data.get('msg', '')}")

    async def ttxc_get_tasks(self):
        data = await self.ttxc_post("/client/v1/task/list", {})
        if data.get("code") != 0:
            self.tlog(f"获取任务列表失败[{data.get('code')}]: {data.get('msg', '')}")
            return []
        tasks = []
        for group in data.get("data") or []:
            for task in group.get("taskList") or []:
                task["taskGroupName"] = group.get("taskGroupName", "")
                tasks.append(task)
        return tasks

    async def ttxc_finish_task(self, task):
        task_id = task.get("taskCode")
        if not task_id:
            return False
        data = await self.ttxc_post("/client/v1/task/finish", {"taskId": task_id})
        name = task.get("taskTitle", task_id)
        if data.get("code") == 0:
            reward = task.get("carbonEnergyAmount") or 0
            self.tlog(f"领取[{name}]成功 +{reward}g")
            return True
        self.tlog(f"领取[{name}]失败[{data.get('code')}]: {data.get('msg', '')}")
        return False

    async def ttxc_do_task(self, task):
        data = await self.ttxc_post(
            "/client/v1/task/do", {"taskId": task.get("taskCode")}
        )
        name = task.get("taskTitle", task.get("taskCode", ""))
        if data.get("code") == 0:
            self.tlog(f"已执行[{name}]")
            return True
        self.tlog(f"执行[{name}]失败[{data.get('code')}]: {data.get('msg', '')}")
        return False

    async def ttxc_claim_ready_tasks(self, tasks, claimed=None):
        if claimed is None:
            claimed = set()
        count = 0
        for task in tasks:
            task_id = task.get("taskCode")
            if task.get("taskStatus") == "UNCLA" and task_id not in claimed:
                if await self.ttxc_finish_task(task):
                    claimed.add(task_id)
                    count += 1
        return count

    async def ttxc_do_jump_tasks(self, tasks):
        count = 0
        for task in tasks:
            if (
                task.get("taskType") == "GAME"
                and task.get("taskStatus") == "UNDO"
                and task.get("jumpUrl")
            ):
                if await self.ttxc_do_task(task):
                    count += 1
                await asyncio.sleep(1)
        return count

    async def ttxc_do_garbage_task(self, tasks):
        task = next(
            (
                t
                for t in tasks
                if t.get("taskType") == "GAME"
                and t.get("taskStatus") == "UNDO"
                and "垃圾分类" in t.get("taskTitle", "")
            ),
            None,
        )
        if not task:
            return False
        start = await self.ttxc_post("/user/v1/start", {})
        answer_no = (start.get("data") or {}).get("answerNo")
        if not answer_no:
            self.tlog("垃圾分类开始失败")
            return False
        await asyncio.sleep(TTXC_GARBAGE_WAIT_SECONDS)
        data = await self.ttxc_post("/user/v1/finish", {"answerNo": answer_no})
        if data.get("code") == 0:
            self.tlog("垃圾分类已通关")
            return True
        self.tlog(f"垃圾分类通关失败[{data.get('code')}]: {data.get('msg', '')}")
        return False

    async def ttxc_prepare_newbie_energy(self, claimed=None):
        if claimed is None:
            claimed = set()
        await self.ttxc_sign()
        tasks = await self.ttxc_get_tasks()
        await self.ttxc_claim_ready_tasks(tasks, claimed)
        await self.ttxc_do_jump_tasks(tasks)
        await self.ttxc_do_garbage_task(tasks)
        tasks = await self.ttxc_get_tasks()
        await self.ttxc_claim_ready_tasks(tasks, claimed)

    async def ttxc_get_lands(self):
        land = safe_int((self.ttxc_charge_level or {}).get("land"), 4)
        data = await self.ttxc_post("/plant/v1/user", {"land": land})
        if data.get("code") != 0:
            self.tlog(f"获取土地失败[{data.get('code')}]: {data.get('msg', '')}")
            return []
        return data.get("data") or []

    async def ttxc_get_plant_id(self):
        data = await self.ttxc_post(
            "/client/v1/plant/page", {"itemType": "SPE", "pageNum": 1, "pageSize": 20}
        )
        items = (data.get("data") or {}).get("list") or []
        return items[0].get("itemNo", "") if items else ""

    async def ttxc_plant_land(self, land_index, plant_id=None):
        plant_id = plant_id or await self.ttxc_get_plant_id()
        if not plant_id or not land_index:
            return None
        buy = await self.ttxc_post(
            "/client/v1/plant/buy", {"plantId": plant_id, "gameCfgId": ""}
        )
        if buy.get("code") != 0:
            self.tlog(f"购买种子失败[{buy.get('code')}]: {buy.get('msg', '')}")
            return None
        data = await self.ttxc_post(
            "/plant/v1/planting", {"landIndex": land_index, "plantId": plant_id}
        )
        if data.get("code") == 0:
            self.tlog(f"已在地块{land_index}种植作物")
            return {
                "landIndex": land_index,
                "status": 3,
                "plant": {"plantId": plant_id},
            }
        self.tlog(
            f"地块{land_index}种植失败[{data.get('code')}]: {data.get('msg', '')}"
        )
        return None

    async def ttxc_ensure_planted_lands(self, lands):
        active = [
            l
            for l in lands
            if l.get("status") in [2, 3] and (l.get("plant") or {}).get("plantId")
        ]
        empty = [l for l in lands if l.get("status") == 1]
        if not empty:
            return active
        plant_id = await self.ttxc_get_plant_id()
        if not plant_id:
            return active
        for land in empty:
            planted = await self.ttxc_plant_land(land.get("landIndex"), plant_id)
            if planted:
                active.append(planted)
        return active

    async def ttxc_charge_land(self, land, mock=None):
        if not land:
            return None
        plant = land.get("plant") or {}
        plant_id, land_index = plant.get("plantId"), land.get("landIndex")
        if not plant_id or not land_index:
            return None
        payload = {"landIndex": land_index, "plantId": plant_id}
        if mock is not None:
            payload["mock"] = mock
        data = await self.ttxc_post("/plant/v1/charge", payload)
        if data.get("code") == 0:
            self.tlog(f"地块{land_index}充能成功")
            result = data.get("data") or {}
            if result and not result.get("plant"):
                result["plant"] = plant
            return result or land
        self.tlog(
            f"地块{land_index}充能失败[{data.get('code')}]: {data.get('msg', '')}"
        )
        if "余额不足" in str(data.get("msg", "")):
            self.ttxc_no_energy = True
        return None

    async def ttxc_harvest_and_replant(self, land):
        harvested = await self.ttxc_harvest_land(land)
        if harvested and land:
            return await self.ttxc_plant_land(land.get("landIndex"))
        return None

    async def ttxc_grow_land_to_harvest(self, land):
        current = land
        if current.get("status") == 2:
            await self.ttxc_harvest_and_replant(current)
            return
        charged = 0
        while current.get("status") == 3 and charged < TTXC_GROW_MAX_CHARGE_PER_LAND:
            if self.ttxc_no_energy:
                return
            current = await self.ttxc_charge_land(current)
            if not current:
                return
            charged += 1
            if current.get("status") == 2:
                await self.ttxc_harvest_and_replant(current)
                return
            if charged < TTXC_GROW_MAX_CHARGE_PER_LAND:
                await asyncio.sleep(1)
        if current.get("status") == 3:
            self.tlog(f"地块{current.get('landIndex')}催熟达到上限，跳过")

    def ttxc_replace_land(self, lands, updated):
        land_index = updated.get("landIndex")
        for i, land in enumerate(lands):
            if land.get("landIndex") == land_index:
                lands[i] = updated
                return
        lands.append(updated)

    async def ttxc_complete_charge_task(self, active, remaining):
        while remaining > 0:
            if self.ttxc_no_energy:
                return
            immature = [
                land
                for land in active
                if land.get("status") == 3 and (land.get("plant") or {}).get("plantId")
            ]
            if not immature:
                self.tlog("未成熟作物不足，提前结束10次充能补足")
                return
            progressed = False
            for land in immature:
                if remaining <= 0 or self.ttxc_no_energy:
                    return
                result = await self.ttxc_charge_land(land)
                if result:
                    self.ttxc_replace_land(active, result)
                    remaining -= 1
                    progressed = True
                await asyncio.sleep(1)
            if not progressed:
                self.tlog("充能未成功，提前结束10次充能补足")
                return

    async def ttxc_farm_tasks(self, tasks):
        charge_task = next(
            (t for t in tasks if "10次作物充能" in t.get("taskTitle", "")), None
        )
        land_task = next(
            (t for t in tasks if "三块不同" in t.get("taskTitle", "")), None
        )
        harvest_task = next(
            (t for t in tasks if "收获一次作物" in t.get("taskTitle", "")), None
        )
        if not charge_task and not land_task and not harvest_task:
            return
        charge_pending = (
            charge_task if (charge_task or {}).get("taskStatus") == "UNDO" else None
        )
        land_pending = (
            land_task if (land_task or {}).get("taskStatus") == "UNDO" else None
        )
        harvest_pending = (
            harvest_task if (harvest_task or {}).get("taskStatus") == "UNDO" else None
        )
        if not charge_pending and not land_pending and not harvest_pending:
            return
        lands = await self.ttxc_get_lands()
        active = await self.ttxc_ensure_planted_lands(lands)
        need_land = max(
            safe_int((land_pending or {}).get("finishValue"))
            - safe_int((land_pending or {}).get("doneValue")),
            0,
        )
        if harvest_pending and not charge_pending and not land_pending:
            for land in active:
                if land.get("status") == 2:
                    await self.ttxc_harvest_and_replant(land)
        if not active:
            self.tlog("没有可充能作物")
            return
        charged = 0
        for i, land in enumerate(active[:need_land]):
            if self.ttxc_no_energy:
                break
            result = await self.ttxc_charge_land(land)
            if result:
                active[i] = result
                charged += 1
                await asyncio.sleep(1)
        need_charge = max(
            safe_int((charge_pending or {}).get("finishValue"))
            - safe_int((charge_pending or {}).get("doneValue"))
            - charged,
            0,
        )
        await self.ttxc_complete_charge_task(active, need_charge)
        for land in active:
            await self.ttxc_grow_land_to_harvest(land)

    async def farm_task(self):
        self._task_tag = "通通乡村"
        self.tlog("开始")
        if not await self.ttxc_login():
            return
        claimed = set()
        if not self.ttxc_newbie_done():
            await self.ttxc_prepare_newbie_energy(claimed)
        if not self.ttxc_newbie_done() and not await self.ttxc_newbie_task():
            return
        await self.ttxc_sign()
        tasks = await self.ttxc_get_tasks()
        await self.ttxc_claim_ready_tasks(tasks, claimed)
        await self.ttxc_do_jump_tasks(tasks)
        await self.ttxc_do_garbage_task(tasks)
        await self.ttxc_farm_tasks(tasks)
        tasks = await self.ttxc_get_tasks()
        await self.ttxc_claim_ready_tasks(tasks, claimed)

    # === 8. 商都福利 ===
    def shangdu_token(self):
        """获取 app.shangdu.com 下发的 token cookie"""
        for c in self.client.cookies.jar:
            if c.name == "token" and "shangdu.com" in (c.domain or ""):
                return c.value
        return self.client.cookies.get("token", "")

    def shangdu_apply_set_cookie(self, headers):
        """从响应头提取 token 并写入 cookie jar"""
        for item in iter_set_cookies(headers):
            if "token=" not in item:
                continue
            token = item.split("token=", 1)[1].split(";", 1)[0].strip()
            if token:
                self.client.cookies.set("token", token, domain="app.shangdu.com")
                return

    @staticmethod
    def shangdu_sorted_json(data):
        """对齐前端 request.f6956a2d.js 的 It(): 去空值后按 key 排序 JSON.stringify"""
        if not data:
            return "{}"

        def clean(v):
            if isinstance(v, dict):
                return {k: clean(v[k]) for k in sorted(v) if v[k] not in (None, "")}
            if isinstance(v, list):
                return [clean(x) for x in v if x not in (None, "")]
            return v

        return json.dumps(clean(data), ensure_ascii=False, separators=(",", ":"))

    def shangdu_decrypt(self, raw):
        """解密 /unicomapp/* 返回的 SM2 密文（HAR: request.f6956a2d.js）"""
        if raw is None:
            return None
        if isinstance(raw, dict):
            return raw
        text = str(raw).strip()
        if not text:
            return None
        if text[0] in "{[":
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"raw": text}
        text = text.strip('"')
        if not text.startswith("04"):
            return {"raw": text}
        try:
            plain = sm2.CryptSM2(
                private_key=SHANGDU_SM2_PRIVATE_KEY, public_key=""
            ).decrypt(bytes.fromhex(text[2:].lower()))
            if not isinstance(plain, (bytes, bytearray)) or not plain:
                raise ValueError(
                    f"SM2解密返回非法类型或空值: {type(plain).__name__}"
                )
            return json.loads(plain.decode("utf-8"))
        except Exception as e:
            self.tlog_exc(e, "SM2解密")
            return {"_cipher": text}

    def shangdu_headers(self, method, path, params=None, data=None):
        """生成商都福利 H5 接口签名头；已与 HAR signature 校验一致"""
        request_id = "".join(
            random.choices(string.ascii_lowercase + string.digits, k=11)
        )
        ts = str(int(time.time() * 1000))

        merged = {}
        if "?" in path:
            merged.update({k: v[-1] for k, v in parse_qs(urlparse(path).query).items()})
        if params:
            merged.update(params)
        if data:
            merged.update(data)

        body = self.shangdu_sorted_json(merged)
        sign_raw = f"{SHANGDU_SIGN_SECRET}{request_id}{ts}{body}"
        token = self.shangdu_token()
        headers = {
            "Accept": "application/json, text/plain, */*",
            "User-Agent": SHANGDU_UA,
            "Referer": f"{SHANGDU_BASE}/unicomapp/",
            "X-Client-Type": "H5",
            "timestamp": ts,
            "requestId": request_id,
            "signature": hashlib.md5(sign_raw.encode()).hexdigest().upper(),
        }
        if token:
            headers["Authorization"] = token
            headers["Cookie"] = f"token={token}"
        if method.upper() == "POST":
            headers["Origin"] = SHANGDU_BASE
        return headers

    async def shangdu_login(self):
        """HAR: openPlatLineNew -> monthlyBenefit/static/index.html -> Set-Cookie token -> /unicomapp/"""
        if self.ecs_token:
            self.client.cookies.set("ecs_token", self.ecs_token, domain=".10010.com")

        r = await self.req(
            "GET",
            "https://m.client.10010.com/mobileService/openPlatform/openPlatLineNew.htm",
            params={
                "to_url": SHANGDU_ENTRY,
                "channel": "KSTD",
                "duanlianjieabc": "tbVtc",
            },
            headers={
                "User-Agent": SHANGDU_UA,
                "Referer": "https://img.client.10010.com/",
            },
            allow_redirects=False,
        )
        loc = r["headers"].get("location") or r["headers"].get("Location")
        if not loc:
            return False

        r = await self.req(
            "GET",
            loc,
            headers={
                "User-Agent": SHANGDU_UA,
                "Referer": "https://img.client.10010.com/",
            },
            allow_redirects=False,
        )
        self.shangdu_apply_set_cookie(r["headers"])
        if self.shangdu_token():
            return True

        loc2 = r["headers"].get("location") or r["headers"].get("Location")
        if loc2:
            if loc2.startswith("/"):
                loc2 = urljoin(SHANGDU_BASE, loc2)
            loc2 = loc2.split("#", 1)[0]
            r = await self.req(
                "GET",
                loc2,
                headers={
                    "User-Agent": SHANGDU_UA,
                    "Referer": "https://img.client.10010.com/",
                },
                allow_redirects=False,
            )
            self.shangdu_apply_set_cookie(r["headers"])

        if self.shangdu_token():
            await self.req(
                "GET",
                f"{SHANGDU_BASE}/unicomapp/",
                headers={
                    "User-Agent": SHANGDU_UA,
                    "Referer": "https://img.client.10010.com/",
                },
            )
            return True
        return False

    async def shangdu_api(self, method, path, params=None, data=None):
        """调用 /unicomapp/* 并解密 SM2 响应"""
        url = f"{SHANGDU_BASE}/unicomapp{path}"
        headers = self.shangdu_headers(method, path, params, data)
        r = await self.req(
            method,
            url,
            headers=headers,
            params=params or None,
            json=data if data else None,
        )
        payload = self.shangdu_decrypt(r.get("data"))
        return {
            "code": r.get("code", -1),
            "headers": r.get("headers", {}),
            "data": payload,
        }

    async def shangdu_click_log(self, event_code, event_name, module, seq_no, url=""):
        return await self.shangdu_api(
            "GET",
            "/activityArea/recordClickOperationLog",
            params={
                "pageName": "MonthRechargeWelfare",
                "activeName": "福利月月冲",
                "pageSeq": "1",
                "seqNo": seq_no,
                "eventCode": event_code,
                "eventName": event_name,
                "module": module,
                "url": url,
            },
        )

    def shangdu_api_ok(self, resp):
        data = resp.get("data") if isinstance(resp, dict) else None
        return (
            resp.get("code") == 200
            and isinstance(data, dict)
            and data.get("code") == 200
        )

    def shangdu_api_msg(self, resp, default=""):
        data = resp.get("data") if isinstance(resp, dict) else None
        if isinstance(data, dict):
            return data.get("msg") or data.get("message") or default
        return default

    def shangdu_lottery_prize_name(self, prize_index, is_festival=False):
        """lottery 接口 data 为转盘奖品下标，非金额（对齐 MonthRechargeWelfare.js）"""
        prizes = (
            SHANGDU_LOTTERY_FESTIVAL_PRIZES if is_festival else SHANGDU_LOTTERY_PRIZES
        )
        if isinstance(prize_index, int) and 0 <= prize_index < len(prizes):
            return prizes[prize_index]
        return str(prize_index)

    async def shangdu_task(self):
        self._task_tag = "商都福利"
        if "河南" not in self.province:
            self.tlog(f"非河南归属地({self.province})，跳过")
            return

        self.tlog("开始")
        if not await self.shangdu_login():
            self.tlog("登录失败")
            return
        self.tlog("登录成功")

        # HAR 顺序: init -> rollingText -> signIn -> SIGN_CLICK -> init -> lottery -> LOTTERY_CLICK -> init
        init_r = await self.shangdu_api("GET", "/monthlyRecharge/init")
        if not self.shangdu_api_ok(init_r):
            self.tlog(
                f"初始化失败 HTTP {init_r.get('code')} {self.shangdu_api_msg(init_r)}"
            )
            return

        init_data = init_r["data"].get("data") or {}
        sign_info = init_data.get("signInInfo") or {}
        lottery_info = init_data.get("lotteryInfo") or {}
        self.tlog(
            f"初始化完成 签到状态={sign_info.get('status')} 抽奖次数={lottery_info.get('remainCount')}"
        )

        await self.shangdu_api("GET", "/monthlyRecharge/rollingText")

        if sign_info.get("status") == 1:
            self.tlog(f"今日已签到(累计{sign_info.get('signInCount', 0)}天)")
        else:
            sign_r = await self.shangdu_api("POST", "/monthlyRecharge/signIn")
            await self.shangdu_click_log("SIGN_CLICK", "签到点击", "signIn", "A")
            if self.shangdu_api_ok(sign_r):
                self.tlog(f"签到成功 {self.shangdu_api_msg(sign_r)}")
            else:
                self.tlog(
                    f"签到失败 HTTP {sign_r.get('code')} {self.shangdu_api_msg(sign_r)}"
                )

        await asyncio.sleep(1)
        init_r = await self.shangdu_api("GET", "/monthlyRecharge/init")
        if self.shangdu_api_ok(init_r):
            lottery_info = (init_r["data"].get("data") or {}).get(
                "lotteryInfo"
            ) or lottery_info

        remain = require_int(
            lottery_info.get("remainCount"), "shangdu.remainCount", minimum=0
        )
        max_lottery = remain if SHANGDU_LOTTERY_MAX is None else SHANGDU_LOTTERY_MAX
        draw_times = min(remain, max_lottery) if remain > 0 else 0
        if draw_times <= 0:
            self.tlog("无剩余抽奖次数")
        else:
            for i in range(draw_times):
                await asyncio.sleep(1)
                lottery_r = await self.shangdu_api("POST", "/monthlyRecharge/lottery")
                await self.shangdu_click_log(
                    "LOTTERY_CLICK", "抽奖点击", "lottery", "C"
                )
                if self.shangdu_api_ok(lottery_r):
                    body = lottery_r.get("data")
                    if not isinstance(body, dict):
                        body = {}
                    prize_idx = body.get("data")
                    prize_name = self.shangdu_lottery_prize_name(
                        prize_idx, bool(lottery_info.get("isFestival"))
                    )
                    self.tlog(
                        f"第{i + 1}次抽奖成功 原始返回={body} 奖品=[{prize_name}]"
                    )
                else:
                    self.tlog(
                        f"第{i + 1}次抽奖失败 HTTP {lottery_r.get('code')} {self.shangdu_api_msg(lottery_r)}"
                    )
                    break

        await self.shangdu_api("GET", "/monthlyRecharge/init")

    def cloud_disk_token(self):
        """联通云盘 userToken（上传大比拼等活动共用）。"""
        return (getattr(self, "cloud_disk", None) or {}).get("userToken", "")

    def cloud_activity_sign(self, payload):
        """panservice 活动请求签名。"""
        raw = (
            "&".join(f"{k}={payload[k]}" for k in sorted(payload))
            + f"&secret={CLOUD_PAN_SIGN_SECRET}"
        )
        return hmac.new(
            CLOUD_PAN_SIGN_SECRET.encode(), raw.encode(), hashlib.sha256
        ).hexdigest()

    # === 9. 云盘上传大比拼===

    def battle_log(self, msg):
        self.task_log("上传大比拼", msg)

    def battle_log_exc(self, e, action=None):
        self.battle_log(f"异常: {self.format_exc(e, action)}")

    def battle_referer(self):
        if self.battle_page_referer:
            return self.battle_page_referer
        token = self.cloud_disk_token()
        return (
            f"https://panservice.mail.wo.cn/h5/activitymobile/cloudBattle"
            f"?activityId={quote(CLOUD_BATTLE_ACTIVITY_ID)}&touchpoint={CLOUD_BATTLE_TOUCHPOINT}&token={token}"
        )

    async def battle_enter(self):
        """进入活动页，刷新 token 并获取带 ticket 的 Referer（lottery-times 必需）"""
        token = self.cloud_disk_token()
        if not token:
            return False
        entry = (
            f"https://panservice.mail.wo.cn/h5/activitymobile/cloudBattle"
            f"?activityId={quote(CLOUD_BATTLE_ACTIVITY_ID)}&touchpoint={CLOUD_BATTLE_TOUCHPOINT}"
            f"&clientid=1001000003&token={token}"
        )
        r = await self.req(
            "GET",
            "https://m.client.10010.com/mobileService/openPlatform/openPlatLineNew.htm",
            params={"to_url": entry},
            allow_redirects=False,
        )
        url = r["headers"].get("location") or r["headers"].get("Location")
        if not url:
            return False
        for _ in range(4):
            if url.startswith("/"):
                url = urljoin("https://panservice.mail.wo.cn", url)
            self.battle_page_referer = url.split("#", 1)[0]
            q = parse_qs(urlparse(url).query)
            new_token = (q.get("token") or [""])[0]
            if new_token:
                self.cloud_disk = {"userToken": new_token}
            if "ticket=" in url:
                return True
            r = await self.req("GET", url, allow_redirects=False)
            nxt = r["headers"].get("location") or r["headers"].get("Location")
            if not nxt or nxt == url:
                return "ticket=" in url
            url = nxt
        return False

    def battle_headers(self, client_id="1001000003", extra=None):
        token = self.cloud_disk_token()
        if not token:
            return {}
        headers = {
            "X-YP-Access-Token": token,
            "Accept": "application/json, text/plain, */*",
            "source-type": "woapi",
            "requestTime": str(int(time.time() * 1000)),
            "User-Agent": BATTLE_UA,
            "clientId": "1001000165",
            "X-SH-Access-Token": "",
            "X-YP-GRAY-FLAG": "undefined",
            "Content-Type": "application/json",
            "X-YP-Client-Id": client_id,
            "token": token,
            "Origin": "https://panservice.mail.wo.cn",
            "Referer": self.battle_referer(),
        }
        if extra:
            headers.update(extra)
        return headers

    async def battle_post(self, path, payload=None, client_id="1001000003", extra=None):
        headers = self.battle_headers(client_id, extra)
        if not headers:
            return {}
        r = await self.req(
            "POST",
            f"https://panservice.mail.wo.cn{path}",
            headers=headers,
            json=payload or {},
        )
        return require_dict_data(r, path)

    async def battle_get(self, path, params=None, client_id="1001000003", extra=None):
        headers = self.battle_headers(client_id, extra)
        if not headers:
            return {}
        r = await self.req(
            "GET",
            f"https://panservice.mail.wo.cn{path}",
            headers=headers,
            params=params or {},
        )
        return require_dict_data(r, path)

    def battle_encrypt_fileinfo(self, info, token):
        key = token[:16].encode()
        iv = CLOUD_BATTLE_FILEINFO_IV.encode()
        plaintext = json.dumps(info, separators=(",", ":"))
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return base64.b64encode(
            cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        ).decode()

    async def battle_signed_post(
        self, path, key, payload=None, client_id="1001000003", extra=None
    ):
        ts = await self.battle_post(
            "/activity/getTimestamp", {"key": key}, client_id, extra
        )
        result = ts.get("result") or {}
        nonce = result.get("nonce")
        timestamp = result.get("timestamp")
        if not nonce or not timestamp:
            self.battle_log(f"getTimestamp失败 {response_summary(ts)}")
            return {}
        body = dict(payload or {})
        body.update(
            {
                "activityId": CLOUD_BATTLE_ACTIVITY_ID,
                "nonce": nonce,
                "timestamp": timestamp,
            }
        )
        body["sign"] = self.cloud_activity_sign(body)
        return await self.battle_post(path, body, client_id, extra)

    async def battle_check_opened(self):
        """返回 True/False 表示是否已开启；None 表示查询失败。"""
        data = await self.battle_get(
            "/activity/checkActivityStatus", {"activityId": CLOUD_BATTLE_ACTIVITY_ID}
        )
        meta = data.get("meta") or {}
        if str(meta.get("code")) != "200":
            self.battle_log(f"查询开启状态失败 {response_summary(data)}")
            return None
        result = data.get("result")
        if not isinstance(result, dict) or "state" not in result:
            self.battle_log(f"查询开启状态失败 {response_summary(data)}")
            return None
        try:
            state = require_int(result["state"], "checkActivityStatus.state")
        except ValueError:
            self.battle_log(f"查询开启状态失败 {response_summary(data)}")
            return None
        if state not in (0, 1):
            self.battle_log(f"查询开启状态失败 {response_summary(data)}")
            return None
        return state == 1

    async def battle_open_activity(self):
        if not self.province or not self.province_code:
            self.battle_log("缺少省份信息，无法开启冲榜")
            return False
        data = await self.battle_post(
            "/activity/openActivity",
            {
                "activityId": CLOUD_BATTLE_ACTIVITY_ID,
                "provinceCode": self.province_code,
                "provinceName": self.province,
            },
        )
        meta = data.get("meta") or {}
        if (
            str(meta.get("code")) == "200"
            and safe_int((data.get("result") or {}).get("state")) == 1
        ):
            self.battle_log(f"开启冲榜成功 {self.province}")
            return True
        self.battle_log(f"开启冲榜失败 {meta.get('message') or response_summary(data)}")
        return False

    async def battle_lottery_times(self):
        """返回 (次数, data)；次数为 None 表示查询失败。"""
        data = await self.battle_get(
            "/activity/lottery/lottery-times", {"activityId": CLOUD_BATTLE_ACTIVITY_ID}
        )
        meta = data.get("meta") or {}
        if str(meta.get("code")) != "200":
            self.battle_log(f"查询抽奖次数失败 {response_summary(data)}")
            return None, data
        result = data.get("result")
        try:
            times = require_int(result, "lotteryTimes", minimum=0)
        except ValueError:
            self.battle_log(f"查询抽奖次数失败 {response_summary(data)}")
            return None, data
        return times, data

    def battle_drawn_today(self, records):
        today = datetime.now().date()
        for item in records or []:
            if not isinstance(item, dict):
                continue
            create_time = item.get("createTime") or ""
            try:
                if datetime.strptime(create_time[:10], "%Y-%m-%d").date() == today:
                    return True
            except ValueError:
                continue
        return False

    async def battle_upload_file(self):
        token = self.cloud_disk_token()
        if not token:
            return False
        content = CLOUD_BATTLE_FILE_CONTENT.encode("utf-8")
        file_name = CLOUD_BATTLE_FILE_NAME
        file_info = {
            "batchNo": datetime.now().strftime("%Y%m%d%H%M%S"),
            "fileName": file_name,
            "fileSize": len(content),
            "fileType": 1,
            "directoryId": "0",
            "spaceType": "0",
        }
        form = {
            "uniqueId": f"{int(time.time() * 1000)}_{random.randint(100000, 999999)}",
            "accessToken": token,
            "psToken": "",
            "totalPart": "1",
            "partSize": str(len(content)),
            "partIndex": "1",
            "channel": "wocloud",
            "fileName": file_name,
            "fileSize": str(len(content)),
            "directoryId": "0",
            "spaceType": "0",
            "fileInfo": self.battle_encrypt_fileinfo(file_info, token),
        }
        headers = {
            "User-Agent": BATTLE_UA,
            "Referer": self.battle_referer(),
            "accessToken": token,
            "access-token": token,
        }
        try:
            r = await self.client.post(
                CLOUD_BATTLE_UPLOAD_URL,
                data=form,
                files={"file": (file_name, content, "text/plain")},
                headers=headers,
                timeout=60.0,
            )
            data = (
                r.json() if r.text.strip().startswith("{") else {"text": r.text[:200]}
            )
        except Exception as e:
            self.battle_log(f"上传异常: {self.format_exc(e, 'upload2C')}")
            return False
        if str(data.get("code")) == "0000":
            raw_data = data.get("data")
            if not isinstance(raw_data, dict):
                self.battle_log(
                    f"上传失败 {data.get('msg') or response_summary(data)}"
                )
                return False
            fid = raw_data.get("fid", "")
            self.battle_log(
                f"上传成功 {file_name} ({len(content)}B) fid={str(fid)[:24]}..."
            )
            return True
        self.battle_log(f"上传失败 {data.get('msg') or response_summary(data)}")
        return False

    async def battle_wait_lottery_times(self, max_wait=8):
        """轮询抽奖次数；返回次数，None 表示查询失败，0 表示合法无次数。"""
        for i in range(max_wait):
            if i:
                await asyncio.sleep(1)
            count, _ = await self.battle_lottery_times()
            if count is None:
                return None
            if count > 0:
                self.battle_log(f"抽奖次数 {count}")
                return count
        self.battle_log("上传后未获得抽奖次数")
        return 0

    async def battle_province_ranking(self):
        data = await self.battle_signed_post(
            "/activity/file/upload/battle/provinceRanking",
            "activity:file:upload:battle:rank",
            {"topN": 34},
        )
        meta = data.get("meta") or {}
        if str(meta.get("code")) != "200":
            self.battle_log(
                f"省份排名查询失败 {meta.get('message') or response_summary(data)}"
            )
            return False
        return True

    async def battle_draw_lottery(self):
        prize = await self.battle_signed_post("/activity/lottery", "activity:lottery")
        meta = prize.get("meta") or {}
        if str(meta.get("code")) != "200":
            self.battle_log(
                f"抽奖失败 {meta.get('message') or response_summary(prize)}"
            )
            return False
        result = prize.get("result") or {}
        prize_name = result.get("prizeName") or response_summary(prize)
        self.battle_log(f"抽奖成功 {prize_name}")
        return True

    async def cloud_battle_task(self):
        """上传大比拼：进入活动 -> 开启冲榜 -> 上传文件 -> 抽奖"""
        if not self.cloud_disk_token():
            return
        self._task_tag = "上传大比拼"
        self.battle_log("开始")
        if not await self.battle_enter():
            self.battle_log("进入活动页失败")
            return

        status = await self.battle_get(
            "/activity/activity-status", {"activityId": CLOUD_BATTLE_ACTIVITY_ID}
        )
        if str((status.get("meta") or {}).get("code")) != "200":
            self.battle_log(f"查询活动状态失败 {response_summary(status)}")
            return
        status_result = status.get("result")
        if not isinstance(status_result, dict) or "activityStatus" not in status_result:
            self.battle_log(
                f"查询活动状态失败 响应缺少activityStatus {response_summary(status)}"
            )
            return
        try:
            activity_status = require_int(
                status_result.get("activityStatus"), "activityStatus"
            )
        except ValueError:
            self.battle_log(
                f"查询活动状态失败 activityStatus非法 {response_summary(status)}"
            )
            return
        if activity_status != 1:
            self.battle_log("活动未上线或已结束")
            return

        opened = await self.battle_check_opened()
        if opened is None:
            return
        if not opened:
            if not await self.battle_open_activity():
                return
        else:
            self.battle_log("冲榜已开启")

        records = await self.battle_get(
            "/activity/lottery/recordList", {"activityId": CLOUD_BATTLE_ACTIVITY_ID}
        )
        if str((records.get("meta") or {}).get("code")) != "200":
            self.battle_log(f"查询抽奖记录失败 {response_summary(records)}")
            return
        record_list = records.get("result")
        if not isinstance(record_list, list):
            self.battle_log(
                f"查询抽奖记录失败 result非list {response_summary(records)}"
            )
            return
        if self.battle_drawn_today(record_list):
            self.battle_log("今日已抽奖")
            return

        if not await self.battle_province_ranking():
            return

        times, _ = await self.battle_lottery_times()
        if times is None:
            return
        if times <= 0:
            if await self.battle_upload_file():
                if not await self.battle_province_ranking():
                    return
            else:
                # 服务端可能已收到上传（60s ReadTimeout 后仍计数），不能直接放弃
                self.battle_log("上传疑似超时，仍尝试查询抽奖次数")
            times = await self.battle_wait_lottery_times()
            if times is None or times <= 0:
                return
        else:
            self.battle_log(f"抽奖次数 {times}")

        await self.battle_draw_lottery()

    # === 云手机积分 / 夏日刮一刮 / 打卡挑战赛 ===
    def uphone_biz_ok(self, data):
        """业务成功：data 必须为 dict 且 code 表示成功。"""
        if not isinstance(data, dict):
            return False
        return data.get("code") in (200, "200", 0, "0")

    def uphone_biz_data(self, r):
        """取出 req() 的 data 字段；非 dict 时返回 None。"""
        if not isinstance(r, dict):
            return None
        data = r.get("data")
        return data if isinstance(data, dict) else None

    def uphone_app_headers(self, extra=None):
        h = {
            "User-Agent": UPHONE_APP_UA,
            "Accept": "*/*",
            "channel": UPHONE_CHANNEL,
            "channelCode": UPHONE_CHANNEL,
            "deviceId": self.uphone_device_id or "0",
        }
        if self.uphone_cp_token:
            h["Authorization"] = self.uphone_cp_token
        if extra:
            h.update(extra)
        return h

    def uphone_h5_headers(self, extra=None):
        h = {
            "User-Agent": UPHONE_H5_UA,
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json; charset=UTF-8",
            "Origin": "https://uphone.wostore.cn",
        }
        if self.uphone_usr_token:
            h["X-USR-TOKEN"] = self.uphone_usr_token
        if extra:
            h.update(extra)
        return h

    def uphone_checkin_headers(self):
        """打卡挑战赛（h5forphone CLD13），复用 SSO cpToken。"""
        token = self.uphone_cp_token or ""
        return {
            "User-Agent": UPHONE_H5_UA,
            "Accept": "*/*",
            "Content-Type": "application/json",
            "Origin": "https://h5forphone.wostore.cn",
            "Referer": f"{UPHONE_CHECKIN_PAGE}?token={token}",
            "X-Requested-With": "XMLHttpRequest",
        }

    async def uphone_checkin_post(self, path, extra_json=None):
        """POST h5forphone/activity/*，body 带 accesstoken=cpToken。"""
        if not self.uphone_cp_token:
            return None
        payload = {"accesstoken": self.uphone_cp_token}
        if extra_json:
            payload.update(extra_json)
        r = await self.req(
            "POST",
            f"{UPHONE_H5FORPHONE}/{path.lstrip('/')}",
            headers=self.uphone_checkin_headers(),
            json=payload,
        )
        return self.uphone_biz_data(r)

    async def uphone_sso_login(self):
        """ecs_token → ticket → cpToken"""
        if not self.ecs_token:
            self.tlog("无 ecs_token")
            return False
        self.uphone_device_id = hashlib.md5(
            f"{self.mobile or self.uuid}".encode()
        ).hexdigest()

        r = await self.req(
            "GET",
            "https://m.client.10010.com/edop_ng/getTicketByNative",
            params={"token": self.ecs_token, "appId": UPHONE_EDOP_APP_ID},
            headers={"User-Agent": UPHONE_APP_UA, "Accept": "*/*"},
        )
        body = self.uphone_biz_data(r)
        ticket = body.get("ticket") if body else None
        if not ticket:
            self.tlog(f"换 ticket 失败: {api_response_err(r, 'getTicketByNative')}")
            return False

        r = await self.req(
            "POST",
            f"{UPHONE_H5API}/token-service/getTokenByTicket",
            headers=self.uphone_app_headers({"Content-Type": "application/json"}),
            json={"channel": UPHONE_CHANNEL, "ticket": ticket},
        )
        body = self.uphone_biz_data(r)
        token = body.get("data") if body else None
        if not (
            body
            and self.uphone_biz_ok(body)
            and isinstance(token, str)
            and token.startswith("eyJ")
        ):
            self.tlog(f"换 cpToken 失败: {api_response_err(r, 'getTokenByTicket')}")
            return False
        self.uphone_cp_token = token
        self.tlog("云手机 SSO 成功")
        return True

    async def uphone_activity_login(self, activity_id):
        if not self.uphone_cp_token:
            return False
        r = await self.req(
            "POST",
            f"{UPHONE_H5API}/activity-service/user/login",
            headers=self.uphone_h5_headers(),
            json={
                "identityType": "cloudPhoneLogin",
                "code": self.uphone_cp_token,
                "channelId": UPHONE_CHANNEL_H5,
                "activityId": activity_id,
                "device": "device",
            },
        )
        body = self.uphone_biz_data(r)
        nested = body.get("data") if body else None
        tok = nested.get("user_token") if isinstance(nested, dict) else None
        if not (body and self.uphone_biz_ok(body) and tok):
            self.tlog(f"活动登录失败({activity_id}): {api_response_err(r, 'user/login')}")
            return False
        self.uphone_usr_token = str(tok)
        return True

    async def uphone_points_summary(self):
        r = await self.req(
            "GET",
            f"{UPHONE_H5API}/activity-service/points/v1/summary",
            headers=self.uphone_h5_headers(),
            params={"activityCode": UPHONE_ACT_EXCHANGE},
        )
        body = self.uphone_biz_data(r)
        if not body or not self.uphone_biz_ok(body):
            return None
        nested = body.get("data")
        return nested if isinstance(nested, dict) else None

    async def uphone_sign(self):
        # sign/history 的 signRecords[0] 是最近一次已签记录（通常为昨天），
        # 拿它判"今日已签"会隔天漏签；直接签到，把"已签"业务响应当正常态
        r = await self.req(
            "POST",
            f"{UPHONE_H5API}/activity-service/points/v1/sign",
            headers=self.uphone_h5_headers(),
            json={"activityCode": UPHONE_ACT_SIGN},
        )
        body = self.uphone_biz_data(r)
        if body and self.uphone_biz_ok(body):
            self.tlog(f"签到成功: {body.get('msg') or 'ok'}")
            return True
        msg = str((body or {}).get("msg") or "")
        if any(k in msg for k in ("已签", "签过", "重复")):
            self.tlog(f"今日已签到: {msg}")
            return True
        self.tlog(f"签到失败: {api_response_err(r, 'points/sign')}")
        return False

    async def uphone_task_list(self, activity_code):
        r = await self.req(
            "POST",
            f"{UPHONE_H5API}/activity-service/user/task/list",
            headers=self.uphone_h5_headers(),
            json={"activityCode": activity_code},
        )
        body = self.uphone_biz_data(r)
        if not body or not self.uphone_biz_ok(body):
            return [], 0
        task_list = body.get("taskList") or []
        if not isinstance(task_list, list):
            task_list = []
        return task_list, safe_int(body.get("rafflesLeftCount"), 0)

    async def uphone_task_logs(self, task_code, detail):
        r = await self.req(
            "POST",
            f"{UPHONE_H5API}/activity-service/user/task/logs",
            headers=self.uphone_h5_headers(),
            json={
                "logType": "01",
                "logCode": task_code,
                "logSource": "01",
                "logDetail": detail,
            },
        )
        body = self.uphone_biz_data(r)
        return self.uphone_biz_ok(body), body

    async def uphone_raffle_get(self, activity_code, task_code):
        r = await self.req(
            "POST",
            f"{UPHONE_H5API}/activity-service/user/task/raffle/get",
            headers=self.uphone_h5_headers(),
            json={"activityCode": activity_code, "taskCode": task_code},
        )
        body = self.uphone_biz_data(r)
        if isinstance(body, dict) and body.get("code") in (10301, "10301"):
            self.tlog(f"领奖受限 {task_code}: {body.get('msg')}")
            return False, body
        return self.uphone_biz_ok(body), body

    async def uphone_obtain_tasks(self):
        """积分任务：logs → 领奖（跳过需真实行为的任务）"""
        if not await self.uphone_activity_login(UPHONE_ACT_OBTAIN):
            return
        tasks, _ = await self.uphone_task_list(UPHONE_ACT_OBTAIN)
        claimed = logged = skipped = 0

        for t in tasks:
            if t.get("status") != "UNCLAIMED":
                continue
            code = str(t.get("taskCode") or "")
            ok, _ = await self.uphone_raffle_get(UPHONE_ACT_OBTAIN, code)
            if ok:
                claimed += 1
                self.tlog(f"领取积分任务 {code} {t.get('taskName')} +{t.get('pointsCount')}")
            await asyncio.sleep(0.25)

        tasks, _ = await self.uphone_task_list(UPHONE_ACT_OBTAIN)
        for t in tasks:
            code = str(t.get("taskCode") or "")
            name = str(t.get("taskName") or code)
            if t.get("status") != "INCOMPLETE":
                continue
            if code in UPHONE_OBTAIN_SKIP:
                skipped += 1
                continue
            ok, body = await self.uphone_task_logs(code, name)
            if not ok:
                self.tlog(f"任务上报失败 {code}: {(body or {}).get('msg')}")
                await asyncio.sleep(0.2)
                continue
            logged += 1
            await asyncio.sleep(0.3)
            tasks2, _ = await self.uphone_task_list(UPHONE_ACT_OBTAIN)
            t2 = next((x for x in tasks2 if x.get("taskCode") == code), None)
            if not t2 or t2.get("status") != "UNCLAIMED":
                self.tlog(f"任务未达可领 {code} status={t2.get('status') if t2 else '?'}")
                continue
            ok, _ = await self.uphone_raffle_get(UPHONE_ACT_OBTAIN, code)
            if ok:
                claimed += 1
                self.tlog(f"完成 {code} {name} +{t.get('pointsCount')}")
            await asyncio.sleep(0.25)

        summary = await self.uphone_points_summary()
        bal = (summary or {}).get("balanceScoreNum")
        self.tlog(
            f"积分任务结束 claimed={claimed} logged={logged} skipped={skipped} 余额={bal}"
        )

    async def uphone_lottery10_remain(self):
        r = await self.req(
            "GET",
            f"{UPHONE_H5API}/activity-service/points/v1/exchange/list",
            headers=self.uphone_h5_headers(),
            params={
                "activityCode": UPHONE_ACT_EXCHANGE,
                "token": self.uphone_cp_token,
            },
        )
        body = self.uphone_biz_data(r)
        if not body or not self.uphone_biz_ok(body):
            return -1
        goods = body.get("data") or []
        if not isinstance(goods, list):
            return -1
        for g in goods:
            if not isinstance(g, dict):
                continue
            if str(g.get("goodsId")) == UPHONE_GOODS_LOTTERY_10:
                ru = g.get("remainUser")
                return -1 if ru is None else safe_int(ru, 0)
        return 0

    async def uphone_lottery_10(self):
        """余额≥阈值且有剩余次数则十连抽"""
        await self.uphone_activity_login(UPHONE_ACT_SIGN)
        summary = await self.uphone_points_summary()
        balance = safe_int((summary or {}).get("balanceScoreNum"), 0)
        if balance < UPHONE_LOTTERY_COST:
            self.tlog(f"积分不足十连 余额={balance} 需≥{UPHONE_LOTTERY_COST}")
            return
        remain = await self.uphone_lottery10_remain()
        if remain == 0:
            self.tlog("十连次数已用完 remainUser=0")
            return
        r = await self.req(
            "POST",
            f"{UPHONE_H5API}/activity-service/points/v1/lottery",
            headers=self.uphone_h5_headers(),
            json={
                "activityCode": UPHONE_ACT_EXCHANGE,
                "goodsId": UPHONE_GOODS_LOTTERY_10,
            },
        )
        body = self.uphone_biz_data(r)
        if not body or not self.uphone_biz_ok(body):
            self.tlog(f"十连失败: {api_response_err(r, 'points/lottery')}")
            return
        raw_data = body.get("data")
        data = raw_data if isinstance(raw_data, dict) else {}
        raw_sm = data.get("summary")
        sm = raw_sm if isinstance(raw_sm, dict) else {}
        raw_results = data.get("results")
        results = raw_results if isinstance(raw_results, list) else []
        prizes = [
            x.get("prizeName")
            for x in results
            if isinstance(x, dict) and x.get("isDrawn")
        ]
        prize_text = ",".join(str(p) for p in prizes if p) if prizes else "无"
        self.tlog(
            f"十连完成 total={sm.get('total')} won={sm.get('won')} 奖品={prize_text}"
        )
        summary = await self.uphone_points_summary()
        self.tlog(f"十连后余额={(summary or {}).get('balanceScoreNum')}")

    async def uphone_summer_claim_one(self):
        """夏日刮一刮：仅领 2508-01（去赚积分）换 1 次次数；无此可领任务则跳过。"""
        if not await self.uphone_activity_login(UPHONE_ACT_SUMMER):
            return 0
        tasks, left = await self.uphone_task_list(UPHONE_ACT_SUMMER)
        pick = next(
            (
                t
                for t in tasks
                if str(t.get("taskCode") or "") == UPHONE_SUMMER_CLAIM_TASK
                and t.get("status") == "UNCLAIMED"
            ),
            None,
        )
        if not pick:
            self.tlog(
                f"夏日 {UPHONE_SUMMER_CLAIM_TASK} 无可领 "
                f"rafflesLeft={left}（已领过或未达条件，跳过）"
            )
            return left

        code = UPHONE_SUMMER_CLAIM_TASK
        name = pick.get("taskName") or code
        ok, body = await self.uphone_raffle_get(UPHONE_ACT_SUMMER, code)
        if ok:
            self.tlog(f"夏日领次数成功 {code} {name}")
        else:
            msg = (body or {}).get("msg") if isinstance(body, dict) else body
            biz = (body or {}).get("code") if isinstance(body, dict) else None
            if biz in (10301, "10301"):
                self.tlog(f"夏日领次数跳过(日限) {code}: {msg}")
            else:
                self.tlog(f"夏日领次数失败 {code}: {msg or body}")
        _, left2 = await self.uphone_task_list(UPHONE_ACT_SUMMER)
        self.tlog(f"夏日抽奖次数 rafflesLeft={left}→{left2}")
        return left2

    async def uphone_summer_lottery(self, max_draws=20):
        draws = 0
        while draws < max_draws:
            _, left = await self.uphone_task_list(UPHONE_ACT_SUMMER)
            if left <= 0:
                break
            r = await self.req(
                "POST",
                f"{UPHONE_H5API}/activity-service/lottery",
                headers=self.uphone_h5_headers(),
                json={"activityCode": UPHONE_ACT_SUMMER},
            )
            body = self.uphone_biz_data(r)
            if not body or not self.uphone_biz_ok(body):
                self.tlog(f"夏日抽奖失败: {api_response_err(r, 'lottery')}")
                break
            draws += 1
            self.tlog(
                f"夏日抽奖#{draws} {body.get('prizeName') or body.get('msg')} "
                f"type={body.get('prizeType')}"
            )
            await asyncio.sleep(0.4)
        if draws == 0:
            self.tlog("夏日无抽奖次数")
        else:
            self.tlog(f"夏日抽奖结束 draws={draws}")
        return draws

    async def uphone_checkin_query(self):
        """查询打卡挑战赛状态。"""
        body = await self.uphone_checkin_post("activity/querySignInList")
        if not body:
            self.tlog("打卡查询无响应")
            return None
        if str(body.get("code")) == "50020":
            self.tlog("打卡 token 失效(50020)")
            return None
        if not self.uphone_biz_ok(body):
            self.tlog(f"打卡查询失败: {body.get('msg') or body}")
            return None
        return body

    async def uphone_checkin_raffle(self, order_id, account="", account_type=""):
        """打卡奖品核销 raffleSignIn（字段 activityOrderid 小写 id）。"""
        if not order_id:
            return False
        body = await self.uphone_checkin_post(
            "activity/raffleSignIn",
            {
                "activityOrderid": order_id,
                "account": account or "",
                "accountType": account_type or "",
            },
        )
        if body and self.uphone_biz_ok(body):
            redir = body.get("redirectUrl") or ""
            self.tlog(
                f"打卡领奖成功 order={order_id}"
                + (f" redirect={redir[:80]}" if redir else "")
            )
            return True
        self.tlog(
            f"打卡领奖失败 order={order_id}: "
            f"{(body or {}).get('msg') if isinstance(body, dict) else body}"
        )
        return False

    async def uphone_checkin_handle_prize(self, body, source="签到"):
        """处理签到/奖品中的 activityOrderId；type=2 需 QQ/微信则跳过。"""
        if not isinstance(body, dict):
            return
        order_id = body.get("activityOrderId") or body.get("activityOrderid")
        if not order_id:
            return
        act_type = body.get("activityType")
        name = body.get("activityName") or body.get("name") or ""
        if act_type in UPHONE_CHECKIN_SKIP_ACTIVITY_TYPES:
            self.tlog(
                f"打卡奖品需手填账号，跳过({source}) type={act_type} "
                f"{name} order={order_id}"
            )
            return
        self.tlog(f"打卡中奖({source}) {name or order_id} type={act_type}")
        await self.uphone_checkin_raffle(order_id)
        await asyncio.sleep(0.3)

    async def uphone_checkin_claim_pending(self):
        """我的奖品：自动领取可核销订单（跳过 type=2）。"""
        body = await self.uphone_checkin_post("activity/signInRightList")
        if not body or not self.uphone_biz_ok(body):
            if body:
                self.tlog(f"打卡奖品列表失败: {body.get('msg') or body}")
            return
        goods = body.get("goodsList") or []
        if not isinstance(goods, list) or not goods:
            self.tlog("打卡奖品列表为空")
            return
        claimed = 0
        for g in goods:
            if not isinstance(g, dict):
                continue
            state = g.get("state")
            # 前端 award：state 1/2 可点；2 多为已发，失败则跳过
            if state not in (1, 2, "1", "2"):
                continue
            act_type = g.get("activityType")
            order_id = g.get("activityOrderId") or g.get("activityOrderid")
            name = g.get("name") or ""
            if not order_id:
                continue
            if act_type in UPHONE_CHECKIN_SKIP_ACTIVITY_TYPES:
                self.tlog(f"打卡待领跳过(需账号) {name} type={act_type}")
                continue
            # state=2 历史已领过的不重复核销，仅补 state=1
            if state not in (1, "1"):
                continue
            self.tlog(f"打卡补领 {name} order={order_id}")
            if await self.uphone_checkin_raffle(order_id):
                claimed += 1
            await asyncio.sleep(0.3)
        self.tlog(f"打卡奖品补领结束 claimed={claimed} total={len(goods)}")

    async def uphone_checkin(self):
        """打卡挑战赛 CLD13：query → signIn → 条件 raffle → 奖品补领。

        复用 uphone_sso_login 的 cpToken，无需 activity-service 登录。
        """
        if not self.uphone_cp_token:
            self.tlog("打卡跳过: 无 cpToken")
            return

        info = await self.uphone_checkin_query()
        if info is None:
            return
        day = info.get("signDayNum")
        left = info.get("surpriseDayNum")
        self.tlog(f"打卡状态 已签{day}天 再签{left}天有惊喜")
        if info.get("refreshFlag") == "refresh":
            self.tlog("打卡完成一轮，开启新周期")

        body = await self.uphone_checkin_post("activity/signIn")
        if not body:
            self.tlog("打卡签到无响应")
            return
        code = str(body.get("code", ""))
        msg = body.get("msg") or ""
        if code == "30038":
            self.tlog(f"打卡今日已签: {msg or '今日已签过'}")
        elif self.uphone_biz_ok(body):
            self.tlog(f"打卡成功: {msg or 'ok'}")
            await self.uphone_checkin_handle_prize(body, source="签到")
            await asyncio.sleep(0.3)
            info2 = await self.uphone_checkin_query()
            if info2:
                self.tlog(
                    f"打卡后 已签{info2.get('signDayNum')}天 "
                    f"再签{info2.get('surpriseDayNum')}天有惊喜"
                )
        else:
            self.tlog(f"打卡失败[{code}]: {msg or body}")

        await self.uphone_checkin_claim_pending()

    async def uphone_task(self):
        """云手机：SSO → 打卡挑战赛 → 积分签到/任务/十连 → 夏日刮一刮"""
        self._task_tag = "云手机积分"
        self.tlog("开始")
        if not await self.uphone_sso_login():
            return

        # 打卡挑战赛仅需 cpToken
        await self.uphone_checkin()

        if not await self.uphone_activity_login(UPHONE_ACT_SIGN):
            return

        await self.uphone_sign()
        await self.uphone_obtain_tasks()
        await self.uphone_lottery_10()
        await self.uphone_summer_claim_one()
        await self.uphone_summer_lottery()
        self.tlog("结束")

    # === 主任务 ===
    async def run(self):
        try:
            if not await self.login():
                return
            only = os.environ.get("UNICOM_ONLY_TASK", "").strip()
            task_map = {
                "market": self.market_task,
                "sign": self.sign_task,
                "xj": self.xj_task,
                "ttlxj": self.ttlxj_task,
                "ltzf": self.ltzf_task,
                "sec": self.sec_task,
                "farm": self.farm_task,
                "cloud_battle": self.cloud_battle_task,
                "shangdu": self.shangdu_task,
                "uphone": self.uphone_task,
            }
            if only:
                names = [n.strip() for n in only.split(",") if n.strip()]
                tasks = [task_map[n] for n in names if n in task_map]
                if not tasks:
                    self.log(f"UNICOM_ONLY_TASK={only!r} 无匹配任务，可选: {list(task_map)}")
                    return
            else:
                tasks = [
                    self.market_task,
                    self.sign_task,
                    self.xj_task,
                    self.ttlxj_task,
                    self.ltzf_task,
                    self.sec_task,
                    self.farm_task,
                    self.cloud_battle_task,
                    self.shangdu_task,
                    self.uphone_task,
                ]
            # 服务端长期不可用的模块（如 wocare 接口整体 5xx）可用环境变量停掉，
            # 避免每次运行都产生注定失败的异常并淹没推送
            skip = {
                n.strip()
                for n in os.environ.get("UNICOM_SKIP_TASK", "").split(",")
                if n.strip()
            }
            if skip:
                skipped = [n for n in skip if n in task_map]
                tasks = [t for t in tasks if t not in {task_map[n] for n in skipped}]
                if skipped:
                    self.log(f"已按 UNICOM_SKIP_TASK 跳过: {','.join(sorted(skipped))}")
            for task in tasks:
                try:
                    await task()
                except Exception as e:
                    self.tlog_exc(e, task.__name__)
        finally:
            await self.close()


async def main():
    # 10点开抢/日期比对/周日判断都依赖本地时区，容器 TZ 为空时显式钉死
    os.environ.setdefault("TZ", "Asia/Shanghai")
    if hasattr(time, "tzset"):
        time.tzset()
    print(f"开始: {datetime.now():%Y-%m-%d %H:%M:%S} TZ={os.environ.get('TZ')}")
    cookies = os.environ.get("chinaUnicomCookie", "")
    if not cookies:
        print("未找到环境变量 chinaUnicomCookie")
        return

    tasks = [
        Unicom(c, i + 1).run() for i, c in enumerate(cookies.split("@")) if c.strip()
    ]
    print(f"启动 {len(tasks)} 个账号")
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            print(f"账号{i + 1} 未捕获异常: {result}", flush=True)
    push_lines = [
        l
        for l in NOTIFY_LINES
        if any(k in l for k in ("失败", "异常", "成功", "抽奖"))
    ]
    if push_lines:
        notify_send("中国联通任务", "\n".join(push_lines))
    print("结束")


if __name__ == "__main__":
    asyncio.run(main())
