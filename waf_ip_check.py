# -*- coding: utf-8 -*-
"""腾讯云黑名单一键下发。

流程：填 IP → 点下发
  1) DescribeDuplicateIP 探测，RemovedIPList = 已封过，跳过
  2) 未封 IP 同时写入：
     - 云防火墙 CreateBlockIgnoreRuleNew：Rules[].Ioc + Comment
     - WAF 黑名单 CreateIpAccessControl：IpList + Note
     Comment 和 Note 同一串：姓名+年月日时分，例如 Operator202609180921
  3) 本次封成功的 IP 追加到 当天 MMDD-black.txt，例如 0918-black.txt
"""
from __future__ import print_function

import base64
import json
import os
import random
import re
import string
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import Canvas, PhotoImage, messagebox, ttk

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False
    import requests

if getattr(sys, "frozen", False):
    SCRIPT_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PACKET_FILE = os.path.join(SCRIPT_DIR, "packet.txt")
SESSION_FILE = os.path.join(SCRIPT_DIR, "waf_ip_check_session.json")
ERROR_LOG = os.path.join(SCRIPT_DIR, "blacklist_error.log")
SLOGANS = [
    "所谓的大佬，一辈子都以为自己是小白",
    "会得越多，越知道自己不会",
    "装大佬的人在秀，当小白的人在涨",
    "没有永恒的大佬，只有还在学的人",
    "今天能打穿，明天仍从零开始",
    "得意时当小白，翻车时才懂敬畏",
]
SLOGAN_GAP = "          ◆          "


def asset_path(*names):
    bases = [os.path.join(SCRIPT_DIR, "assets")]
    meipass = getattr(sys, "_MEIPASS", "")
    if meipass:
        bases.insert(0, os.path.join(meipass, "assets"))
    for base in bases:
        p = os.path.join(base, *names)
        if os.path.isfile(p):
            return p
    return os.path.join(bases[-1], *names)


def ensure_assets():
    try:
        from linshen_assets import ICO, PNG32
    except ImportError:
        return
    folder = os.path.join(SCRIPT_DIR, "assets")
    try:
        os.makedirs(folder, exist_ok=True)
    except Exception:
        return
    mapping = (("linshen.ico", ICO), ("linshen32.png", PNG32))
    for name, blob in mapping:
        path = os.path.join(folder, name)
        if os.path.isfile(path) and os.path.getsize(path) > 100:
            continue
        try:
            with open(path, "wb") as f:
                f.write(base64.b64decode(blob))
        except Exception:
            pass


def _log_crash(text):
    try:
        with open(ERROR_LOG, "a", encoding="utf-8") as f:
            f.write(text)
            if not text.endswith("\n"):
                f.write("\n")
    except Exception:
        pass


def _excepthook(typ, val, tb):
    import traceback
    _log_crash("".join(traceback.format_exception(typ, val, tb)))
    sys.__excepthook__(typ, val, tb)


sys.excepthook = _excepthook

DEFAULT_IPS = ""
DEFAULT_UIN = ""
DEFAULT_OWNER_UIN = ""
DEFAULT_CSRF = ""
DEFAULT_NAME = ""
DEFAULT_COOKIE = ""

API_HOST = "console.cloud.tencent.com"
API_PATH = "/cgi/capi"
WAF_REFERER = "https://console.cloud.tencent.com/guanjia/tea-iplist"
CFW_REFERER = "https://console.cloud.tencent.com/cfw/ips"

HW_HOST = "console.huaweicloud.com"
DEFAULT_HW_REGION = "cn-south-1"
DEFAULT_HW_PROJECT = ""
DEFAULT_HW_OBJECT_ID = ""
DEFAULT_HW_FW_INSTANCE = ""
DEFAULT_HW_EPS = ""
DEFAULT_HW_CFTK = ""
DEFAULT_HW_COOKIE = ""


def rand_lid(n=10):
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(n))


def strip_cookie_header(raw):
    text = (raw or "").strip()
    if text.lower().startswith("cookie:"):
        text = text.split(":", 1)[1].strip()
    return text


def cookie_map(cookie):
    kv = {}
    for part in strip_cookie_header(cookie).split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        kv[k.strip()] = v.strip()
    return kv


def csrf_from_skey(skey):
    """腾讯云控制台 csrfCode = gtk(skey)，skey 一换 csrf 必须重算。"""
    if not skey:
        return ""
    h = 5381
    for ch in skey:
        h += (h << 5) + ord(ch)
    return str(h & 0x7FFFFFFF)


def digits_id(value):
    return "".join(ch for ch in (value or "") if ch.isdigit())


def cftk_from_cookie(cookie):
    found = ""
    for part in strip_cookie_header(cookie).split(";"):
        part = part.strip()
        low = part.lower()
        if low.startswith("cftk=") or low.startswith("console_cftk="):
            found = part.split("=", 1)[1].strip().strip('"')
    return found


def hw_identity(cookie):
    """从 Cookie 抽当前登录身份。agency / region 随账号变，不写死。"""
    kv = cookie_map(cookie)
    agency = (kv.get("agencyID") or kv.get("agencyId") or kv.get("_w3Fid") or "").strip().strip('"')
    jsid = (kv.get("J_SESSION_ID") or "").strip()
    js_region = (kv.get("J_SESSION_REGION") or "").strip()
    regions = []
    for key, val in kv.items():
        if key.endswith("_cfProjectName") and (val or "").startswith("cn-") and val not in regions:
            regions.append(val)
    if DEFAULT_HW_REGION not in regions:
        regions.append(DEFAULT_HW_REGION)
    if js_region.startswith("cn-") and js_region not in regions:
        regions.append(js_region)
    return {
        "agency": agency,
        "cftk": cftk_from_cookie(cookie),
        "jsession": jsid,
        "regions": regions,
        "js_region": js_region,
        "user": (kv.get("masked_user") or "").strip(),
    }


def hw_sets_ok(status, body):
    return status == 200 and isinstance(body, dict) and "data" in body


def parse_ips(text):
    raw = text.replace(",", " ").replace(";", " ").replace("\r", "\n")
    ips = []
    seen = set()
    for line in raw.splitlines():
        for part in line.split():
            ip = part.strip().strip("\"'")
            if ip and not ip.startswith("#") and ip not in seen:
                seen.add(ip)
                ips.append(ip)
    return ips


def make_comment(name, now=None):
    """姓名 + 年月日 + 当下时分，例如 Operator202609180921。Comment 和 Note 共用。"""
    name = (name or "").strip() or DEFAULT_NAME or "Operator"
    now = now or datetime.now()
    return name + now.strftime("%Y%m%d%H%M")


def _http_get(url, params=None, timeout=8, decode=None):
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0"}
    if HAS_HTTPX:
        with httpx.Client(timeout=timeout, follow_redirects=True, proxy=None) as client:
            r = client.get(url, params=params, headers=headers)
            raw = r.content
    else:
        r = requests.get(
            url, params=params, headers=headers, timeout=timeout,
            proxies={"http": None, "https": None},
        )
        raw = r.content
    if decode:
        return raw.decode(decode, errors="ignore")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("gbk", errors="ignore")


def _join_geo(parts):
    out = []
    for p in parts:
        p = (p or "").strip()
        if not p or p in ("None", "未知", "内网IP", "-"):
            continue
        if p.endswith("省") or p.endswith("市") or p.endswith("区") or p.endswith("县"):
            pass
        dup = False
        for i, old in enumerate(out):
            if p == old or p in old or old in p:
                if len(p) > len(old):
                    out[i] = p
                dup = True
                break
        if not dup:
            out.append(p)
    return "".join(out)


def lookup_geo(ip):
    """网上查归属地。主用太平洋 whois.pconline.com.cn，失败再试 ip.useragentinfo.com。"""
    try:
        text = _http_get(
            "https://whois.pconline.com.cn/ipJson.jsp",
            params={"ip": ip, "json": "true"},
            decode="gbk",
        )
        data = json.loads(text.strip())
        geo = _join_geo([data.get("pro"), data.get("city")])
        if not geo:
            addr = (data.get("addr") or "").strip()
            geo = addr.split()[0] if addr else ""
        if geo:
            return geo
    except Exception:
        pass
    try:
        text = _http_get("https://ip.useragentinfo.com/json", params={"ip": ip})
        data = json.loads(text.strip())
        geo = _join_geo([
            data.get("country") if data.get("country") not in ("中国", "CN") else "",
            data.get("province"),
            data.get("city"),
        ])
        if geo:
            return geo
    except Exception:
        pass
    return "未知"


def ban_success_line(geo, ip):
    return "%s %s 存在攻击行为请求封禁（腾讯云已封）" % (geo or "未知", ip)


def vendor_from_name(name):
    """对象组 name → 供应商，例如 云快充封堵-008 → 云快充。"""
    s = (name or "").strip()
    if not s:
        return ""
    s = re.sub(u"封堵|封禁IP|封禁", "", s)
    parts = []
    for p in s.split("-"):
        p = p.strip()
        if not p:
            continue
        if re.match(r"^20\d{2,4}$", p) or re.match(r"^\d+$", p) or re.match(r"(?i)^HW$", p):
            continue
        p = re.sub(u"防护$", "", p)
        if p:
            parts.append(p)
    if not parts:
        return name
    if parts[0] == u"护网" and len(parts) > 1:
        return parts[0] + "-" + parts[1]
    return parts[0]


def parse_hw_records(body):
    records = []
    if isinstance(body, dict):
        data = body.get("data") or {}
        records = data.get("records") or []
    names = []
    vendors = []
    seen = set()
    for rec in records:
        n = (rec.get("name") or "").strip()
        if not n:
            continue
        names.append(n)
        v = vendor_from_name(n)
        if v and v not in seen:
            seen.add(v)
            vendors.append(v)
    return names, vendors


def _query_hw_sets_once(ip, cookie, cftk, agency, region, project, object_id, fw_instance, eps):
    url = "https://%s/cfw/v1/%s/address-sets" % (HW_HOST, project)
    params = {
        "object_id": object_id,
        "limit": "50",
        "offset": "0",
        "query_address_set_type": "0",
        "address": ip,
    }
    headers = {
        "Host": HW_HOST,
        "Cookie": cookie.strip(),
        "X-Cf2-Target-Url": "cfw=/v1/%s/address-sets" % project,
        "X-Cf2-Dynamic-Index": "true",
        "Cftk": cftk.strip(),
        "Cf2-Cftk": "",
        "Agencyid": agency,
        "X-Language": "zh-cn",
        "Projectname": region,
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/json, text/plain, */*",
        "Region": region,
        "Referer": (
            "https://console.huaweicloud.com/cfw/?locale=zh-cn"
            "&agencyId=%s&region=%s&fwInstanceId=%s&enterpriseProjectId=%s"
            % (agency, region, fw_instance, eps)
        ),
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
    }
    if HAS_HTTPX:
        with httpx.Client(http2=True, timeout=30.0, follow_redirects=False, proxy=None) as client:
            r = client.get(url, params=params, headers=headers)
            http_ver = r.http_version
            text = r.text
            status = r.status_code
    else:
        r = requests.get(
            url, params=params, headers=headers, timeout=30,
            proxies={"http": None, "https": None},
        )
        http_ver = "HTTP/1.1"
        text = r.text
        status = r.status_code
    try:
        body = json.loads(text)
    except ValueError:
        body = {"_raw": text}
    if isinstance(body, dict):
        body["_used_agency"] = agency
        body["_used_region"] = region
    return status, http_ver, body, text


def query_hw_sets(ip, cookie, cftk=None, agency=None, region=None, project=None, object_id=None, fw_instance=None, eps=None):
    ident = hw_identity(cookie)
    cftk = (cftk or ident["cftk"] or "").strip()
    agency = (agency or ident["agency"] or "").strip()
    project = (project or "").strip()
    object_id = (object_id or "").strip()
    fw_instance = (fw_instance or "").strip()
    eps = (eps or "").strip()
    regions = [region] if region else list(ident["regions"] or [DEFAULT_HW_REGION])
    last = (0, "", {}, "")
    for reg in regions:
        last = _query_hw_sets_once(ip, cookie, cftk, agency, reg, project, object_id, fw_instance, eps)
        status, _ver, body, _text = last
        if hw_sets_ok(status, body):
            return last
        err = body.get("error_code") if isinstance(body, dict) else ""
        if err == "CFW.00200005":
            continue
        break
    return last


def black_txt_path(now=None):
    now = now or datetime.now()
    return os.path.join(SCRIPT_DIR, now.strftime("%m%d") + "-black.txt")


def append_black_file(ip_list, note, now=None):
    """封成功的 IP 追加到 0918-black.txt，同日已有的不重复写。"""
    now = now or datetime.now()
    path = black_txt_path(now)
    existing = set()
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    existing.add(line)
    new_ips = [ip for ip in ip_list if ip not in existing]
    if not new_ips:
        return path, 0
    with open(path, "a", encoding="utf-8") as f:
        f.write("# %s  Note=%s\n" % (now.strftime("%Y-%m-%d %H:%M:%S"), note))
        for ip in new_ips:
            f.write(ip + "\n")
    return path, len(new_ips)


def build_cfw_payload(ip_list, comment):
    rules = []
    for ip in ip_list:
        rules.append({
            "Ioc": ip,
            "DirectionList": "1,0",
            "EndTime": "3000-01-01 00:00:00",
            "Comment": comment,
            "CustomRule": {},
        })
    return {
        "regionId": 1,
        "serviceType": "cfw",
        "cmd": "CreateBlockIgnoreRuleNew",
        "data": {
            "Version": "2019-09-04",
            "Rules": rules,
            "RuleType": 1,
            "CoverDuplicate": 0,
        },
    }


def build_waf_payload(ip_list, note):
    return {
        "regionId": 1,
        "serviceType": "waf",
        "cmd": "CreateIpAccessControl",
        "data": {
            "Version": "2018-01-25",
            "Domain": "global",
            "ActionType": 42,
            "InstanceId": "",
            "Edition": "",
            "Note": note,
            "IpList": list(ip_list),
            "SourceType": "custom",
            "ValidTS": 0,
            "JobType": "TimedJob",
            "JobDateTime": {
                "Timed": [{"StartDateTime": 0, "EndDateTime": 0}],
                "TimeTZone": "UTC+8",
            },
        },
    }


def parse_packet_file(path):
    out = {}
    if not path or not os.path.isfile(path):
        return out
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    for line in content.splitlines():
        if line.lower().startswith("cookie:"):
            out["cookie"] = line.split(":", 1)[1].strip()
            break
    first = content.splitlines()[0] if content.splitlines() else ""
    for key in ("csrfCode", "uin", "ownerUin"):
        marker = key + "="
        if marker in first:
            val = first.split(marker, 1)[1].split("&", 1)[0].split(" ", 1)[0]
            out[key] = val
    return out


def load_session():
    data = {
        "ips": DEFAULT_IPS,
        "cookie": DEFAULT_COOKIE,
        "csrf": DEFAULT_CSRF,
        "uin": DEFAULT_UIN,
        "owner_uin": DEFAULT_OWNER_UIN,
        "name": DEFAULT_NAME,
        "hw_cookie": DEFAULT_HW_COOKIE,
        "hw_cftk": DEFAULT_HW_CFTK,
        "hw_project": DEFAULT_HW_PROJECT,
        "hw_object_id": DEFAULT_HW_OBJECT_ID,
        "hw_fw_instance": DEFAULT_HW_FW_INSTANCE,
        "hw_eps": DEFAULT_HW_EPS,
    }
    pkt = parse_packet_file(PACKET_FILE)
    if pkt.get("cookie"):
        data["cookie"] = pkt["cookie"]
    if pkt.get("csrfCode"):
        data["csrf"] = pkt["csrfCode"]
    if pkt.get("uin"):
        data["uin"] = pkt["uin"]
    if pkt.get("ownerUin"):
        data["owner_uin"] = pkt["ownerUin"]
    if os.path.isfile(SESSION_FILE):
        try:
            with open(SESSION_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
            for k in data:
                if saved.get(k):
                    data[k] = saved[k]
        except Exception:
            pass
    data["cookie"] = strip_cookie_header(data.get("cookie") or "")
    data["hw_cookie"] = strip_cookie_header(data.get("hw_cookie") or "")
    kv = cookie_map(data["cookie"])
    csrf = csrf_from_skey(kv.get("skey") or "")
    if csrf:
        data["csrf"] = csrf
    uin = digits_id(kv.get("uin") or "")
    if uin:
        data["uin"] = uin
    owner = digits_id(kv.get("ownerUin") or "")
    if owner:
        data["owner_uin"] = owner
    cftk = cftk_from_cookie(data["hw_cookie"])
    if cftk:
        data["hw_cftk"] = cftk
    return data


def save_session(data):
    try:
        with open(SESSION_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def extract_response_lists(body):
    removed = []
    duplicate = []
    node = body
    for _ in range(6):
        if not isinstance(node, dict):
            break
        resp = node.get("Response")
        if isinstance(resp, dict) and ("RemovedIPList" in resp or "DuplicateIPList" in resp):
            removed = resp.get("RemovedIPList") or []
            duplicate = resp.get("DuplicateIPList") or []
            return list(removed), list(duplicate)
        if "RemovedIPList" in node or "DuplicateIPList" in node:
            removed = node.get("RemovedIPList") or []
            duplicate = node.get("DuplicateIPList") or []
            return list(removed), list(duplicate)
        node = node.get("data", node)
    return removed, duplicate


def classify_ips(ip_list, removed, duplicate):
    removed_set = set(removed)
    duplicate_set = set(duplicate)
    rows = []
    for ip in ip_list:
        if ip in removed_set:
            status = "已封过"
            note = "RemovedIPList，跳过不下发"
        elif ip in duplicate_set:
            status = "名单重复"
            note = "DuplicateIPList，跳过不下发"
        else:
            status = "未封"
            note = "将写入 Ioc / IpList 下发"
        rows.append({"ip": ip, "status": status, "note": note})
    return rows


def biz_ok(status, body):
    if status != 200 or not isinstance(body, dict):
        return False
    if body.get("code") not in (0, None):
        return False
    inner = body.get("data")
    if isinstance(inner, dict) and inner.get("code") not in (0, None):
        return False
    return True


def console_post(cmd, service_type, dict_id, referer, payload, cookie, csrf, uin, owner_uin):
    ts = int(time.time() * 1000)
    params = {
        "cmd": cmd,
        "action": "delegate",
        "serviceType": service_type,
        "secure": "1",
        "version": "3",
        "json": "1",
        "dictId": str(dict_id),
        "withLanguage": "1",
        "sts": "1",
        "t": str(ts),
        "uin": uin.strip(),
        "ownerUin": owner_uin.strip(),
        "csrfCode": csrf.strip(),
    }
    headers = {
        "Host": API_HOST,
        "Cookie": cookie.strip(),
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Content-Type": "application/json",
        "Origin": "https://console.cloud.tencent.com",
        "Referer": referer,
        "X-Requested-With": "XMLHttpRequest",
        "X-Lid": rand_lid(),
        "X-Life": str(random.randint(100000, 9999999)),
    }
    url = "https://%s%s" % (API_HOST, API_PATH)
    if HAS_HTTPX:
        with httpx.Client(http2=True, timeout=30.0, follow_redirects=False, proxy=None) as client:
            r = client.post(url, params=params, json=payload, headers=headers)
            http_ver = r.http_version
            text = r.text
            status = r.status_code
    else:
        r = requests.post(
            url, params=params, json=payload, headers=headers, timeout=30,
            proxies={"http": None, "https": None},
        )
        http_ver = "HTTP/1.1"
        text = r.text
        status = r.status_code
    try:
        body = json.loads(text)
    except ValueError:
        body = {"_raw": text}
    return status, http_ver, body, text


def probe(ip_list, cookie, csrf, uin, owner_uin):
    payload = {
        "regionId": 1,
        "serviceType": "waf",
        "cmd": "DescribeDuplicateIP",
        "data": {
            "Version": "2018-01-25",
            "IPList": ip_list,
            "ActionType": 42,
            "Domain": "global",
        },
    }
    return console_post(
        "DescribeDuplicateIP", "waf", 2123, WAF_REFERER,
        payload, cookie, csrf, uin, owner_uin,
    )


def create_cfw(ip_list, comment, cookie, csrf, uin, owner_uin):
    return console_post(
        "CreateBlockIgnoreRuleNew", "cfw", 2402, CFW_REFERER,
        build_cfw_payload(ip_list, comment), cookie, csrf, uin, owner_uin,
    )


def create_waf(ip_list, note, cookie, csrf, uin, owner_uin):
    return console_post(
        "CreateIpAccessControl", "waf", 2123, WAF_REFERER,
        build_waf_payload(ip_list, note), cookie, csrf, uin, owner_uin,
    )


def dump_json(body, raw):
    if isinstance(body, dict):
        return json.dumps(body, ensure_ascii=False, indent=2)
    return raw or ""


BG = "#f6f5f2"
SURFACE = "#efeee9"
CARD = "#ffffff"
LINE = "#e4e0d6"
TEXT = "#1c1b19"
MUTED = "#8a8680"
GOLD = "#1c1b19"
GOLD_DIM = "#9a958c"
INK = "#ffffff"


class App(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self.title("BLACKLIST")
        self.geometry("1080x920")
        self.minsize(920, 760)
        self._busy = False
        self._tx_ready = False
        self._hw_ready = False
        self._icon_photo = None
        self._brand_icon = None
        self.slogan_cv = None
        self._slogan_id = None
        self._slogan_x = 0
        sess = load_session()
        ensure_assets()
        self._set_icon()
        self._build(sess)
        self._tick_comment()

    def _apply_theme(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", background=BG, foreground=TEXT, fieldbackground=CARD, bordercolor=LINE, troughcolor=BG)
        style.configure("TFrame", background=BG)
        style.configure("Card.TFrame", background=CARD)
        style.configure("TLabel", background=BG, foreground=TEXT, font=("Microsoft YaHei UI", 9))
        style.configure("Muted.TLabel", background=BG, foreground=MUTED, font=("Microsoft YaHei UI", 9))
        style.configure("Gold.TLabel", background=BG, foreground=GOLD, font=("Consolas", 10))
        style.configure("Card.TLabel", background=CARD, foreground=MUTED, font=("Microsoft YaHei UI", 9))
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=SURFACE, foreground=MUTED, padding=[22, 9], font=("Microsoft YaHei UI", 10))
        style.map("TNotebook.Tab", background=[("selected", CARD)], foreground=[("selected", TEXT)])
        style.configure("Cfg.TNotebook", background=BG, borderwidth=0)
        style.configure("Cfg.TNotebook.Tab", background=SURFACE, foreground=MUTED, padding=[28, 10], font=("Microsoft YaHei UI", 11))
        style.map("Cfg.TNotebook.Tab", background=[("selected", CARD)], foreground=[("selected", TEXT)])
        style.configure(
            "Treeview",
            background=CARD, fieldbackground=CARD, foreground=TEXT,
            rowheight=30, font=("Consolas", 10), borderwidth=0, relief="flat",
        )
        style.configure(
            "Treeview.Heading",
            background=SURFACE, foreground=MUTED, font=("Microsoft YaHei UI", 9),
            relief="flat", borderwidth=0,
        )
        style.map("Treeview", background=[("selected", "#ebe8e1")], foreground=[("selected", TEXT)])
        style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        style.configure(
            "TEntry",
            fieldbackground=CARD, foreground=TEXT, insertcolor=TEXT,
            bordercolor=LINE, lightcolor=LINE, darkcolor=LINE, padding=6,
        )
        style.configure("Ghost.TButton", background=SURFACE, foreground=MUTED, bordercolor=LINE, padding=7, font=("Microsoft YaHei UI", 9))
        style.map("Ghost.TButton", background=[("active", CARD)], foreground=[("active", TEXT)])

    def _text(self, parent, height, font, **kw):
        opts = dict(
            bg=CARD, fg=TEXT, insertbackground=TEXT, relief="flat",
            highlightthickness=1, highlightbackground=LINE, highlightcolor=TEXT,
            wrap=tk.WORD, undo=True, borderwidth=0, padx=10, pady=8,
        )
        opts.update(kw)
        return tk.Text(parent, height=height, font=font, **opts)

    def _flat_btn(self, parent, text, cmd, primary=True):
        if primary:
            return tk.Button(
                parent, text=text, command=cmd,
                bg=TEXT, fg=INK, activebackground="#333230", activeforeground=INK,
                relief="flat", bd=0, cursor="hand2",
                font=("Microsoft YaHei UI", 10, "bold"), padx=18, pady=6,
            )
        return tk.Button(
            parent, text=text, command=cmd,
            bg=CARD, fg=TEXT, activebackground=SURFACE, activeforeground=TEXT,
            relief="solid", bd=1, cursor="hand2",
            font=("Microsoft YaHei UI", 10), padx=14, pady=5,
        )

    def _set_icon(self):
        ico = asset_path("linshen.ico")
        png = asset_path("linshen32.png")
        if os.path.isfile(ico):
            try:
                self.iconbitmap(ico)
            except Exception:
                pass
        if os.path.isfile(png):
            try:
                self._icon_photo = PhotoImage(file=png)
                self.iconphoto(True, self._icon_photo)
            except Exception:
                pass

    def _build_brand(self):
        brand = tk.Frame(self, bg="#121212")
        brand.pack(fill=tk.X)
        row = tk.Frame(brand, bg="#121212")
        row.pack(fill=tk.X, padx=12, pady=(8, 0))
        png32 = asset_path("linshen32.png")
        if os.path.isfile(png32):
            try:
                self._brand_icon = PhotoImage(file=png32)
                tk.Label(row, image=self._brand_icon, bg="#121212", bd=0).pack(side=tk.LEFT, padx=(0, 10))
            except Exception:
                pass
        self.slogan_cv = Canvas(row, height=32, bg="#121212", highlightthickness=0, bd=0)
        self.slogan_cv.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Label(
            brand, text="by 林神", fg="#c9a227", bg="#121212",
            font=("Microsoft YaHei UI", 9),
        ).pack(anchor="w", padx=54, pady=(0, 8))
        self._start_marquee()

    def _start_marquee(self):
        if self.slogan_cv is None:
            return
        blob = SLOGAN_GAP.join(SLOGANS) + SLOGAN_GAP
        self._slogan_x = 40
        self._slogan_id = self.slogan_cv.create_text(
            self._slogan_x, 16,
            text=blob,
            anchor="w",
            fill="#e6c35c",
            font=("Microsoft YaHei UI", 12),
        )
        self.after(40, self._tick_marquee)

    def _tick_marquee(self):
        cv = self.slogan_cv
        if cv is None:
            return
        try:
            if not cv.winfo_exists():
                return
        except Exception:
            return
        self._slogan_x -= 2
        cv.coords(self._slogan_id, self._slogan_x, 16)
        bbox = cv.bbox(self._slogan_id)
        if bbox and bbox[2] < 8:
            self._slogan_x = max(cv.winfo_width(), 200)
            cv.coords(self._slogan_id, self._slogan_x, 16)
        self.after(30, self._tick_marquee)

    def _build(self, sess):
        self.configure(bg=BG)
        self._apply_theme()
        self._build_brand()
        tk.Frame(self, bg=TEXT, height=2).pack(fill=tk.X)

        root = tk.Frame(self, bg=BG)
        root.pack(fill=tk.BOTH, expand=True, padx=20, pady=14)

        header = tk.Frame(root, bg=BG)
        header.pack(fill=tk.X, pady=(0, 10))
        tk.Label(header, text="黑名单下发", bg=BG, fg=TEXT, font=("Microsoft YaHei UI", 16, "bold")).pack(side=tk.LEFT)
        self.lbl_status = tk.Label(header, text="就绪", bg=BG, fg=MUTED, font=("Microsoft YaHei UI", 9))
        self.lbl_status.pack(side=tk.LEFT, padx=16)
        self.lbl_file = tk.Label(header, text=os.path.basename(black_txt_path()), bg=BG, fg=MUTED, font=("Consolas", 9))
        self.lbl_file.pack(side=tk.RIGHT)
        self.lbl_comment = tk.Label(header, text="", bg=BG, fg=TEXT, font=("Consolas", 10))
        self.lbl_comment.pack(side=tk.RIGHT, padx=12)

        msg_wrap = tk.Frame(root, bg=SURFACE)
        msg_wrap.pack(fill=tk.X, pady=(0, 10))
        msg_head = tk.Frame(msg_wrap, bg=SURFACE)
        msg_head.pack(fill=tk.X, padx=10, pady=(6, 0))
        tk.Label(msg_head, text="通报", bg=SURFACE, fg=MUTED, font=("Microsoft YaHei UI", 8)).pack(side=tk.LEFT)
        tk.Label(msg_head, text="复制", bg=SURFACE, fg=MUTED, font=("Microsoft YaHei UI", 8), cursor="hand2").pack(side=tk.RIGHT)
        msg_head.winfo_children()[-1].bind("<Button-1>", lambda e: self.on_copy_msg())
        self.txt_msg = self._text(msg_wrap, 2, ("Microsoft YaHei UI", 9), bg=SURFACE, fg=MUTED, highlightthickness=0, padx=10, pady=4)
        self.txt_msg.pack(fill=tk.X, padx=4, pady=(0, 6))
        self.txt_msg.insert("1.0", "封禁成功后，通报会出现在这里。")
        self.txt_msg.config(state=tk.DISABLED)

        self.nb_cfg = ttk.Notebook(root, style="Cfg.TNotebook")
        self.nb_cfg.pack(fill=tk.X, pady=(0, 12))
        tx_tab = ttk.Frame(self.nb_cfg, padding=12)
        hw_tab = ttk.Frame(self.nb_cfg, padding=12)
        self.nb_cfg.add(tx_tab, text="  1  腾讯云 Cookie  ")
        self.nb_cfg.add(hw_tab, text="  2  华为云 Cookie  ")

        ttk.Label(tx_tab, text="只做查询探测（DescribeDuplicateIP），不会下发封禁。", style="Muted.TLabel").pack(anchor="w")
        tx_h = ttk.Frame(tx_tab)
        tx_h.pack(fill=tk.X, pady=(8, 4))
        ttk.Label(tx_h, text="Cookie", style="Muted.TLabel").pack(side=tk.LEFT)
        self.lbl_tx_ok = tk.Label(tx_h, text="未探测", bg=BG, fg=MUTED, font=("Microsoft YaHei UI", 9))
        self.lbl_tx_ok.pack(side=tk.RIGHT)
        self.txt_cookie = self._text(tx_tab, 5, ("Consolas", 10))
        self.txt_cookie.pack(fill=tk.X)
        self.txt_cookie.insert("1.0", sess.get("cookie") or "")
        self.txt_cookie.bind("<KeyRelease>", lambda e: (self._sync_tx_fields(), self._mark_tx(False)))
        tx_meta = ttk.Frame(tx_tab)
        tx_meta.pack(fill=tk.X, pady=(8, 8))
        ttk.Label(tx_meta, text="csrfCode", style="Muted.TLabel").pack(side=tk.LEFT)
        self.ent_csrf = ttk.Entry(tx_meta, width=14)
        self.ent_csrf.pack(side=tk.LEFT, padx=(6, 14))
        self.ent_csrf.insert(0, sess.get("csrf") or "")
        ttk.Label(tx_meta, text="uin", style="Muted.TLabel").pack(side=tk.LEFT)
        self.ent_uin = ttk.Entry(tx_meta, width=16)
        self.ent_uin.pack(side=tk.LEFT, padx=(6, 14))
        self.ent_uin.insert(0, sess.get("uin") or "")
        ttk.Label(tx_meta, text="ownerUin", style="Muted.TLabel").pack(side=tk.LEFT)
        self.ent_owner = ttk.Entry(tx_meta, width=16)
        self.ent_owner.pack(side=tk.LEFT, padx=(6, 0))
        self.ent_owner.insert(0, sess.get("owner_uin") or "")
        self.btn_tx_ok = self._flat_btn(tx_tab, "探测腾讯云是否有效", self.on_confirm_tencent)
        self.btn_tx_ok.pack(anchor="e")

        ttk.Label(
            hw_tab,
            text="只做查询探测（对象组 address-sets GET），不会写入封禁。Agency / 区域从 Cookie 自动取。",
            style="Muted.TLabel",
        ).pack(anchor="w")
        hw_h = ttk.Frame(hw_tab)
        hw_h.pack(fill=tk.X, pady=(8, 4))
        ttk.Label(hw_h, text="Cookie", style="Muted.TLabel").pack(side=tk.LEFT)
        self.lbl_hw_ok = tk.Label(hw_h, text="未探测", bg=BG, fg=MUTED, font=("Microsoft YaHei UI", 9))
        self.lbl_hw_ok.pack(side=tk.RIGHT)
        self.txt_hw_cookie = self._text(hw_tab, 5, ("Consolas", 10))
        self.txt_hw_cookie.pack(fill=tk.X)
        self.txt_hw_cookie.insert("1.0", sess.get("hw_cookie") or "")
        self.txt_hw_cookie.bind("<KeyRelease>", lambda e: (self._sync_hw_fields(), self._mark_hw(False)))
        hw_meta = ttk.Frame(hw_tab)
        hw_meta.pack(fill=tk.X, pady=(8, 8))
        ttk.Label(hw_meta, text="Cftk", style="Muted.TLabel").pack(side=tk.LEFT)
        self.ent_hw_cftk = ttk.Entry(hw_meta, width=40)
        self.ent_hw_cftk.pack(side=tk.LEFT, padx=(6, 0), fill=tk.X, expand=True)
        self.ent_hw_cftk.insert(0, sess.get("hw_cftk") or "")
        hw_ids = ttk.Frame(hw_tab)
        hw_ids.pack(fill=tk.X, pady=(8, 4))
        ttk.Label(hw_ids, text="project", style="Muted.TLabel").pack(side=tk.LEFT)
        self.ent_hw_project = ttk.Entry(hw_ids, width=36)
        self.ent_hw_project.pack(side=tk.LEFT, padx=(6, 12))
        self.ent_hw_project.insert(0, sess.get("hw_project") or "")
        ttk.Label(hw_ids, text="object_id", style="Muted.TLabel").pack(side=tk.LEFT)
        self.ent_hw_object = ttk.Entry(hw_ids, width=36)
        self.ent_hw_object.pack(side=tk.LEFT, padx=(6, 0), fill=tk.X, expand=True)
        self.ent_hw_object.insert(0, sess.get("hw_object_id") or "")
        hw_ids2 = ttk.Frame(hw_tab)
        hw_ids2.pack(fill=tk.X, pady=(4, 4))
        ttk.Label(hw_ids2, text="fwInstanceId", style="Muted.TLabel").pack(side=tk.LEFT)
        self.ent_hw_fw = ttk.Entry(hw_ids2, width=36)
        self.ent_hw_fw.pack(side=tk.LEFT, padx=(6, 12))
        self.ent_hw_fw.insert(0, sess.get("hw_fw_instance") or "")
        ttk.Label(hw_ids2, text="EPS", style="Muted.TLabel").pack(side=tk.LEFT)
        self.ent_hw_eps = ttk.Entry(hw_ids2, width=36)
        self.ent_hw_eps.pack(side=tk.LEFT, padx=(6, 0), fill=tk.X, expand=True)
        self.ent_hw_eps.insert(0, sess.get("hw_eps") or "")
        self.lbl_hw_ident = ttk.Label(hw_tab, text="", style="Muted.TLabel")
        self.lbl_hw_ident.pack(anchor="w", pady=(4, 0))
        self.btn_hw_ok = self._flat_btn(hw_tab, "探测华为云是否有效", self.on_confirm_huawei)
        self.btn_hw_ok.pack(anchor="e")

        card = tk.Frame(root, bg=CARD, highlightthickness=1, highlightbackground=LINE)
        card.pack(fill=tk.X, pady=(0, 10))
        inner = tk.Frame(card, bg=CARD)
        inner.pack(fill=tk.BOTH, expand=True, padx=14, pady=12)
        top_card = tk.Frame(inner, bg=CARD)
        top_card.pack(fill=tk.X)
        tk.Label(top_card, text="IP 列表", bg=CARD, fg=TEXT, font=("Microsoft YaHei UI", 10, "bold")).pack(side=tk.LEFT)
        tk.Label(top_card, text="每行一个，逗号也行", bg=CARD, fg=MUTED, font=("Microsoft YaHei UI", 8)).pack(side=tk.RIGHT)
        self.txt_ips = self._text(inner, 4, ("Consolas", 13))
        self.txt_ips.pack(fill=tk.X, pady=(8, 10))
        self.txt_ips.insert("1.0", sess.get("ips") or "")
        self.txt_ips.focus_set()
        self.txt_ips.bind("<Control-Return>", lambda e: (self.on_submit(), "break")[1])
        bar = tk.Frame(inner, bg=CARD)
        bar.pack(fill=tk.X)
        tk.Label(bar, text="姓名", bg=CARD, fg=MUTED, font=("Microsoft YaHei UI", 9)).pack(side=tk.LEFT)
        self.ent_name = ttk.Entry(bar, width=12, font=("Microsoft YaHei UI", 10))
        self.ent_name.pack(side=tk.LEFT, padx=(8, 16))
        self.ent_name.insert(0, sess.get("name") or DEFAULT_NAME)
        self.ent_name.bind("<KeyRelease>", lambda e: self._refresh_comment())
        self.btn = self._flat_btn(bar, "下发封禁", self.on_submit, True)
        self.btn.pack(side=tk.RIGHT)
        self.btn_hw = self._flat_btn(bar, "华为查询", self.on_huawei, False)
        self.btn_hw.pack(side=tk.RIGHT, padx=(0, 8))
        ttk.Button(bar, text="清空", style="Ghost.TButton", command=self.on_clear_ips).pack(side=tk.RIGHT, padx=8)

        tk.Label(root, text="结果", bg=BG, fg=MUTED, font=("Microsoft YaHei UI", 8)).pack(anchor="w")
        cols = ("ip", "status", "geo", "hw")
        self.tree = ttk.Treeview(root, columns=cols, show="headings", height=5)
        self.tree.heading("ip", text="IP")
        self.tree.heading("status", text="状态")
        self.tree.heading("geo", text="归属地")
        self.tree.heading("hw", text="华为供应商")
        self.tree.column("ip", width=160, anchor="w")
        self.tree.column("status", width=80, anchor="center")
        self.tree.column("geo", width=180, anchor="w")
        self.tree.column("hw", width=420, anchor="w")
        self.tree.pack(fill=tk.X, pady=(4, 10))
        self.tree.tag_configure("blocked", background="#f4eee8", foreground="#6e6860")
        self.tree.tag_configure("open", background=CARD, foreground=TEXT)
        self.tree.tag_configure("dup", background="#f6f1e4", foreground="#6e6860")
        self.tree.tag_configure("ok", background="#f3f1ea", foreground=TEXT)
        self.tree.tag_configure("fail", background="#f7ecec", foreground="#8a5555")

        nb = ttk.Notebook(root)
        nb.pack(fill=tk.BOTH, expand=True)
        payload_tab = ttk.Frame(nb, padding=8)
        raw_tab = ttk.Frame(nb, padding=8)
        nb.add(payload_tab, text="  请求体  ")
        nb.add(raw_tab, text="  响应  ")
        self.txt_payload = self._text(payload_tab, 16, ("Consolas", 10), fg=MUTED)
        self.txt_payload.pack(fill=tk.BOTH, expand=True)
        self.txt_raw = self._text(raw_tab, 16, ("Consolas", 10), fg=MUTED)
        self.txt_raw.pack(fill=tk.BOTH, expand=True)

        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self._sync_tx_fields()
        self._sync_hw_fields()
        self._refresh_comment()

    def _comment(self):
        return make_comment(self.ent_name.get())

    def _refresh_comment(self):
        self.lbl_comment.config(text=self._comment())
        self.lbl_file.config(text=os.path.basename(black_txt_path()))
        self._refresh_payload()

    def _tick_comment(self):
        self._refresh_comment()
        self.after(10000, self._tick_comment)

    def _refresh_payload(self):
        ips = parse_ips(self.txt_ips.get("1.0", "end"))
        note = self._comment()
        if not ips:
            text = "先在上面填 IP。"
        else:
            text = (
                "===== WAF CreateIpAccessControl  IpList + Note =====\n"
                + json.dumps(build_waf_payload(ips, note), ensure_ascii=False, indent=2)
                + "\n\n===== 云防火墙 CreateBlockIgnoreRuleNew  Ioc + Comment =====\n"
                + json.dumps(build_cfw_payload(ips, note), ensure_ascii=False, indent=2)
            )
        self.txt_payload.delete("1.0", "end")
        self.txt_payload.insert("1.0", text)

    def on_clear_ips(self):
        self.txt_ips.delete("1.0", "end")
        self.txt_ips.focus_set()
        self._refresh_payload()

    def _sync_tx_fields(self, update_ui=True):
        raw = self.txt_cookie.get("1.0", "end").strip()
        cookie = strip_cookie_header(raw)
        if update_ui and cookie != raw:
            self.txt_cookie.delete("1.0", "end")
            self.txt_cookie.insert("1.0", cookie)
        kv = cookie_map(cookie)
        csrf = csrf_from_skey(kv.get("skey") or "") or self.ent_csrf.get().strip()
        uin = digits_id(kv.get("uin") or "") or self.ent_uin.get().strip()
        owner = digits_id(kv.get("ownerUin") or "") or self.ent_owner.get().strip()
        if update_ui:
            if csrf and csrf != self.ent_csrf.get().strip():
                self.ent_csrf.delete(0, "end")
                self.ent_csrf.insert(0, csrf)
            if uin and uin != self.ent_uin.get().strip():
                self.ent_uin.delete(0, "end")
                self.ent_uin.insert(0, uin)
            if owner and owner != self.ent_owner.get().strip():
                self.ent_owner.delete(0, "end")
                self.ent_owner.insert(0, owner)
        return cookie, csrf, uin, owner

    def _sync_hw_fields(self, update_ui=True):
        raw = self.txt_hw_cookie.get("1.0", "end").strip()
        cookie = strip_cookie_header(raw)
        if update_ui and cookie != raw:
            self.txt_hw_cookie.delete("1.0", "end")
            self.txt_hw_cookie.insert("1.0", cookie)
        ident = hw_identity(cookie)
        cftk = ident["cftk"] or self.ent_hw_cftk.get().strip()
        if update_ui and cftk and cftk != self.ent_hw_cftk.get().strip():
            self.ent_hw_cftk.delete(0, "end")
            self.ent_hw_cftk.insert(0, cftk)
        if update_ui and hasattr(self, "lbl_hw_ident"):
            bits = []
            if ident.get("user"):
                bits.append(ident["user"])
            if ident.get("agency"):
                bits.append("agency " + ident["agency"])
            if ident.get("regions"):
                bits.append("region " + ident["regions"][0])
            if cookie and not ident.get("jsession"):
                bits.append("缺 J_SESSION_ID（Application 里拷）")
            self.lbl_hw_ident.config(text="  ·  ".join(bits) if bits else "贴 Cookie 后自动填 agency / region")
        return cookie, cftk

    def _collect(self):
        cookie, csrf, uin, owner = self._sync_tx_fields()
        hw_cookie, hw_cftk = self._sync_hw_fields()
        return {
            "ips": self.txt_ips.get("1.0", "end").strip(),
            "cookie": cookie,
            "csrf": csrf,
            "uin": uin,
            "owner_uin": owner,
            "name": self.ent_name.get().strip(),
            "hw_cookie": hw_cookie,
            "hw_cftk": hw_cftk,
            "hw_project": self.ent_hw_project.get().strip(),
            "hw_object_id": self.ent_hw_object.get().strip(),
            "hw_fw_instance": self.ent_hw_fw.get().strip(),
            "hw_eps": self.ent_hw_eps.get().strip(),
        }

    def on_reload_packet(self):
        pkt = parse_packet_file(PACKET_FILE)
        if not pkt:
            messagebox.showwarning("未找到", "读不到数据包文件:\n" + PACKET_FILE)
            return
        if pkt.get("cookie"):
            self.txt_cookie.delete("1.0", "end")
            self.txt_cookie.insert("1.0", pkt["cookie"])
        if pkt.get("csrfCode"):
            self.ent_csrf.delete(0, "end")
            self.ent_csrf.insert(0, pkt["csrfCode"])
        if pkt.get("uin"):
            self.ent_uin.delete(0, "end")
            self.ent_uin.insert(0, pkt["uin"])
        if pkt.get("ownerUin"):
            self.ent_owner.delete(0, "end")
            self.ent_owner.insert(0, pkt["ownerUin"])
        self.lbl_status.config(text="已从数据包文件重载 Cookie / csrf / uin")
        self._mark_tx(False)

    def on_confirm_tencent(self):
        if self._busy:
            return
        data = self._collect()
        if not data["cookie"] or not data["csrf"]:
            self._mark_tx(False, "Cookie/csrf 空")
            messagebox.showwarning("腾讯云", "先贴 Cookie，并填 csrfCode")
            return
        save_session(data)
        self._set_busy(True, "查询探测腾讯云 Cookie（不下发）")

        def worker():
            try:
                st, ver, body, raw = probe(
                    ["1.1.1.1"], data["cookie"], data["csrf"], data["uin"], data["owner_uin"]
                )
                ok = biz_ok(st, body)
                err = None if ok else "HTTP %s" % st
            except Exception as e:
                ok, ver, body, raw, err = False, "", {}, str(e), str(e)
            self.after(0, lambda: self._done_confirm_tx(ok, ver, body, raw, err))

        threading.Thread(target=worker, daemon=True).start()

    def _done_confirm_tx(self, ok, ver, body, raw, err):
        self._set_busy(False)
        pretty = dump_json(body, raw) if body else (err or "")
        self.txt_raw.delete("1.0", "end")
        self.txt_raw.insert("1.0", pretty)
        if ok:
            self._mark_tx(True, "有效")
            self.lbl_status.config(text="腾讯云 Cookie 有效（查询探测，未封禁）")
        else:
            self._mark_tx(False, "无效")
            self.lbl_status.config(text="腾讯云 Cookie 无效，重新登录控制台复制")

    def on_confirm_huawei(self):
        if self._busy:
            return
        data = self._collect()
        cookie = data.get("hw_cookie") or ""
        cftk = data.get("hw_cftk") or cftk_from_cookie(cookie)
        if cftk and cftk != self.ent_hw_cftk.get().strip():
            self.ent_hw_cftk.delete(0, "end")
            self.ent_hw_cftk.insert(0, cftk)
            data["hw_cftk"] = cftk
        if not cookie:
            self._mark_hw(False, "Cookie 空")
            messagebox.showwarning("华为云", "先贴华为云 Cookie")
            return
        ident = hw_identity(cookie)
        if not cftk:
            self._mark_hw(False, "缺 Cftk")
            messagebox.showwarning("华为云", "Cftk 空。Cookie 里带 cftk= 会自动填")
            return
        if not ident.get("jsession"):
            self._mark_hw(False, "缺 J_SESSION_ID")
            messagebox.showwarning("华为云", "Cookie 没有 J_SESSION_ID。从 DevTools → Application → Cookies 整段复制")
            return
        if not ident.get("agency"):
            self._mark_hw(False, "缺 agencyID")
            messagebox.showwarning("华为云", "Cookie 没有 agencyID")
            return
        if not data.get("hw_project") or not data.get("hw_object_id"):
            self._mark_hw(False, "缺 project/object_id")
            messagebox.showwarning("华为云", "先填 project 和 object_id（从 CFW 控制台 URL / 抓包里抄）")
            return
        save_session(data)
        self._set_busy(True, "查询探测华为云 Cookie（不下发）")

        def worker():
            try:
                st, ver, body, raw = query_hw_sets(
                    "1.1.1.1", cookie, cftk,
                    project=data.get("hw_project"),
                    object_id=data.get("hw_object_id"),
                    fw_instance=data.get("hw_fw_instance"),
                    eps=data.get("hw_eps"),
                )
                ok = hw_sets_ok(st, body)
                err = None if ok else "HTTP %s" % st
            except Exception as e:
                ok, ver, body, raw, err = False, "", {}, str(e), str(e)
            self.after(0, lambda: self._done_confirm_hw(ok, ver, body, raw, err))

        threading.Thread(target=worker, daemon=True).start()

    def _done_confirm_hw(self, ok, ver, body, raw, err):
        self._set_busy(False)
        pretty = dump_json(body, raw) if body else (err or "")
        self.txt_raw.delete("1.0", "end")
        self.txt_raw.insert("1.0", pretty)
        if ok:
            used = ""
            if isinstance(body, dict):
                used = "  %s / %s" % (body.get("_used_agency") or "", body.get("_used_region") or "")
            self._mark_hw(True, "有效")
            self.lbl_status.config(text="华为云 Cookie 有效（查询探测，未封禁）" + used)
        else:
            self._mark_hw(False, "无效")
            self.lbl_status.config(text="华为云 Cookie 无效，重新登录控制台复制")

    def _set_msg(self, text):
        self.txt_msg.config(state=tk.NORMAL)
        self.txt_msg.delete("1.0", "end")
        if text:
            self.txt_msg.insert("1.0", text)
        else:
            self.txt_msg.insert("1.0", "封禁成功后，通报会出现在这里。")
        self.txt_msg.config(state=tk.DISABLED)

    def _mark_tx(self, ok, text=None):
        self._tx_ready = bool(ok)
        if ok:
            self.lbl_tx_ok.config(text=text or "有效", fg="#2f6b3a")
        else:
            self.lbl_tx_ok.config(text=text or "未探测", fg=MUTED)

    def _mark_hw(self, ok, text=None):
        self._hw_ready = bool(ok)
        if ok:
            self.lbl_hw_ok.config(text=text or "有效", fg="#2f6b3a")
        else:
            self.lbl_hw_ok.config(text=text or "未探测", fg=MUTED)

    def _set_busy(self, busy, text=None):
        self._busy = busy
        if busy:
            self.btn.config(state=tk.DISABLED, bg="#d8d5ce", fg=MUTED)
            self.btn_hw.config(state=tk.DISABLED, bg=SURFACE, fg=MUTED)
            self.btn_tx_ok.config(state=tk.DISABLED, bg="#d8d5ce", fg=MUTED)
            self.btn_hw_ok.config(state=tk.DISABLED, bg="#d8d5ce", fg=MUTED)
        else:
            self.btn.config(state=tk.NORMAL, bg=TEXT, fg=INK)
            self.btn_hw.config(state=tk.NORMAL, bg=CARD, fg=TEXT)
            self.btn_tx_ok.config(state=tk.NORMAL, bg=TEXT, fg=INK)
            self.btn_hw_ok.config(state=tk.NORMAL, bg=TEXT, fg=INK)
        if text:
            self.lbl_status.config(text=text)

    def on_submit(self):
        if self._busy:
            return
        data = self._collect()
        ips = parse_ips(data["ips"])
        if not ips:
            messagebox.showwarning("提示", "先填要下发的 IP")
            return
        if not self._tx_ready:
            messagebox.showwarning("提示", "先到便签 1 探测腾讯云 Cookie 是否有效")
            return
        if not data["cookie"] or not data["csrf"]:
            messagebox.showwarning("提示", "腾讯云 Cookie / csrfCode 不能空")
            return
        note = self._comment()
        save_session(data)
        self._refresh_payload()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.txt_raw.delete("1.0", "end")
        self._set_msg("")
        self._set_busy(True, "探测中")

        def worker():
            logs = []
            try:
                st, ver, body, raw = probe(ips, data["cookie"], data["csrf"], data["uin"], data["owner_uin"])
                logs.append("===== DescribeDuplicateIP %s %s =====\n%s" % (ver, st, dump_json(body, raw)))
                if not biz_ok(st, body):
                    result = {"ok": False, "stage": "probe", "logs": logs, "err": "探测失败 HTTP %s" % st}
                    self.after(0, lambda: self._finish(result, ips, note, [], []))
                    return
                removed, duplicate = extract_response_lists(body if isinstance(body, dict) else {})
                rows = classify_ips(ips, removed, duplicate)
                opened = [r["ip"] for r in rows if r["status"] == "未封"]
                skipped = [r for r in rows if r["status"] != "未封"]
                if not opened:
                    result = {
                        "ok": True, "stage": "skip", "logs": logs, "err": None,
                        "rows": rows, "opened": [], "file": None, "added": 0,
                        "waf_ok": None, "cfw_ok": None,
                    }
                    self.after(0, lambda: self._finish(result, ips, note, skipped, opened))
                    return

                self.after(0, lambda: self.lbl_status.config(text="下发 WAF  ·  %d" % len(opened)))
                wst, wver, wbody, wraw = create_waf(
                    opened, note, data["cookie"], data["csrf"], data["uin"], data["owner_uin"]
                )
                logs.append("===== CreateIpAccessControl %s %s =====\n%s" % (wver, wst, dump_json(wbody, wraw)))
                waf_ok = biz_ok(wst, wbody)

                self.after(0, lambda: self.lbl_status.config(text="下发云防火墙  ·  %d" % len(opened)))
                cst, cver, cbody, craw = create_cfw(
                    opened, note, data["cookie"], data["csrf"], data["uin"], data["owner_uin"]
                )
                logs.append("===== CreateBlockIgnoreRuleNew %s %s =====\n%s" % (cver, cst, dump_json(cbody, craw)))
                cfw_ok = biz_ok(cst, cbody)

                path, added = None, 0
                msgs = []
                geos = {}
                if waf_ok or cfw_ok:
                    path, added = append_black_file(opened, note)
                    self.after(0, lambda: self.lbl_status.config(text="查归属地"))
                    for ip in opened:
                        geo = lookup_geo(ip)
                        geos[ip] = geo
                        msgs.append(ban_success_line(geo, ip))

                result = {
                    "ok": waf_ok or cfw_ok,
                    "stage": "send",
                    "logs": logs,
                    "err": None,
                    "rows": rows,
                    "opened": opened,
                    "file": path,
                    "added": added,
                    "waf_ok": waf_ok,
                    "cfw_ok": cfw_ok,
                    "waf_st": wst,
                    "cfw_st": cst,
                    "msgs": msgs,
                    "geos": geos,
                }
                self.after(0, lambda: self._finish(result, ips, note, skipped, opened))
            except Exception as e:
                logs.append(str(e))
                result = {"ok": False, "stage": "exc", "logs": logs, "err": str(e)}
                self.after(0, lambda: self._finish(result, ips, note, [], []))

        threading.Thread(target=worker, daemon=True).start()

    def _finish(self, result, ips, note, skipped, opened):
        self._set_busy(False)
        self.txt_raw.delete("1.0", "end")
        self.txt_raw.insert("1.0", "\n\n".join(result.get("logs") or []))
        for item in self.tree.get_children():
            self.tree.delete(item)

        if result.get("err") and result.get("stage") in ("probe", "exc"):
            self.lbl_status.config(text="失败  ·  Cookie 过期去会话页")
            return

        rows = result.get("rows") or classify_ips(ips, [], [])
        waf_ok = result.get("waf_ok")
        cfw_ok = result.get("cfw_ok")
        geos = result.get("geos") or {}
        msgs = result.get("msgs") or []
        self._set_msg("\n".join(msgs) if msgs else "")
        for r in rows:
            geo = geos.get(r["ip"], "")
            if r["status"] == "已封过":
                tag, status, geo = "blocked", "已封过", geo or "—"
            elif r["status"] == "名单重复":
                tag, status, geo = "dup", "名单重复", geo or "—"
            else:
                if waf_ok or cfw_ok:
                    tag, status = "ok", "已下发"
                    geo = geo or "—"
                elif result.get("stage") == "skip":
                    tag, status, geo = "open", "未封", "—"
                else:
                    tag, status, geo = "fail", "失败", geo or "—"
            self.tree.insert("", "end", values=(r["ip"], status, geo, "—"), tags=(tag,))

        if result.get("stage") == "skip":
            self.lbl_status.config(text="无需下发  ·  均已在名单")
            return

        bits = []
        bits.append("WAF " + ("ok" if waf_ok else "fail"))
        bits.append("CFW " + ("ok" if cfw_ok else "fail"))
        if result.get("file") and result.get("added"):
            bits.append("+%d  %s" % (result["added"], os.path.basename(result["file"])))
        self.lbl_status.config(text="  ·  ".join(bits))
        self.lbl_file.config(text=os.path.basename(black_txt_path()))

    def on_huawei(self):
        if self._busy:
            return
        data = self._collect()
        ips = parse_ips(data["ips"])
        if not ips:
            messagebox.showwarning("提示", "先填要查的 IP")
            return
        if not self._hw_ready:
            messagebox.showwarning("提示", "先到便签 2 探测华为云 Cookie 是否有效")
            return
        if not data.get("hw_cookie"):
            messagebox.showwarning("提示", "华为云 Cookie 不能空")
            return
        if not data.get("hw_project") or not data.get("hw_object_id"):
            messagebox.showwarning("提示", "华为云 project / object_id 不能空")
            return
        save_session(data)
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.txt_raw.delete("1.0", "end")
        self._set_msg("")
        self._set_busy(True, "华为对象组查询  ·  %d" % len(ips))

        def worker():
            logs = []
            rows = []
            lines = []
            try:
                for i, ip in enumerate(ips, 1):
                    self.after(0, lambda i=i: self.lbl_status.config(text="华为查询  %d/%d" % (i, len(ips))))
                    st, ver, body, raw = query_hw_sets(
                        ip, data["hw_cookie"], data["hw_cftk"],
                        project=data.get("hw_project"),
                        object_id=data.get("hw_object_id"),
                        fw_instance=data.get("hw_fw_instance"),
                        eps=data.get("hw_eps"),
                    )
                    logs.append("===== %s  %s %s =====\n%s" % (ip, ver, st, dump_json(body, raw)))
                    if not hw_sets_ok(st, body):
                        rows.append({"ip": ip, "status": "失败", "vendors": [], "names": []})
                        continue
                    names, vendors = parse_hw_records(body)
                    if names:
                        rows.append({"ip": ip, "status": "已封", "vendors": vendors, "names": names})
                        lines.append("%s  %s" % (ip, "、".join(vendors) if vendors else "、".join(names)))
                    else:
                        rows.append({"ip": ip, "status": "未封", "vendors": [], "names": []})
                self.after(0, lambda: self._finish_hw(rows, lines, logs))
            except Exception as e:
                logs.append(str(e))
                self.after(0, lambda: self._finish_hw([], [str(e)], logs))

        threading.Thread(target=worker, daemon=True).start()

    def _finish_hw(self, rows, lines, logs):
        self._set_busy(False)
        self.txt_raw.delete("1.0", "end")
        self.txt_raw.insert("1.0", "\n\n".join(logs or []))
        for item in self.tree.get_children():
            self.tree.delete(item)
        if lines:
            self._set_msg("\n".join(lines))
        else:
            self._set_msg("")
        blocked = 0
        for r in rows:
            vendors = r.get("vendors") or []
            hw = "、".join(vendors) if vendors else ("—" if r["status"] != "已封" else "、".join(r.get("names") or []))
            if r["status"] == "已封":
                tag, blocked = "ok", blocked + 1
            elif r["status"] == "失败":
                tag = "fail"
            else:
                tag = "open"
            self.tree.insert("", "end", values=(r["ip"], r["status"], "—", hw), tags=(tag,))
        self.lbl_status.config(text="华为  ·  已封 %d / %d" % (blocked, len(rows)))

    def on_copy_msg(self):
        text = self.txt_msg.get("1.0", "end").strip()
        if not text or text.startswith("封禁成功后"):
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self.lbl_status.config(text="已复制")

    def on_close(self):
        save_session(self._collect())
        self.destroy()


def main():
    _log_crash("start %s frozen=%s exe=%s" % (
        datetime.now().isoformat(timespec="seconds"),
        bool(getattr(sys, "frozen", False)),
        sys.executable,
    ))
    App().mainloop()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        import traceback
        _log_crash(traceback.format_exc())
        raise
