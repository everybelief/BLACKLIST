# BLACKLIST

[Releases 下载 Windows exe](https://github.com/everybelief/BLACKLIST/releases/latest)

值守封 IP 用的。腾讯云 WAF 点一遍、云防火墙再点一遍，华为那边还得翻对象组看封没封、挂在哪个供应商名下。这个窗口一次做完。

Cookie 从控制台 F12 拷进来。探测只查询，不会封。点「下发封禁」才写腾讯云。华为目前只查不写。

逐步操作看 [使用说明.md](./使用说明.md)。

## 能干啥

- 先问腾讯云这批 IP 封过没有，封过的跳过
- 没封的，WAF 和云防火墙一起下，备注写成同一串：姓名+年月日时分
- 成功的 IP 追加到当天的 `1006-black.txt` 这种文件
- 查一下归属地，通报文案直接复制
- 华为对象组查询：在不在、供应商叫啥（`云快充封堵-008` → `云快充`）

## 跑

```
pip install -r requirements.txt
python waf_ip_check.py
```

Windows，Python 3.8+，推荐 3.12。有 httpx 走 HTTP/2，没有就用 requests。

打 exe（必须 3.12 的 PyInstaller）：

```
python -m PyInstaller --noconfirm BLACKLIST.spec
```

`dist\BLACKLIST.exe` 拷到单独目录再跑，会话文件写在 exe 旁边。打包前先把正在跑的 BLACKLIST 关掉。

## 怎么用

1. 登录腾讯云，打开 WAF IP 名单页，F12 → Network，复制完整 Cookie（别用 `document.cookie`，HttpOnly 会丢），贴便签 1，点探测
2. 填 IP，填姓名
3. 下发封禁（Ctrl+Enter 也行）
4. 要核华为的话，便签 2 贴 Cookie，把控制台 URL 里的 project / object_id / fwInstanceId 填上，探测后再点华为查询

Cookie 过期就重新登录再拷一遍。`skey` 变了 csrf 会自动重算。

## 代码

就一个 `waf_ip_check.py`。上面是 Tk 窗口，下面是调控制台的函数。按钮开线程，避免界面卡住。

```
界面 App
  ├ 腾讯云  console.cloud.tencent.com/cgi/capi
  │    DescribeDuplicateIP
  │    CreateIpAccessControl          WAF
  │    CreateBlockIgnoreRuleNew       云防火墙
  ├ 华为云  /cfw/v1/{project}/address-sets
  └ 旁边文件
       waf_ip_check_session.json   Cookie，别提交
       MMDD-black.txt              当天封成功的 IP
```

下发顺序：先探测 → 已封/重复的跳过 → 剩下的两边一起写 → 记文件 → 查归属地出通报。

## 别提交

`waf_ip_check_session.json`、`packet.txt`、`*-black.txt`、Cookie、exe。`.gitignore` 已经挡了。
