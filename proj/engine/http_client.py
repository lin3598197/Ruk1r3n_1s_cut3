import json
import re
import time
import urllib.parse

import requests

from proj.html_parser import FormParser
from proj.payloads import COMMON_GET_PARAMS, COMMON_COOKIE_NAMES


class HttpClientMixin:
    """負責底層 HTTP 送出、注入點建構與自動發現。"""

    @staticmethod
    def _normalize_url(url):
        """
        修正常見的 URL 邊界問題後回傳可安全 urlparse 的字串：
        - 缺 scheme（例如使用者貼上 "target.com/page"）補上 http://
        - path 中的重複斜線（"//a//b"）合併，避免部分框架的路由比對失敗
          導致誤判注入點不存在
        """
        if url and not re.match(r'^[a-zA-Z][a-zA-Z0-9+.\-]*://', url):
            url = 'http://' + url
        parsed = urllib.parse.urlparse(url)
        path = re.sub(r'/{2,}', '/', parsed.path) or '/'
        return parsed._replace(path=path).geturl()

    @staticmethod
    def _inject_path_segments(url, payload):
        """
        對 URL path 中每一段（以 / 分隔的非空片段）逐一替換成 payload，
        涵蓋 REST 風格路由如 /api/user/123 或 /render/{template} 這類
        注入點不落在查詢字串、而是落在路徑片段本身的情況。
        純數字或看起來像 UUID 的片段優先（較可能是可變動的資源識別碼），
        但仍會嘗試全部片段，避免漏掉命名不規則的路由。
        """
        parsed = urllib.parse.urlparse(url)
        segments = parsed.path.split('/')
        injected_urls = []
        quoted_payload = urllib.parse.quote(payload, safe='')
        for i, seg in enumerate(segments):
            if not seg:
                continue
            new_segments = list(segments)
            new_segments[i] = quoted_payload
            new_path = '/'.join(new_segments)
            injected_urls.append(parsed._replace(path=new_path).geturl())
        return injected_urls

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
            return [f"{url}?{p}={urllib.parse.quote(payload)}" for p in COMMON_GET_PARAMS]

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
        # 比照 form_get：每個候選參數名各自是獨立的 point，而非把整批候選名塞給
        # HTTP 層自己在單一 point 裡逐一試錯——後者只能靠 status code 篩選猜測是否
        # 命中，但無法區分「猜對參數名」與「API 對任何參數都回 200」，見
        # send_to_point 的 get_param 分支
        existing_params = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        if existing_params:
            for param_name in existing_params:
                points.append(('get_param', base_url, 'GET', param_name, f'URL查詢參數: {param_name}'))
        else:
            for param_name in COMMON_GET_PARAMS:
                points.append(('get_param', base_url, 'GET', param_name, f'URL查詢參數(猜測): {param_name}'))
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
                    log_cb(f"    表單 action={form_url} method={method} ({len(form['inputs'])} 個欄位)")
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

        # Cookie 注入點：優先用目標實際 Set-Cookie 回來的既有 cookie 名稱（例如
        # session、username 等），而非只送一個寫死的 ssti_test cookie——若伺服器
        # 端根本不理會未知 cookie 名稱，payload 永遠不會進入模板渲染，導致「手動
        # 改對 cookie 名稱可以打中，工具卻測不出 SSTI」的漏測。做法比照 get_param
        # 對既有 query string 的處理：抓得到既有 cookie 就逐一各自建立注入點，
        # 抓不到才退回常見猜測名清單。self.session 是 requests.Session，前面
        # self.session.get(base_url, ...) 收到的 Set-Cookie 已自動併入
        # self.session.cookies，故不需另外從 r.cookies 讀取。
        existing_cookies = list(self.session.cookies.keys())
        if existing_cookies:
            for cookie_name in existing_cookies:
                points.append(('cookie', base_url, 'GET', cookie_name, f'Cookie: {cookie_name}'))
        else:
            for cookie_name in COMMON_COOKIE_NAMES:
                points.append(('cookie', base_url, 'GET', cookie_name, f'Cookie(猜測): {cookie_name}'))
        self.discovered_injection_points = points
        # 只彙總類型計數，不逐一列出每個注入點——get_param 在沒有既有 query
        # string 時會展開成整份 COMMON_GET_PARAMS 猜測清單（見上方 130-131
        # 行），逐一印出會變成一整排「URL查詢參數(猜測): xxx」洗版日誌。
        # points 完整內容仍保留在 self.discovered_injection_points 供實際測試。
        type_counts = {}
        for p in points:
            type_counts[p[0]] = type_counts.get(p[0], 0) + 1
        summary = ', '.join(f'{t}×{c}' for t, c in type_counts.items())
        log_cb(f"[*] 發現 {len(points)} 個潛在注入點 ({summary})")
        return points

    def send_to_point(self, point, payload):
        ptype, url, method, data, desc = point
        try:
            if ptype == 'get_param':
                field_name = data or 'q'
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                qs[field_name] = [payload]
                new_query = urllib.parse.urlencode(qs, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()
                t0 = time.time()
                r = self.session.get(test_url, timeout=self.timeout, allow_redirects=True)
                return r.text, r.status_code, time.time() - t0
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
                # data 帶有實際要注入的 cookie 名稱（既有 Set-Cookie 名稱優先，
                # 見 auto_discover），而非寫死 ssti_test——伺服器通常只會把它
                # 認得的 cookie 值代入模板，未知名稱的 cookie 常被直接忽略。
                # 其餘既有 cookie（例如認證用的 session）一併帶上，避免因缺少
                # 必要 cookie 導致請求被導向登入頁等，反而測不到真正的注入點。
                cookie_name = data or 'ssti_test'
                c = dict(self.session.cookies)
                c[cookie_name] = payload
                t0 = time.time()
                r = self.session.get(url, cookies=c, timeout=self.timeout, allow_redirects=True)
                return r.text, r.status_code, time.time() - t0
            else:
                return self.send(url, method, data, None, None, payload)
        except requests.exceptions.Timeout:
            return 'TIMEOUT', -1, self.timeout
        except Exception as e:
            return f'ERROR:{e}', -2, 0
