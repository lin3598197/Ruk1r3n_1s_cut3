import re

from proj.payloads import MATH_PROBE_TEMPLATES


class TemplateDetectMixin:
    """負責樣板引擎偵測：基準比對、數學運算探測、錯誤訊息識別。"""

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

        import difflib
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

    # 通用路由/伺服器層級錯誤頁的特徵（跟 template engine 是否解析了 payload 無關，
    # 純粹代表這個請求根本沒走到 render 那一步，例如路徑不存在、方法不允許等）
    _GENERIC_ERROR_MARKERS = (
        '404 not found', '403 forbidden', '405 method not allowed',
        'nginx', 'apache tomcat', 'cloudflare', 'the requested url was not found',
        'whitelabel error page',
    )
    # template engine 真的嘗試解析並丟出例外時，回應通常會帶有這類 traceback/
    # exception 結構特徵；純路由層錯誤頁一般不會有這些
    _EXCEPTION_STRUCTURE_MARKERS = (
        'traceback (most recent call last)', 'stacktrace', 'stack trace',
        'exception in thread', 'at java.', 'at org.springframework',
        '.java:', '.py", line', 'caused by:',
    )

    def _detect_by_error(self, text, status):
        """從錯誤訊息/回應中識別模板引擎（if-else 鏈）"""
        if not text or status == 200:
            return None, 0

        text_lower = text.lower()

        # 非 200 不代表這個回應就是 template engine 吐出來的錯誤——也可能只是
        # web server / 路由層本身的通用錯誤頁（例如 404 Not Found、Whitelabel
        # Error Page），跟 payload 語法有沒有被解析毫無關係。若內容看起來是
        # 通用錯誤頁、且沒有任何 exception/traceback 結構特徵，直接放棄比對，
        # 避免把「框架名稱洩漏」誤判為「payload 語法真的被該引擎解析執行」。
        looks_generic = any(m in text_lower for m in self._GENERIC_ERROR_MARKERS)
        has_exception_structure = any(m in text_lower for m in self._EXCEPTION_STRUCTURE_MARKERS)
        if looks_generic and not has_exception_structure:
            return None, 0

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

    def _math_probe_concat(self, point, template_key, expr, expected=None, expected_re=None):
        """
        以 MATH_PROBE_TEMPLATES 裡對應引擎語法的字串串接模板包裹 expr 送出，
        取代直接拼接 marker 文字與表達式（那樣即使引擎看不懂語法、原樣輸出，
        marker 仍會出現在回應裡而造成誤判）。
        """
        template = MATH_PROBE_TEMPLATES[template_key]
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

    def detect_template(self, points, log_cb):
        """智能模板偵測：結合錯誤訊息 + 數學運算 + 回應差異"""
        best_engine = None
        best_conf = 0
        best_point = None
        best_reason = ""

        # 猜測型注入點（例如 get_param 沒有既有 query string 時展開的整份候選
        # 參數清單）數量可能很多，逐一列印會洗版日誌；改成每種類型只在第一次
        # 進入時提示一次總數，之後同類型的點靜默測試，只有真的命中/有異常時
        # 才輸出（見下方各 Step 的 log_cb）。
        type_seen_count = {}
        total_points = len(points)

        for point_idx, point in enumerate(points):
            if not self.scanning:
                break

            ptype, url, method, data, desc = point
            type_seen_count[ptype] = type_seen_count.get(ptype, 0) + 1
            if type_seen_count[ptype] == 1:
                same_type_total = sum(1 for p in points if p[0] == ptype)
                if same_type_total > 1:
                    log_cb(f"[*] 開始測試 {ptype} 類型注入點（共 {same_type_total} 個候選，"
                           f"逐一測試，僅命中或有異常時才輸出）...")
                else:
                    log_cb(f"[*] 在 {desc} 進行智能模板偵測...")

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
                # 用 token 包裹重複運算式，只有運算結果（49 重複5次）真的出現在
                # marker 之間才算數；不能直接送裸露的 "{{7*7}}"*5 再看回應變長
                # 多少——若該引擎根本看不懂語法、原樣把 payload 字串回顯（例如
                # 錯誤頁或「您輸入的是: ...」之類的頁面），回應一樣會變長，但
                # 那是字串回顯而非模板執行，裸露長度檢測法無法區分兩者，會
                # 誤判為 SSTI。
                token_len = self._make_token()
                probe_time = f'SSTI_{token_len}_START_' + ('{{7*7}}' * 5) + f'SSTI_{token_len}_END_'
                text_t, status_t, elapsed_t = self.send_to_point(point, probe_time)
                extracted_len = self._extract_by_token(text_t, token_len) if status_t == 200 else None
                if extracted_len == '49' * 5:
                    log_cb("    [!] 重複運算探針命中 (49*5)，可能存在 SSTI (待盲注確認)")
                    if best_conf < 2:
                        best_conf = 2
                        best_point = point
                        best_reason = "重複運算探針命中"

        if best_engine:
            log_cb(f"[+] 最終識別: {best_engine} (信心度 {best_conf}) @ {best_point[4]}")
            log_cb(f"    原因: {best_reason}")

        return best_engine, best_conf, best_point, [best_reason] if best_reason else []
