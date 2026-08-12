from html.parser import HTMLParser


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
