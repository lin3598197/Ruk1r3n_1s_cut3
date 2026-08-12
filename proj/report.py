import csv
import html
import json
from datetime import datetime


def export_json(fp, results_data):
    with open(fp, 'w', encoding='utf-8') as f:
        json.dump(results_data, f, ensure_ascii=False, indent=2)


def export_csv(fp, results_data):
    with open(fp, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['phase', 'chain', 'cmd', 'status', 'output', 'raw'], extrasaction='ignore')
        w.writeheader()
        w.writerows(results_data)


def export_html(fp, results_data):
    with open(fp, 'w', encoding='utf-8') as f:
        f.write('<html><head><meta charset="utf-8"><title>SSTI Report</title><style>')
        f.write('body{font-family:monospace;max-width:1200px;margin:0 auto;padding:20px;}')
        f.write('table{border-collapse:collapse;width:100%;}th,td{border:1px solid #ddd;padding:8px;text-align:left;}')
        f.write('th{background:#333;color:#fff;}pre{white-space:pre-wrap;word-wrap:break-word;background:#f4f4f4;padding:10px;border-radius:4px;}')
        f.write('</style></head><body>')
        f.write('<h1>SSTI 攻擊報告</h1>')
        f.write(f'<p>生成時間: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>')
        f.write('<table><tr><th>Phase</th><th>Chain</th><th>Cmd</th><th>Status</th><th>Output</th><th>Raw Response</th></tr>')
        for r in results_data:
            f.write(f"<tr><td>{html.escape(str(r.get('phase','')))}</td>")
            f.write(f"<td>{html.escape(str(r.get('chain','')))}</td>")
            f.write(f"<td>{html.escape(str(r.get('cmd','')))}</td>")
            f.write(f"<td>{html.escape(str(r.get('status','')))}</td>")
            f.write(f"<td><pre>{html.escape(str(r.get('output',''))[:2000])}</pre></td>")
            f.write(f"<td><pre>{html.escape(str(r.get('raw',''))[:2000])}</pre></td></tr>")
        f.write('</table></body></html>')


def export_text(fp, results_data):
    with open(fp, 'w', encoding='utf-8') as f:
        for r in results_data:
            f.write(f"{'='*60}\n")
            for k, v in r.items():
                f.write(f"{k}: {v}\n")


def export_report(fp, results_data):
    """依副檔名分派到對應的匯出格式（json/csv/html，其餘一律當純文字）"""
    if fp.endswith('.json'):
        export_json(fp, results_data)
    elif fp.endswith('.csv'):
        export_csv(fp, results_data)
    elif fp.endswith('.html'):
        export_html(fp, results_data)
    else:
        export_text(fp, results_data)
