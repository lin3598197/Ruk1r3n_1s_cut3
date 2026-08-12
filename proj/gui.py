import threading
import time
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog

from proj.engine.core import SSTIEngine
from proj.report import export_report


class SSTIOneClickGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SSTI One-Click")
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

        ttk.Label(main, text="SSTI One-Click", font=('TkDefaultFont', 24, 'bold')).pack()
        ttk.Label(main, text="僅供學習與授權滲透測試使用", foreground='red', font=('TkDefaultFont', 9)).pack(pady=(0, 15))

        input_frame = ttk.Frame(main)
        input_frame.pack(fill=tk.X, pady=10)

        ttk.Label(input_frame, text="目標 URL:", font=('TkDefaultFont', 12)).pack(side=tk.LEFT, padx=5)
        self.URL_PLACEHOLDER = "http://example.com/"
        self.url_var = tk.StringVar(value=self.URL_PLACEHOLDER)
        self.url_is_placeholder = True
        url_entry = ttk.Entry(input_frame, textvariable=self.url_var, width=70,
                               font=('TkDefaultFont', 12), foreground='grey')
        url_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        url_entry.bind('<Return>', lambda e: self.start_attack())
        url_entry.bind('<FocusIn>', self._on_url_focus_in)
        url_entry.bind('<FocusOut>', self._on_url_focus_out)
        self.url_entry = url_entry

        btn_frame = ttk.Frame(main)
        btn_frame.pack(fill=tk.X, pady=10)

        self.attack_btn = tk.Button(btn_frame, text="🚀 一鍵攻擊", command=self.start_attack,
                                     font=('TkDefaultFont', 14, 'bold'), bg='#ff6b6b', fg='white',
                                     activebackground='#ee5a5a', activeforeground='white',
                                     padx=30, pady=10, cursor='hand2')
        self.attack_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = tk.Button(btn_frame, text="⏹ 停止", command=self.stop_attack, state=tk.DISABLED,
                                   font=('TkDefaultFont', 12), padx=20, pady=10)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        ttk.Button(btn_frame, text="💾 匯出報告", command=self.export_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="🧹 清除", command=self.clear_all).pack(side=tk.LEFT, padx=5)

        self.progress = ttk.Progressbar(main, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=5)

        result_nb = ttk.Notebook(main)
        result_nb.pack(fill=tk.BOTH, expand=True, pady=5)

        log_frame = ttk.Frame(result_nb, padding="5")
        result_nb.add(log_frame, text="📜 執行日誌")
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, font=('TkDefaultFont', 10))
        self.log_text.pack(fill=tk.BOTH, expand=True)

        raw_frame = ttk.Frame(result_nb, padding="5")
        result_nb.add(raw_frame, text="📄 原始命令輸出")
        self.raw_text = scrolledtext.ScrolledText(raw_frame, wrap=tk.WORD, font=('TkDefaultFont', 10))
        self.raw_text.pack(fill=tk.BOTH, expand=True)

        detail_frame = ttk.Frame(result_nb, padding="5")
        result_nb.add(detail_frame, text="📊 詳細彙總")
        self.detail_text = scrolledtext.ScrolledText(detail_frame, wrap=tk.WORD, font=('TkDefaultFont', 10))
        self.detail_text.pack(fill=tk.BOTH, expand=True)

        self.status_var = tk.StringVar(value="就緒 — 輸入 URL 後點擊「一鍵攻擊」")
        ttk.Label(main, textvariable=self.status_var, font=('TkDefaultFont', 10), foreground='gray').pack(fill=tk.X, pady=5)

        self.log("SSTI One-Click")
        self.log("=" * 60)

    def log(self, msg):
        ts = time.strftime('%H:%M:%S')
        self.log_text.insert(tk.END, f"[{ts}] {msg}\n")
        self.log_text.see(tk.END)

    def add_result(self, r):
        self.results_data.append(r)
        raw = r.get('raw', '')
        if raw or r.get('output'):
            self.raw_text.insert(tk.END, f"\n{'='*60}\n")
            self.raw_text.insert(tk.END, f"[Phase: {r.get('phase', '')}] [Chain: {r.get('chain', '')}]\n")
            self.raw_text.insert(tk.END, f"[Cmd: {r.get('cmd', '')}] [Status: {r.get('status', '')}]\n")
            self.raw_text.insert(tk.END, f"{'='*60}\n")
            self.raw_text.insert(tk.END, f"--- 原始 HTTP 回應內文 ---\n{raw}\n" if raw else "")
            self.raw_text.insert(tk.END, f"--- 擷取內容 (token marker 之間) ---\n{r.get('output', '')}\n")
            self.raw_text.see(tk.END)

    def update_filters(self, filters, level):
        self.log(f"[*] WAF/過濾分析結果（強度: {level}/10）:")
        for k, v in filters.items():
            status = "🚫 已過濾" if v else "✅ 可用"
            self.log(f"    {status} {k}")

    def _on_url_focus_in(self, event):
        if self.url_is_placeholder:
            self.url_var.set('')
            self.url_entry.config(foreground='black')
            self.url_is_placeholder = False

    def _on_url_focus_out(self, event):
        if not self.url_var.get().strip():
            self.url_var.set(self.URL_PLACEHOLDER)
            self.url_entry.config(foreground='grey')
            self.url_is_placeholder = True

    def start_attack(self):
        if self.url_is_placeholder:
            messagebox.showwarning("警告", "請輸入目標 URL")
            return
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
        self.status_var.set("掃描中... 封包檢測 → 識別引擎 → 偵測WAF/黑名單過濾 → 搜尋flag/passwd")

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
                detail = "\n模板偵測結果彙總:\n" + "="*60 + "\n"
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
            export_report(fp, self.results_data)
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
