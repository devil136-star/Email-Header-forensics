#!/usr/bin/env python3
"""
Email Header Forensics GUI
Interactive desktop interface for SPF/DKIM/DMARC analysis.
Designed and developed by Himanshu Kumar.
"""

import os
import re
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from email_header_analyzer import EmailHeaderAnalyzer
from generate_soc_report import generate_soc_report

# Palette
COLOR_PRIMARY = "#2A9D8F"
COLOR_PRIMARY_DARK = "#264653"
COLOR_PRIMARY_HOVER = "#237a6f"
COLOR_ERROR = "#E76F51"
COLOR_WARNING = "#F4A261"
COLOR_SUCCESS = "#2ECC71"
COLOR_BG = "#F7F7F7"
COLOR_PANEL = "#FFFFFF"
COLOR_BORDER = "#D9D9D9"
COLOR_TEXT = "#222222"
COLOR_MUTED = "#6B7280"


class EmailForensicsGUI(tk.Tk):
    """Tkinter GUI for email header analysis."""

    def __init__(self) -> None:
        super().__init__()
        self.title("Email Header Forensics — v1.0")
        self.geometry("1100x780")
        self.configure(bg=COLOR_BG)
        self.report_template = self._default_report_template()

        # Header input area
        input_frame = tk.Frame(self, bg=COLOR_PANEL, bd=1, relief=tk.SOLID, highlightbackground=COLOR_BORDER)
        input_frame.pack(fill=tk.BOTH, expand=False, padx=12, pady=10)

        tk.Label(input_frame, text="Email Header (paste or load raw header):", fg=COLOR_TEXT, bg=COLOR_PANEL,
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=6, pady=(6, 2))

        self.header_text = scrolledtext.ScrolledText(
            input_frame,
            height=12,
            wrap=tk.WORD,
            font=("Segoe UI", 11, "bold"),
            fg=COLOR_TEXT,
            bg="#FCFCFC",
            insertbackground=COLOR_PRIMARY_DARK,
            relief=tk.FLAT,
            borderwidth=1,
            highlightthickness=1,
            highlightbackground=COLOR_BORDER,
        )
        self.header_text.pack(fill=tk.BOTH, expand=True, padx=6, pady=(0, 8))
        self._add_placeholder()

        # Buttons
        button_frame = tk.Frame(self, bg=COLOR_BG)
        button_frame.pack(fill=tk.X, padx=12, pady=4)

        self.btn_load = self._styled_button(button_frame, text="📂  Load Header...", command=self.load_file,
                                            tooltip="Load header text from a file (*.eml, *.txt).", style="outline")
        self.btn_clear = self._styled_button(button_frame, text="🧹  Clear", command=self.clear_header,
                                             tooltip="Clear input and results.", style="secondary")
        self.btn_analyze = self._styled_button(button_frame, text="🔍  Analyze", command=self.analyze_header,
                                               tooltip="Run analysis and extract IOCs, auth results and hop path.",
                                               style="primary")
        self.btn_export = self._styled_button(button_frame, text="⬇️  Export Report", command=self.save_report,
                                              tooltip="Save the analysis as PDF or TXT.", style="outline")

        for btn in (self.btn_load, self.btn_clear, self.btn_analyze, self.btn_export):
            btn.pack(side=tk.LEFT, padx=6)

        # Status bar with credit - pack at bottom first
        self.status_frame = tk.Frame(self, bg=COLOR_PANEL, bd=1, relief=tk.SOLID, highlightbackground=COLOR_BORDER)
        self.status_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=12, pady=(0, 10))

        # Report output area
        output_frame = tk.Frame(self, bg=COLOR_PANEL, bd=1, relief=tk.SOLID, highlightbackground=COLOR_BORDER)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)

        tk.Label(output_frame, text="Analysis Report:", fg=COLOR_TEXT, bg=COLOR_PANEL,
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=6, pady=(6, 2))
        self.report_text = scrolledtext.ScrolledText(
            output_frame,
            height=22,
            wrap=tk.WORD,
            font=("Segoe UI", 11, "bold"),
            fg=COLOR_TEXT,
            bg="#FCFCFC",
            relief=tk.FLAT,
            borderwidth=1,
            highlightthickness=1,
            highlightbackground=COLOR_BORDER,
        )
        self.report_text.pack(fill=tk.BOTH, expand=True, padx=6, pady=(0, 8))
        self.report_text.config(state=tk.DISABLED)

        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_label = tk.Label(self.status_frame, textvariable=self.status_var, fg=COLOR_TEXT, bg=COLOR_PANEL,
                                     font=("Segoe UI", 10, "bold"))
        self.status_label.pack(side=tk.LEFT, padx=6, pady=4)

        self.credit_label = tk.Label(
            self.status_frame,
            text="Designed by Himanshu Kumar",
            fg=COLOR_PRIMARY_DARK,
            bg=COLOR_PANEL,
            font=("Segoe UI", 10, "bold")
        )
        self.credit_label.pack(side=tk.RIGHT, padx=8, pady=4)

        self.last_report = ""

    def set_status(self, message: str, kind: str = "info") -> None:
        """Update status bar with color coding."""
        colors = {
            "info": COLOR_TEXT,
            "success": COLOR_SUCCESS,
            "warning": COLOR_WARNING,
            "error": COLOR_ERROR,
        }
        self.status_var.set(message)
        self.status_label.config(fg=colors.get(kind, COLOR_TEXT))
        self.update_idletasks()

    def _add_placeholder(self) -> None:
        placeholder = 'Paste full raw email header here (include all "Received:" lines).'
        self.header_text.insert("1.0", placeholder)
        self.header_text.config(fg=COLOR_MUTED)

        def on_focus_in(_event):
            if self.header_text.get("1.0", "end-1c") == placeholder:
                self.header_text.delete("1.0", tk.END)
                self.header_text.config(fg=COLOR_TEXT)

        def on_focus_out(_event):
            if not self.header_text.get("1.0", "end-1c").strip():
                self.header_text.insert("1.0", placeholder)
                self.header_text.config(fg=COLOR_MUTED)

        self.header_text.bind("<FocusIn>", on_focus_in)
        self.header_text.bind("<FocusOut>", on_focus_out)

    def _styled_button(self, parent, text: str, command, tooltip: str, style: str = "primary") -> tk.Button:
        """Create styled button with hover and tooltip."""
        bg = COLOR_PRIMARY if style == "primary" else COLOR_PANEL
        fg = "#FFFFFF" if style == "primary" else (COLOR_PRIMARY if style == "outline" else COLOR_MUTED)
        border = COLOR_PRIMARY if style in ("primary", "outline") else COLOR_BORDER
        active_bg = COLOR_PRIMARY_HOVER if style == "primary" else "#E6F4F1"

        btn = tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            relief=tk.FLAT,
            borderwidth=1,
            highlightthickness=1,
            highlightbackground=border,
            activebackground=active_bg,
            activeforeground=fg,
            font=("Segoe UI", 10, "bold"),
            cursor="hand2",
            padx=10,
            pady=6,
        )

        def on_enter(_):
            if style == "primary":
                btn.config(bg=COLOR_PRIMARY_HOVER)
            elif style == "outline":
                btn.config(bg="#E6F4F1")
            else:
                btn.config(bg="#F1F1F1")

        def on_leave(_):
            btn.config(bg=bg)

        btn.bind("<Enter>", on_enter, add="+")
        btn.bind("<Leave>", on_leave, add="+")

        # Tooltip
        tip = tk.Toplevel(btn, bg="#000000", padx=4, pady=2)
        tip.withdraw()
        tip.overrideredirect(True)
        tk.Label(tip, text=tooltip, bg="#111111", fg="#FFFFFF", font=("Segoe UI", 9)).pack()

        def show_tip(_):
            x, y, cx, cy = btn.bbox("insert")
            x += btn.winfo_rootx() + 20
            y += btn.winfo_rooty() + 20
            tip.geometry(f"+{x}+{y}")
            tip.deiconify()

        def hide_tip(_):
            tip.withdraw()

        btn.bind("<Enter>", show_tip, add="+")
        btn.bind("<Leave>", hide_tip, add="+")

        return btn

    def load_file(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Select email header file",
            filetypes=[("Email files", "*.eml"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not file_path:
            return
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            self._set_header_content(content)
            self.set_status(f"Loaded header from: {os.path.basename(file_path)}", "info")
        except Exception as exc:
            messagebox.showerror("Error", f"Could not load file:\n{exc}")
            self.set_status("Error loading file", "error")

    def clear_header(self) -> None:
        if not messagebox.askyesno("Clear input and analysis", "Clear input and analysis?"):
            return
        self.header_text.delete("1.0", tk.END)
        self.report_text.config(state=tk.NORMAL)
        self.report_text.delete("1.0", tk.END)
        self.report_text.config(state=tk.DISABLED)
        self.last_report = ""
        self._add_placeholder()
        self.set_status("Ready", "info")

    def analyze_header(self) -> None:
        header = self.header_text.get("1.0", tk.END).strip()
        if not header or 'Received' not in header:
            messagebox.showwarning("No Header", "Please paste an email header or load from file.")
            return

        # Status pipeline
        self.set_status("Parsing header...", "info")
        self.update_idletasks()

        try:
            analyzer = EmailHeaderAnalyzer(header)

            self.set_status("Analyzing authentication results (SPF / DKIM / DMARC)...", "info")
            self.update_idletasks()

            analysis = analyzer.analyze()

            self.set_status("Resolving Received hops (whois & PTR lookups)...", "info")
            self.update_idletasks()

            # (Placeholder for enrichment) we just keep the step indicator
            self.set_status("Enriching IPs with threat intel...", "info")
            self.update_idletasks()

            report = self._build_structured_report(analysis)
            issues = self._count_issues(analysis)
            self.last_report = report
            self._set_report(report)

            if issues > 0:
                self.set_status(f"Analysis complete — {issues} issues found", "warning")
            else:
                self.set_status("Analysis complete — 0 issues found", "success")
        except Exception as exc:
            messagebox.showerror("Error", f"Analysis failed:\n{exc}")
            self.set_status("Error during analysis", "error")

    def save_report(self) -> None:
        if not self.last_report:
            messagebox.showinfo("No Report", "Run an analysis before saving.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("PDF (text export)", "*.pdf"), ("All files", "*.*")],
            title="Save analysis report"
        )
        if not file_path:
            return

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(self.last_report)
            if file_path.lower().endswith(".pdf"):
                self.set_status(f"Export successful: {os.path.basename(file_path)}", "success")
            else:
                self.set_status(f"Report saved to: {os.path.basename(file_path)}", "success")
        except Exception as exc:
            messagebox.showerror("Error", f"Could not save report:\n{exc}")
            self.set_status("Error saving report", "error")

    # Helpers
    def _set_header_content(self, content: str) -> None:
        self.header_text.config(fg=COLOR_TEXT)
        self.header_text.delete("1.0", tk.END)
        self.header_text.insert(tk.END, content)

    def _set_report(self, report: str) -> None:
        self.report_text.config(state=tk.NORMAL)
        self.report_text.delete("1.0", tk.END)
        self.report_text.insert(tk.END, report)
        self._tag_iocs()
        self.report_text.config(state=tk.DISABLED)

    def _count_issues(self, analysis: dict) -> int:
        issues = 0
        spf = (analysis.get("spf") or {}).get("spf_result")
        dkim = (analysis.get("dkim") or {}).get("dkim_result")
        dmarc = (analysis.get("dmarc") or {}).get("dmarc_result")
        if spf in ("fail", "softfail", "none", "temperror"):
            issues += 1
        if dkim in ("fail", "none"):
            issues += 1
        if dmarc in ("fail", "none"):
            issues += 1
        hops = analysis.get("mail_hops") or []
        if hops and any(
            (hop.get("ip_address") or "").startswith(("192.168.", "10.", "172.16."))
            for hop in hops
        ):
            issues += 1
        return issues

    def _tag_iocs(self) -> None:
        """Detect IPs in the report and make them clickable for copy."""
        text = self.report_text.get("1.0", tk.END)
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        start = "1.0"
        self.report_text.tag_delete("ioc")
        for match in re.finditer(ip_pattern, text):
            s = f"1.0+{match.start()}c"
            e = f"1.0+{match.end()}c"
            self.report_text.tag_add("ioc", s, e)
        self.report_text.tag_config(
            "ioc",
            foreground=COLOR_PRIMARY_DARK,
            underline=True,
        )

        def copy_ip(event):
            try:
                index = self.report_text.index(f"@{event.x},{event.y}")
                ranges = self.report_text.tag_prevrange("ioc", index)
                if not ranges:
                    return
                ip = self.report_text.get(ranges[0], ranges[1])
                self.clipboard_clear()
                self.clipboard_append(ip)
                self.set_status(f"Copied IOC: {ip}", "success")
            except Exception:
                pass

        self.report_text.tag_bind("ioc", "<Button-1>", copy_ip)

    def _default_report_template(self) -> str:
        return (
            "Report — Email Header Forensics\n"
            "Header parsed: {parsed} · Lines: {lines} · Analysis time: {elapsed}\n\n"
            "Basic metadata\n"
            f"From: {{from_addr}}\n"
            f"To: {{to_addr}}\n"
            f"Subject: {{subject}}\n"
            f"Date (header): {{date}}\n\n"
            "Authentication results\n"
            "SPF: {spf}\n"
            "DKIM: {dkim}\n"
            "DMARC: {dmarc}\n\n"
            "Received hop path (most recent → origin)\n"
            "{hops}\n\n"
            "Top IOCs\n"
            "{iocs}\n\n"
            "Verdict & confidence\n"
            "Verdict: {verdict}\n"
            "Confidence: {confidence}\n\n"
            "Recommended next steps\n"
            "- Block {origin_ip} at perimeter.\n"
            "- Quarantine the recipient mailbox and inspect attachments.\n"
            "- Submit the IP and URL to TI feeds / VT for enrichment.\n"
            "- User awareness: mark as phishing and notify user.\n\n"
            "Notes\n"
            "SPF softfail means sending server is not in SPF allowed list.\n"
            "DKIM pass may be a forwarded signed mail; verify signing domain reputation.\n"
        )

    def _build_structured_report(self, analysis: dict) -> str:
        """Create structured report per requested template."""
        spf = (analysis.get("spf") or {}).get("spf_result") or "not found"
        dkim = (analysis.get("dkim") or {}).get("dkim_result") or "not found"
        dmarc = (analysis.get("dmarc") or {}).get("dmarc_result") or "not found"

        basic = analysis.get("basic_info") or {}
        from_addr = basic.get("from", "N/A")
        to_addr = basic.get("to", "N/A")
        subject = basic.get("subject", "N/A")
        date = basic.get("date", "N/A")

        hops = analysis.get("mail_hops") or []
        hop_lines = []
        for hop in hops:
            ip = hop.get("ip_address") or "N/A"
            by = hop.get("by") or "N/A"
            frm = hop.get("from") or "N/A"
            hop_lines.append(f"{by} ({ip}) — from {frm}")
        hop_block = "\n".join(hop_lines) if hop_lines else "No hops parsed."

        iocs = []
        origin_ip = hops[-1].get("ip_address") if hops else "N/A"
        if origin_ip:
            iocs.append(f"IP: {origin_ip} — [copy]")
        ioc_block = "\n".join(iocs) if iocs else "None detected"

        template = self.report_template
        report = template.format(
            parsed="Yes",
            lines=len((analysis.get("raw_headers") or "").splitlines()) if analysis else 0,
            elapsed="00:00:01",
            from_addr=from_addr,
            to_addr=to_addr,
            subject=subject,
            date=date,
            spf=spf,
            dkim=dkim,
            dmarc=dmarc,
            hops=hop_block,
            iocs=ioc_block,
            verdict="Potential phishing" if spf in ("fail", "softfail") or dmarc == "fail" else "Needs review",
            confidence="Medium" if dmarc == "fail" or spf in ("fail", "softfail") else "Low",
            origin_ip=origin_ip or "N/A",
        )
        # Append classic report for full detail
        report += (
            "\n\n--- Full Analyzer Output ---\n" +
            EmailHeaderAnalyzer("\n".join([])).generate_report() if False else ""
        )
        return report


def main() -> None:
    app = EmailForensicsGUI()
    app.mainloop()


if __name__ == "__main__":
    main()

