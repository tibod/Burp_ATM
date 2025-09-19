# -*- coding: utf-8 -*-
# Advanced Token Manager (Burp Suite, Jython 2.7)
#
# UI:
#   - Two tabs:
#       A) "Settings"
#          1) "Tokens directory", "Read tokens from files", "File read interval (s)"
#          2) "Enable live tokens capture", "Write captured tokens to files"
#          3) "Enable plugin for..." with tool checkboxes
#          4) "URL filter regex (full URL)" + text field
#          5) Rules list (tooltip, no visible label) — EXPANDS to fill space
#          6) Current token values (live capture)
#          [Config path shown at the end]
#       B) "Log"
#          - Log (last 200 lines)
#
# Features:
# - Replace placeholders __T1__, __T2__, ... in request headers/body.
# - Value sources: (1) Live capture rules (priority), (2) Files (__Tn__.txt) with caching (fallback).
# - Optional URL filter regex (full URL) gating learning.
# - "Write captured tokens to files" checkbox to persist to __Tn__.txt.
# - Per-tool toggles, persistent JSON conf in plugin folder, log limited to 200 lines.
# - Auto-save on checkbox click and focus-lost of text fields/areas (and spinner changes).
# - Guard: never capture values that look like placeholders (__T\d+__).
# - Flash plugin tab title when a new token is learned.
# - Added separate section "Live search tokens in:" with per-tool toggles
# - Separated tool gating for replacement vs. live-capture
#
from burp import IBurpExtender, IHttpListener, ITab
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets, Dimension
from javax.swing import (JPanel, JLabel, JTextField, JTextArea, JScrollPane,
                         JSpinner, SpinnerNumberModel, JCheckBox, JTabbedPane, SwingConstants, Timer)
from javax.swing.border import EmptyBorder
from java.util import ArrayList
from java.awt.event import ItemListener, FocusListener
from javax.swing.event import ChangeListener
import os, re, time, json

EXTENSION_NAME = "Advanced Token Manager"

# ----- Configuration / constants -----
LOG_MAX_LINES = 200

try:
    BASE_DIR = os.path.dirname(__file__)
except:
    BASE_DIR = os.getcwd()

CONF_FILE = os.path.join(BASE_DIR, "AdvancedTokenManager.conf")

PLACEHOLDER_REGEX = re.compile(r'__T(\d+)__')
PLACEHOLDER_EXACT = re.compile(r'^__T\d+__$')  # guard: do not capture placeholder-like values

RULES_TOOLTIP = (
    "One rule per line, format:\n"
    "__T1__ => Authorization:\\s*Bearer\\s*([^\\r\\n]+)\n"
    "__T2__ => X-Id-Token:\\s*([^\\r\\n]+)\n"
)

DEFAULT_RULES_EXAMPLE = (
    "# __T1__ => Authorization:\\s*Bearer\\s*([^\\r\\n]+)\n"
    "# __T2__ => X-Id-Token:\\s*([^\\r\\n]+)\n"
    "# Add more rules below, one per line: __Tn__ => <your-regex>\n"
)

def bool_from(obj, default=False):
    try:
        s = str(obj).strip().lower()
        return s in ("1", "true", "yes", "on")
    except:
        return default

# --------------------- File cache ---------------------
class TokenCache(object):
    def __init__(self, base_dir, refresh_interval_sec=60, logger=None):
        self.base_dir = base_dir
        self.refresh_interval = max(1, int(refresh_interval_sec))
        self.cache = {}
        self._logger = logger

    def set_base_dir(self, base_dir): self.base_dir = base_dir
    def set_refresh_interval(self, sec): self.refresh_interval = max(1, int(sec))

    def _log(self, msg):
        if self._logger: self._logger(msg)

    def _file_path(self, placeholder):
        return os.path.join(self.base_dir, placeholder + ".txt")

    def _load_file(self, path):
        with open(path, 'rb') as f:
            raw = f.read()
        first = raw.splitlines()[0] if raw else b""
        try: return first.decode('utf-8').strip()
        except: return first.decode('latin-1').strip()

    def get_value(self, placeholder):
        if not self.base_dir or not os.path.isdir(self.base_dir):
            return None
        path = self._file_path(placeholder)
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            return None

        now = time.time()
        entry = self.cache.get(placeholder)
        need = True
        if entry and (now - entry['last_check'] < self.refresh_interval) and (entry['mtime'] == mtime):
            need = False

        if need:
            try:
                val = self._load_file(path)
                self.cache[placeholder] = {'value': val, 'mtime': mtime, 'last_check': now}
                if not entry:
                    self._log("[Files] Loaded %s" % os.path.basename(path))
                elif entry['mtime'] != mtime:
                    self._log("[Files] Reloaded %s (mtime changed)" % os.path.basename(path))
                else:
                    self._log("[Files] Refreshed %s" % os.path.basename(path))
            except Exception as e:
                self._log("[Files] Error reading %s: %s" % (path, str(e)))
                return None
        return self.cache[placeholder]['value']

    def write_value(self, placeholder, value):
        if not self.base_dir or not os.path.isdir(self.base_dir):
            self._log("[Files] Base dir does not exist; cannot write.")
            return False
        path = self._file_path(placeholder)
        try:
            with open(path, 'wb') as f:
                f.write((value or "").encode('utf-8'))
            if placeholder in self.cache:
                del self.cache[placeholder]
            self._log("[Files] Wrote %s" % os.path.basename(path))
            return True
        except Exception as e:
            self._log("[Files] Error writing %s: %s" % (path, str(e)))
            return False

# --------------------- Live capture rules ---------------------
class Rule(object):
    def __init__(self, placeholder, regex_str):
        self.placeholder = placeholder.strip()
        self.regex_str = regex_str.strip()
        self.pattern = None
        try:
            flags = re.MULTILINE  # DOTALL removed; always off
            self.pattern = re.compile(self.regex_str, flags)
        except Exception:
            self.pattern = None

    def match(self, text):
        if not self.pattern: return None
        m = self.pattern.search(text)
        if not m: return None
        if m.groups():
            return m.group(1).strip()
        return m.group(0).strip()

class RulesManager(object):
    def __init__(self, logger=None):
        self._logger = logger
        self.rules = []
        self.live_values = {}

    def _log(self, msg):
        if self._logger: self._logger(msg)

    def load_rules_from_text(self, text):
        self.rules = []
        for line in (text or "").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("=>", 1)
            if len(parts) != 2:
                self._log("[Rules] Ignored bad line (expected '__Tn__ => <regex>'): %s" % line)
                continue
            placeholder = parts[0].strip()
            regex_str = parts[1].strip()
            if not placeholder.startswith("__T") or not placeholder.endswith("__"):
                self._log("[Rules] Ignored (bad placeholder): %s" % line)
                continue
            rule = Rule(placeholder, regex_str)
            if rule.pattern is None:
                self._log("[Rules] Invalid regex, ignored: %s" % regex_str)
            else:
                self.rules.append(rule)

    def scan_and_update(self, raw_request_text, tool_name="Unknown"):
        changed = False
        for rule in self.rules:
            val = rule.match(raw_request_text)
            if val:
                if PLACEHOLDER_EXACT.match(val):
                    continue
                prev = self.live_values.get(rule.placeholder)
                if prev != val:
                    self.live_values[rule.placeholder] = val
                    show = val[:80] + ("..." if len(val) > 80 else "")
                    self._log("[Live - %s] %s := %s" % (tool_name, rule.placeholder, show))
                    changed = True
        return changed

    def get_live_value(self, placeholder):
        return self.live_values.get(placeholder)

    def dump_values(self):
        if not self.live_values:
            return "(no live values yet)"
        lines = []
        keys = sorted(self.live_values.keys())
        for k in keys:
            v = self.live_values[k]
            sample = v if len(v) <= 200 else (v[:200] + " ...")
            lines.append("%s = %s" % (k, sample))
        return "\n".join(lines)

# --------------------- Main Burp extension ---------------------
class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName(EXTENSION_NAME)

        self.log_buffer = []
        self.tabbed = JTabbedPane()
        self._build_ui()

        self.file_cache = TokenCache(self.dirField.getText(), int(self.refreshSpinner.getValue()), logger=self._log)
        self.rules_mgr = RulesManager(logger=self._log)

        self._load_settings_from_file()
        self.rules_mgr.load_rules_from_text(self.rulesArea.getText())

        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)

        self._log("%s loaded." % EXTENSION_NAME)
        self._log("Placeholders: __T1__, __T2__, ... -> files: __T1__.txt, __T2__.txt, ...")

    # ---------- UI builders ----------
    def _build_ui(self):
        from java.awt import GridBagLayout, GridBagConstraints, Insets, FlowLayout, Dimension
        from javax.swing import JPanel, JLabel, JTextField, JTextArea, JScrollPane, JCheckBox, JTabbedPane, SwingConstants
        from javax.swing.border import EmptyBorder

        self.settingsPanel = JPanel(GridBagLayout())
        self.settingsPanel.setBorder(EmptyBorder(10,10,10,10))
        c = GridBagConstraints()
        c.gridx = 0
        c.weightx = 1.0
        c.insets = Insets(4,4,4,4)
        c.fill = GridBagConstraints.HORIZONTAL
        row = 0

        # --- Combined Row 1: Tokens dir + Files on/off + refresh + Live + Write-to-files ---
        combined = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0))

        combined.add(JLabel("Tokens directory: "))
        tf_cols_dir = 28
        self.dirField = JTextField(os.getcwd(), tf_cols_dir)
        self._fix_singleline(self.dirField)
        combined.add(self.dirField)

        self.cbEnableFiles = JCheckBox("Read tokens from files", True)
        combined.add(self.cbEnableFiles)

        combined.add(JLabel("File read interval (s): "))
        self.refreshSpinner = JSpinner(SpinnerNumberModel(60, 1, 3600, 1))
        self.refreshSpinner.setMaximumSize(self.refreshSpinner.getPreferredSize())
        combined.add(self.refreshSpinner)

        spacer = JPanel()
        spacer.setPreferredSize(Dimension(24, 1))
        spacer.setOpaque(False)
        combined.add(spacer)

        self.cbEnableLive  = JCheckBox("Enable live tokens capture", True)
        self.cbWriteFiles  = JCheckBox("Write captured tokens to files", False)
        combined.add(self.cbEnableLive)
        combined.add(self.cbWriteFiles)

        c.gridy = row; c.weighty = 0.0; c.fill = GridBagConstraints.HORIZONTAL
        self.settingsPanel.add(combined, c); row += 1

        # --- Row 2: REPLACEMENT tool toggles ---
        row2 = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0))
        row2.add(JLabel("Replace token in: "))
        self.cbRProxy     = JCheckBox("Proxy", True)
        self.cbRRepeater  = JCheckBox("Repeater", True)
        self.cbRIntruder  = JCheckBox("Intruder", True)
        self.cbRScanner   = JCheckBox("Scanner", True)
        self.cbRTarget    = JCheckBox("Target", False)
        self.cbRSequencer = JCheckBox("Sequencer", False)
        self.cbRExtender  = JCheckBox("Extender", True)
        for cb in [self.cbRProxy, self.cbRRepeater, self.cbRIntruder, self.cbRScanner,
                   self.cbRTarget, self.cbRSequencer, self.cbRExtender]:
            row2.add(cb)
        c.gridy = row; c.weighty = 0.0; c.fill = GridBagConstraints.HORIZONTAL
        self.settingsPanel.add(row2, c); row += 1

        # --- Row 3: LIVE CAPTURE tool toggles ---
        row3 = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0))
        row3.add(JLabel("Live search tokens in: "))
        self.cbCProxy     = JCheckBox("Proxy", True)
        self.cbCRepeater  = JCheckBox("Repeater", True)
        self.cbCIntruder  = JCheckBox("Intruder", True)
        self.cbCScanner   = JCheckBox("Scanner", True)
        self.cbCTarget    = JCheckBox("Target", False)
        self.cbCSequencer = JCheckBox("Sequencer", False)
        self.cbCExtender  = JCheckBox("Extender", True)
        for cb in [self.cbCProxy, self.cbCRepeater, self.cbCIntruder, self.cbCScanner,
                   self.cbCTarget, self.cbCSequencer, self.cbCExtender]:
            row3.add(cb)
        c.gridy = row; c.weighty = 0.0; c.fill = GridBagConstraints.HORIZONTAL
        self.settingsPanel.add(row3, c); row += 1

        # --- Row 4: URL filter regex ---
        row4 = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0))
        row4.add(JLabel("URL filter regex (full URL): "))
        tf_cols_url = 30
        self.urlFilterField = JTextField("", tf_cols_url)
        self._fix_singleline(self.urlFilterField)
        row4.add(self.urlFilterField)
        c.gridy = row; c.weighty = 0.0; c.fill = GridBagConstraints.HORIZONTAL
        self.settingsPanel.add(row4, c); row += 1

        # --- Row 5: Rules textarea ---
        self.rulesArea = JTextArea(16, 92)
        self.rulesArea.setToolTipText(RULES_TOOLTIP)
        self.rulesArea.setLineWrap(True); self.rulesArea.setWrapStyleWord(True)
        self.rulesArea.setText(DEFAULT_RULES_EXAMPLE)

        rulesScroll = JScrollPane(self.rulesArea)
        c.gridy = row; c.weighty = 1.0; c.fill = GridBagConstraints.BOTH
        self.settingsPanel.add(rulesScroll, c); row += 1

        # --- Row 6: Current tokens ---
        row6lbl = JLabel("Current tokens (live capture):")
        row6lbl.setHorizontalAlignment(SwingConstants.LEFT)
        c.gridy = row; c.weighty = 0.0; c.fill = GridBagConstraints.HORIZONTAL
        self.settingsPanel.add(row6lbl, c); row += 1

        self.currentArea = JTextArea(6, 92); self.currentArea.setEditable(False)
        curScroll = JScrollPane(self.currentArea)
        c.gridy = row; c.weighty = 0.0; c.fill = GridBagConstraints.BOTH
        self.settingsPanel.add(curScroll, c); row += 1

        # --- Row 7: Config path info ---
        confInfo = JLabel("Config file: %s" % CONF_FILE)
        c.gridy = row; c.weighty = 0.0; c.fill = GridBagConstraints.HORIZONTAL
        self.settingsPanel.add(confInfo, c); row += 1

        # --- Log tab ---
        self.logArea = JTextArea(18, 100); self.logArea.setEditable(False)
        logScroll = JScrollPane(self.logArea)
        self.logPanel = JPanel(BorderLayout())
        self.logPanel.setBorder(EmptyBorder(10,10,10,10))
        self.logPanel.add(logScroll, BorderLayout.CENTER)

        # --- Tabs ---
        self.tabbed.addTab("Settings", self.settingsPanel)
        self.tabbed.addTab("Log", self.logPanel)

        # wire autosave events
        self._wire_autosave_handlers()

    def _fix_singleline(self, tf):
        tf.setMaximumSize(tf.getPreferredSize())

    def _wire_autosave_handlers(self):
        class _ItemHandler(ItemListener):
            def __init__(self, outer): self.outer = outer
            def itemStateChanged(self, e): self.outer._auto_save()

        ih = _ItemHandler(self)
        # original checkboxes
        for cb in [self.cbEnableFiles, self.cbEnableLive, self.cbWriteFiles]:
            cb.addItemListener(ih)
        # replacement tool toggles
        for cb in [self.cbRProxy, self.cbRRepeater, self.cbRIntruder, self.cbRScanner,
                   self.cbRTarget, self.cbRSequencer, self.cbRExtender]:
            cb.addItemListener(ih)
        # capture tool toggles
        for cb in [self.cbCProxy, self.cbCRepeater, self.cbCIntruder, self.cbCScanner,
                   self.cbCTarget, self.cbCSequencer, self.cbCExtender]:
            cb.addItemListener(ih)

        class _ChangeHandler(ChangeListener):
            def __init__(self, outer): self.outer = outer
            def stateChanged(self, e): self.outer._auto_save()
        self.refreshSpinner.addChangeListener(_ChangeHandler(self))

        class _FocusHandler(FocusListener):
            def __init__(self, outer): self.outer = outer
            def focusGained(self, e): pass
            def focusLost(self, e): self.outer._auto_save()
        fh = _FocusHandler(self)
        self.dirField.addFocusListener(fh)
        self.urlFilterField.addFocusListener(fh)
        self.rulesArea.addFocusListener(fh)
        
    def _tool_name(self, toolFlag):
        cb = self.callbacks
        mapping = {
            cb.TOOL_PROXY: "Proxy",
            cb.TOOL_REPEATER: "Repeater",
            cb.TOOL_INTRUDER: "Intruder",
            cb.TOOL_SCANNER: "Scanner",
            cb.TOOL_TARGET: "Target",
            cb.TOOL_SEQUENCER: "Sequencer",
            cb.TOOL_EXTENDER: "Extender",
        }
        return mapping.get(toolFlag, "Unknown")

    # --- IHttpListener ---
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            return

        # Determine which modes are on for this tool
        allow_replace = self._tool_allowed(toolFlag, "replace")
        allow_capture = self._tool_allowed(toolFlag, "capture")

        if not allow_replace and not allow_capture:
            return

        try:
            req_bytes = messageInfo.getRequest()
            if req_bytes is None: return

            analyzed = self.helpers.analyzeRequest(messageInfo)
            headers = analyzed.getHeaders()
            body_bytes = req_bytes[analyzed.getBodyOffset():]

            headers_text = ""
            for h in headers:
                headers_text += (h + "\r\n")
            body_str = self.helpers.bytesToString(body_bytes)
            raw_text = headers_text + "\r\n" + (body_str or "")

            full_url = ""
            try:
                u = analyzed.getUrl()
                if u is not None:
                    full_url = u.toString()
            except:
                full_url = ""

            # Live capture, gated by URL filter AND per-tool capture setting
            if allow_capture and self.cbEnableLive.isSelected():
                url_ok = True
                url_regex = self.urlFilterField.getText().strip()
                if url_regex:
                    try:
                        if not re.search(url_regex, full_url or ""):
                            url_ok = False
                    except Exception as e:
                        self._log("[URL-Filter] Invalid regex: %s" % str(e))
                        url_ok = True
                if url_ok:
                    tool_name = self._tool_name(toolFlag)
                    if self.rules_mgr.scan_and_update(raw_text, tool_name):
                        self._refresh_current_tokens_view()
                        if self.cbWriteFiles.isSelected():
                            for ph, val in self.rules_mgr.live_values.items():
                                if val and not PLACEHOLDER_EXACT.match(val):
                                    self.file_cache.write_value(ph, val)
                        self._flash_tab_title()

            # Replacement in headers/body (LIVE -> FILES), only if tool is allowed for replacement
            modified_headers = None
            modified_body_str = body_str
            if allow_replace:
                modified_headers = self._replace_in_headers(headers)
                modified_body_str = self._replace_placeholders(body_str)

            changed = (modified_headers is not None) or (modified_body_str != body_str)
            if not changed:
                return

            if modified_headers is None:
                modified_headers = headers

            body_out = self.helpers.stringToBytes(modified_body_str)
            modified_headers = self._update_content_length(modified_headers, len(body_out))
            new_req = self.helpers.buildHttpMessage(modified_headers, body_out)
            messageInfo.setRequest(new_req)

        except Exception as e:
            self._log("[Error] %s" % str(e))

    # --- ITab ---
    def getTabCaption(self): return EXTENSION_NAME
    def getUiComponent(self): return self.tabbed

    # --- Auto-save ---
    def _auto_save(self):
        self.file_cache.set_base_dir(self.dirField.getText().strip())
        try:
            self.file_cache.set_refresh_interval(int(self.refreshSpinner.getValue()))
        except:
            pass
        self.rules_mgr.load_rules_from_text(self.rulesArea.getText())
        self._save_settings_to_file()
        self._refresh_current_tokens_view()

    # --- Helpers ---
    def _tool_allowed(self, toolFlag, mode):
        """
        mode: 'replace' or 'capture'
        """
        cb = self.callbacks
        allowed = []
        if mode == "replace":
            if self.cbRProxy.isSelected():     allowed.append(cb.TOOL_PROXY)
            if self.cbRRepeater.isSelected():  allowed.append(cb.TOOL_REPEATER)
            if self.cbRIntruder.isSelected():  allowed.append(cb.TOOL_INTRUDER)
            if self.cbRScanner.isSelected():   allowed.append(cb.TOOL_SCANNER)
            if self.cbRTarget.isSelected():    allowed.append(cb.TOOL_TARGET)
            if self.cbRSequencer.isSelected(): allowed.append(cb.TOOL_SEQUENCER)
            if self.cbRExtender.isSelected():  allowed.append(cb.TOOL_EXTENDER)
        else:  # capture
            if self.cbCProxy.isSelected():     allowed.append(cb.TOOL_PROXY)
            if self.cbCRepeater.isSelected():  allowed.append(cb.TOOL_REPEATER)
            if self.cbCIntruder.isSelected():  allowed.append(cb.TOOL_INTRUDER)
            if self.cbCScanner.isSelected():   allowed.append(cb.TOOL_SCANNER)
            if self.cbCTarget.isSelected():    allowed.append(cb.TOOL_TARGET)
            if self.cbCSequencer.isSelected(): allowed.append(cb.TOOL_SEQUENCER)
            if self.cbCExtender.isSelected():  allowed.append(cb.TOOL_EXTENDER)
        return toolFlag in allowed

    def _replace_in_headers(self, headers):
        changed = False
        out = ArrayList()
        for h in headers:
            new_h = self._replace_placeholders(h)
            if new_h != h: changed = True
            out.add(new_h)
        return out if changed else None

    def _replace_placeholders(self, s):
        def repl(m):
            ph = "__T%s__" % m.group(1)
            val = None
            if self.cbEnableLive.isSelected():
                val = self.rules_mgr.get_live_value(ph)
            if (val is None or val == "") and self.cbEnableFiles.isSelected():
                val = self.file_cache.get_value(ph)
            if val and not PLACEHOLDER_EXACT.match(val):
                return val
            return ph
        try:
            return PLACEHOLDER_REGEX.sub(repl, s)
        except:
            return s

    def _update_content_length(self, headers, new_len):
        out = ArrayList()
        for h in headers:
            if h is not None and h.lower().startswith("content-length:"):
                out.add("Content-Length: %d" % new_len)
            else:
                out.add(h)
        return out

    def _refresh_current_tokens_view(self):
        try:
            txt = self.rules_mgr.dump_values()
            self.currentArea.setText(txt)
        except:
            pass

    # ----- Settings persistence (JSON file in plugin folder) -----
    def _save_settings_to_file(self):
        data = {
            "dir": self.dirField.getText().strip(),
            "interval": int(self.refreshSpinner.getValue()),
            "enable_files": bool(self.cbEnableFiles.isSelected()),
            "enable_live": bool(self.cbEnableLive.isSelected()),
            "write_files": bool(self.cbWriteFiles.isSelected()),
            "rules": self.rulesArea.getText(),
            "url_filter": self.urlFilterField.getText().strip(),
            "replace_tools": {
                "proxy": bool(self.cbRProxy.isSelected()),
                "repeater": bool(self.cbRRepeater.isSelected()),
                "intruder": bool(self.cbRIntruder.isSelected()),
                "scanner": bool(self.cbRScanner.isSelected()),
                "target": bool(self.cbRTarget.isSelected()),
                "sequencer": bool(self.cbRSequencer.isSelected()),
                "extender": bool(self.cbRExtender.isSelected()),
            },
            "capture_tools": {
                "proxy": bool(self.cbCProxy.isSelected()),
                "repeater": bool(self.cbCRepeater.isSelected()),
                "intruder": bool(self.cbCIntruder.isSelected()),
                "scanner": bool(self.cbCScanner.isSelected()),
                "target": bool(self.cbCTarget.isSelected()),
                "sequencer": bool(self.cbCSequencer.isSelected()),
                "extender": bool(self.cbCExtender.isSelected()),
            }
        }
        try:
            with open(CONF_FILE, "w") as f:
                f.write(json.dumps(data, indent=2))
        except Exception as e:
            self._log("[Settings] Error writing conf: %s" % str(e))

    def _load_settings_from_file(self):
        if not os.path.isfile(CONF_FILE):
            return
        try:
            with open(CONF_FILE, "r") as f:
                data = json.load(f)

            self.dirField.setText(data.get("dir", self.dirField.getText()))
            try:
                self.refreshSpinner.setValue(int(data.get("interval", 60)))
            except:
                pass
            self.cbEnableFiles.setSelected(bool_from(data.get("enable_files", True)))
            self.cbEnableLive.setSelected(bool_from(data.get("enable_live", True)))
            self.cbWriteFiles.setSelected(bool_from(data.get("write_files", False)))
            
            rules_val = data.get("rules", None)
            if rules_val is not None and str(rules_val).strip() != "":
                self.rulesArea.setText(rules_val)
            
            self.urlFilterField.setText(data.get("url_filter", ""))

            # Defaults mirror previous behavior
            rep = data.get("replace_tools", {})
            cap = data.get("capture_tools", {})

            self.cbRProxy.setSelected(bool_from(rep.get("proxy", True), True))
            self.cbRRepeater.setSelected(bool_from(rep.get("repeater", True), True))
            self.cbRIntruder.setSelected(bool_from(rep.get("intruder", True), True))
            self.cbRScanner.setSelected(bool_from(rep.get("scanner", True), True))
            self.cbRTarget.setSelected(bool_from(rep.get("target", False), False))
            self.cbRSequencer.setSelected(bool_from(rep.get("sequencer", False), False))
            self.cbRExtender.setSelected(bool_from(rep.get("extender", True), True))

            self.cbCProxy.setSelected(bool_from(cap.get("proxy", True), True))
            self.cbCRepeater.setSelected(bool_from(cap.get("repeater", True), True))
            self.cbCIntruder.setSelected(bool_from(cap.get("intruder", True), True))
            self.cbCScanner.setSelected(bool_from(cap.get("scanner", True), True))
            self.cbCTarget.setSelected(bool_from(cap.get("target", False), False))
            self.cbCSequencer.setSelected(bool_from(cap.get("sequencer", False), False))
            self.cbCExtender.setSelected(bool_from(cap.get("extender", True), True))

            self.file_cache.set_base_dir(self.dirField.getText().strip())
            self.file_cache.set_refresh_interval(int(self.refreshSpinner.getValue()))
            self.rules_mgr.load_rules_from_text(self.rulesArea.getText())

            self._log("[Settings] Loaded from conf file")
        except Exception as e:
            self._log("[Settings] Error loading conf: %s" % str(e))

    # ----- Central logger (keeps last LOG_MAX_LINES lines) -----
    def _log(self, msg):
        try:
            for line in str(msg).splitlines():
                self.log_buffer.append(line)
        except:
            self.log_buffer.append(str(msg))
        if len(self.log_buffer) > LOG_MAX_LINES:
            self.log_buffer = self.log_buffer[-LOG_MAX_LINES:]
        try:
            self.logArea.setText("\n".join(self.log_buffer))
            self.logArea.setCaretPosition(self.logArea.getDocument().getLength())
        except:
            pass

    # ----- Tab title "flash" when new token learned -----
    def _flash_tab_title(self):
        try:
            idx = self.tabbed.indexOfComponent(self.settingsPanel)
            if idx < 0: return
            original = EXTENSION_NAME
            blink = EXTENSION_NAME + " • NEW"
            self.tabbed.setTitleAt(idx, blink)
            def _revert(_e):
                try: self.tabbed.setTitleAt(idx, original)
                except: pass
            t = Timer(1200, _revert)
            t.setRepeats(False); t.start()
        except:
            pass

