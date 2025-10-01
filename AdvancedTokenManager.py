# -*- coding: utf-8 -*-
# Advanced Token Manager (Burp Suite, Jython 2.7)
from burp import IBurpExtender, IHttpListener, ITab, IExtensionStateListener
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets, Dimension, FlowLayout
from javax.swing import (JPanel, JLabel, JTextField, JSpinner, SpinnerNumberModel, JCheckBox,
                         JTabbedPane, SwingConstants, Timer, JButton, JTable, JScrollPane, JTextArea, SwingUtilities)
from javax.swing.table import DefaultTableModel
from javax.swing.border import EmptyBorder
from javax.swing.event import ChangeListener, TableModelListener, TableColumnModelListener
from java.util import ArrayList
from java.awt.event import ItemListener, FocusListener, ComponentAdapter

import os, re, time, json, base64, hashlib
from datetime import datetime, timedelta

# ----- Configuration / constants -----
try:
    BASE_DIR = os.path.dirname(__file__)
except:
    BASE_DIR = os.getcwd()
    
EXTENSION_NAME = "Advanced Token Manager"
CONF_FILE = os.path.join(BASE_DIR, "AdvancedTokenManager.conf")
PLACEHOLDER_REGEX = re.compile(r'__T(\d+)__')
PLACEHOLDER_EXACT = re.compile(r'^__T\d+__$')  # guard: do not capture placeholder-like values
EXT_LOG = None
    
def set_gmt_offset(value):
    global GMT_OFFSET_HOURS
    try:
        if value is None or value == "":
            GMT_OFFSET_HOURS = 0.0
            return True
        if isinstance(value, (int, float)):
            val = float(value)
        else:
            s = str(value).strip()
            if s.startswith('+'):
                s2 = s[1:]
            else:
                s2 = s
            try:
                val = float(s2)
                if s.startswith('-'):
                    val = -abs(val)
                elif s.startswith('+'):
                    val = abs(val)
            except Exception:
                return False
        if not (-12.0 <= val <= 14.0):
            return False
        GMT_OFFSET_HOURS = float(val)
        return True
    except Exception:
        return False

def get_gmt_offset():
    try:
        return float(GMT_OFFSET_HOURS)
    except:
        return 0.0

def bool_from(obj, default=False):
    try:
        s = str(obj).strip().lower()
        return s in ("1", "true", "yes", "on")
    except:
        return default

def fmt_ts(ts):
    try:
        try:
            ts_int = int(ts)
        except Exception:
            try:
                ts_int = int(float(ts))
            except Exception:
                return ""
        if ts_int > 10**12:
            ts_int //= 1000
        try:
            utc_dt = datetime.utcfromtimestamp(ts_int)
        except Exception:
            return ""
        try:
            offset_hours = get_gmt_offset()
        except:
            offset_hours = 0.0
        try:
            local_dt = utc_dt + timedelta(hours=float(offset_hours))
            return local_dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return ""
    except Exception:
        return ""

def hash10(s):
    if s == "":
        return ""
        
    try:
        return hashlib.sha256((s or "").encode('utf-8')).hexdigest()[:10]
    except:
        return "??????????"

def _try_log(msg):
    try:
        g = globals().get('log', None)
        if callable(g):
            try:
                g(msg); return
            except: pass
        global EXT_LOG
        if callable(EXT_LOG):
            try:
                EXT_LOG(msg); return
            except: pass
        try:
            print("[ATM DEBUG] %s" % str(msg))
        except: pass
    except: pass

def _b64url_to_text(b64s):
    try:
        s = (b64s or "")
        pad = '=' * ((4 - (len(s) % 4)) % 4)
        try:
            raw = base64.urlsafe_b64decode(s + pad)
        except Exception:
            alt = s.replace('-', '+').replace('_', '/')
            raw = base64.b64decode(alt + pad)
        try:
            return raw.decode('utf-8', 'ignore')
        except Exception:
            return str(raw)
    except Exception:
        raise

def _extract_jwt_core(token):
    try:
        t = (token or "").strip()
        if not t: return None
        if t.lower().startswith("bearer "):
            t = t[7:].strip()
        if len(t) >= 2 and ((t[0] == '{' and t[-1] == '}') or (t[0] == '"' and t[-1] == '"') or (t[0] == "'" and t[-1] == "'")):
            t = t[1:-1].strip()
        m = re.search(r'([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)', t)
        return m.group(1) if m else None
    except Exception:
        return None

def _decode_jwt_payload(token):
    core = _extract_jwt_core(token)
    if not core:
        return None
    try:
        parts = core.split('.')
        if len(parts) != 3: return None
        header_b64, payload_b64 = parts[0], parts[1]
        # header is parsed mainly to validate base64; ignore content
        _ = json.loads(_b64url_to_text(header_b64))
        try:
            obj = json.loads(_b64url_to_text(payload_b64))
            return obj
        except Exception:
            return None
    except Exception:
        return None

def jwt_exp_str(token):
    obj = _decode_jwt_payload(token)
    if not obj: return ""
    exp = obj.get('exp')
    if exp is None: return ""
    try:
        exp_int = int(exp)
    except Exception:
        try:
            exp_int = int(float(exp))
        except Exception:
            return ""
    if exp_int > 10**12:
        exp_int //= 1000
    return fmt_ts(exp_int)

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
    def get_value_and_mtime(self, placeholder):
        val = self.get_value(placeholder)
        if val is None: return None, None
        try:
            mtime = self.cache.get(placeholder, {}).get('mtime', None)
        except:
            mtime = None
        return val, mtime
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
        self.regex_str = (regex_str or "").strip()
        self.pattern = None
        try:
            flags = re.MULTILINE
            if self.regex_str:
                self.pattern = re.compile(self.regex_str, flags)
        except Exception:
            self.pattern = None
    def match(self, text):
        if not self.pattern: return None
        m = self.pattern.search(text)
        if not m: return None
        if m.groups():
            return (m.group(1) or "").strip()
        return m.group(0).strip()

class RulesManager(object):
    def __init__(self, logger=None):
        self._logger = logger
        self.rules = []  # list[Rule]
        self.rules_dict = {}  # {"__T0__": "regex", ...}
        self.live_values = {}  # {"__T0__": {"value":"...", "ts": epoch, "source":"Live|Manual"}}
    def _log(self, msg):
        if self._logger: self._logger(msg)
    def load_rules_from_dict(self, rules_dict):
        self.rules = []
        self.rules_dict = {}
        if isinstance(rules_dict, dict):
            for k, v in rules_dict.items():
                ph = str(k).strip()
                rx = (v or "").strip()
                if ph.startswith("__T") and ph.endswith("__"):
                    self.rules_dict[ph] = rx
                    self.rules.append(Rule(ph, rx))
        else:
            # ignore bad format completely (per requirement)
            self._log("[Rules] Ignoring non-dict rules in config; starting fresh.")
            self.rules_dict = {}
            self.rules = []
    def set_rule(self, placeholder, regex_str):
        self.rules_dict[str(placeholder)] = (regex_str or "")
        # rebuild single rule
        found = False
        for i, r in enumerate(self.rules):
            if r.placeholder == placeholder:
                self.rules[i] = Rule(placeholder, regex_str)
                found = True
                break
        if not found:
            self.rules.append(Rule(placeholder, regex_str))
    def get_placeholders(self):
        phs = sorted(set([r.placeholder for r in self.rules] + list(self.rules_dict.keys())))
        return phs
    def scan_and_update(self, raw_request_text, tool_name="Unknown"):
        changed = False
        for rule in self.rules:
            val = rule.match(raw_request_text)
            if val:
                if PLACEHOLDER_EXACT.match(val):
                    continue
                prev = self.live_values.get(rule.placeholder, {}).get("value")
                if prev != val:
                    now = time.time()
                    self.live_values[rule.placeholder] = {"value": val, "ts": now, "source": tool_name}
                    h10 = hash10(val)
                    self._log("[%s] [Live - %s] %s := %s" % (h10, tool_name, rule.placeholder, val))
                    changed = True
        return changed
    def get_live_value(self, placeholder):
        meta = self.live_values.get(placeholder)
        if meta: return meta.get("value")
        return None
    def get_live_meta(self, placeholder):
        return self.live_values.get(placeholder) or {}

# --------------------- Main Burp extension ---------------------
class BurpExtender(IBurpExtender, IHttpListener, ITab, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName(EXTENSION_NAME)
        self._unloaded = False
        self._timers = []

        self.log_buffer = []
        self.tabbed = JTabbedPane()
        self._build_ui()

        self.file_cache = TokenCache(self.dirField.getText(), int(self.refreshSpinner.getValue()), logger=self._log)
        self.rules_mgr = RulesManager(logger=self._log)

        # Load settings (may include rules dict in new format)
        self._load_settings_from_file()

        # Ensure table has placeholders __T0__..__T9__ (and load regex from config if any)
        self._init_table_rows_with_defaults()

        # Apply loaded rules into RulesManager
        self.rules_mgr.load_rules_from_dict(self._get_rules_dict_from_table())

        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)
        callbacks.registerExtensionStateListener(self)

        self._log("%s loaded." % EXTENSION_NAME)
        self._log("Placeholders available: __T0__ .. __T9__ (editable Regex/Value in table)")

        # Initial refresh of the table values (Updated/Hash/Source/Expires/Current Value)
        self._refresh_tokens_table_values()

    # ---------- UI builders ----------
    def _build_ui(self):
        self._suspend_col_resize = False  # blokada przed zapętleniem przy programowej zmianie szerokości

        self.settingsPanel = JPanel(GridBagLayout())
        self.settingsPanel.setBorder(EmptyBorder(10,10,10,10))
        c = GridBagConstraints()
        c.gridx = 0
        c.weightx = 1.0
        c.insets = Insets(4,4,4,4)
        c.fill = GridBagConstraints.HORIZONTAL
        row = 0

        # --- Combined Row 1
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

        self.cbWriteFiles  = JCheckBox("Write captured tokens to files", False)
        combined.add(self.cbWriteFiles)

        combined.add(JLabel("GMT offset (hrs): "))
        self.gmtOffsetField = JTextField("0", 6)
        self.gmtOffsetField.setToolTipText("Enter hours offset from UTC, e.g. +2, -6, 1.5. Valid range -12 .. +14")
        self._fix_singleline(self.gmtOffsetField)
        combined.add(self.gmtOffsetField)

        c.gridy = row; c.weighty = 0.0; c.fill = GridBagConstraints.HORIZONTAL
        self.settingsPanel.add(combined, c); row += 1

        # --- Row 2: REPLACEMENT tool toggles (z wymuszoną szerokością etykiety)
        row2 = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0))
        lblReplace = JLabel("Replace token in: ")
        row2.add(lblReplace)
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

        # --- Row 3: LIVE CAPTURE tool toggles (z tą samą szerokością etykiety)
        row3 = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0))
        lblLive = JLabel("Live search tokens in: ")
        row3.add(lblLive)
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

        # === Wyrównanie etykiet do identycznej szerokości ===
        try:
            # policz maksymalną preferowaną szerokość
            d1 = lblReplace.getPreferredSize()
            d2 = lblLive.getPreferredSize()
            max_w = max(d1.width, d2.width)
            pref_h = max(d1.height, d2.height)
            dim = Dimension(max_w, pref_h)
            # ustaw identyczny preferred/minimum size
            for lab in (lblReplace, lblLive):
                lab.setPreferredSize(dim)
                lab.setMinimumSize(dim)
                # zapobiega niechcianemu rozciąganiu w FlowLayout (zachowujemy left-align)
        except:
            pass

        c.gridy = row; c.weighty = 0.0; c.fill = GridBagConstraints.HORIZONTAL
        self.settingsPanel.add(row2, c); row += 1
        c.gridy = row; c.weighty = 0.0; c.fill = GridBagConstraints.HORIZONTAL
        self.settingsPanel.add(row3, c); row += 1

        # --- Row 4: URL filter regex
        row4 = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0))
        row4.add(JLabel("URL filter regex (full URL): "))
        tf_cols_url = 30
        self.urlFilterField = JTextField("", tf_cols_url)
        self._fix_singleline(self.urlFilterField)
        row4.add(self.urlFilterField)
        c.gridy = row; c.weighty = 0.0; c.fill = GridBagConstraints.HORIZONTAL
        self.settingsPanel.add(row4, c); row += 1

        # --- Row 5: Tokens table
        columns = ["Placeholder", "Regex", "Updated", "Hash", "Source", "Expires", "Current Value"]

        class TokensTableModel(DefaultTableModel):
            def __init__(self, columns, rows):
                DefaultTableModel.__init__(self, columns, rows)
            def isCellEditable(self, row, col):
                try:
                    return (col == 1 or col == 6)
                except:
                    return False

        self.tokensModel = TokensTableModel(columns, 0)
        self.tokensTable = JTable(self.tokensModel)

        # flaga do wyciszania eventów
        self._suspend_table_events = False

        # table edits listener (jak było)
        self._table_listener = self._on_table_edited()
        self.tokensModel.addTableModelListener(self._table_listener)

        # TRYB: kontrolujemy szerokości sami i zawsze wypełniamy viewport
        self.tokensTable.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS)

        # wstępne preferencje (użyte także do domyślnych ratio, jeśli brak w configu)
        try:
            self.tokensTable.getColumnModel().getColumn(0).setPreferredWidth(90)
            self.tokensTable.getColumnModel().getColumn(1).setPreferredWidth(400)
            self.tokensTable.getColumnModel().getColumn(2).setPreferredWidth(135)
            self.tokensTable.getColumnModel().getColumn(3).setPreferredWidth(70)
            self.tokensTable.getColumnModel().getColumn(4).setPreferredWidth(120)
            self.tokensTable.getColumnModel().getColumn(5).setPreferredWidth(135)
            self.tokensTable.getColumnModel().getColumn(6).setPreferredWidth(500)
        except:
            pass

        # Scroll + dynamiczne dopasowanie
        self.tokensScroll = JScrollPane(self.tokensTable)

        # Listener: zmiana rozmiaru widoku -> zastosuj ratio
        outer = self
        class _ResizeListener(ComponentAdapter):
            def componentResized(self, e):
                try:
                    outer._apply_column_widths()
                except Exception as ex:
                    outer._log("[View] resize listener err: %s" % str(ex))

        self.tokensScroll.getViewport().addComponentListener(_ResizeListener())
        self.tokensScroll.addComponentListener(_ResizeListener())

        # Listener: ręczna zmiana szerokości kolumn -> przelicz ratio i zapisz
        col_model = self.tokensTable.getColumnModel()
        outer = self
        class _TcmListener(TableColumnModelListener):
            def columnAdded(self, e): pass
            def columnRemoved(self, e): pass
            def columnMoved(self, e): pass
            def columnSelectionChanged(self, e): pass
            def columnMarginChanged(self, e):
                try:
                    header = outer.tokensTable.getTableHeader()
                    resizing_col = header.getResizingColumn() if header is not None else None
                    if resizing_col is None:
                        return
                    SwingUtilities.invokeLater(lambda: outer._update_ratios_from_current_widths(save=True))
                except Exception as ex:
                    outer._log("[View] columnMarginChanged err: %s" % str(ex))

        col_model.addColumnModelListener(_TcmListener())

        c.gridy = row; c.weighty = 1.0; c.fill = GridBagConstraints.BOTH
        self.settingsPanel.add(self.tokensScroll, c); row += 1

        # --- Row 6: Config path
        confInfo = JLabel("Config file: %s" % CONF_FILE)
        c.gridy = row; c.weighty = 0.0; c.fill = GridBagConstraints.HORIZONTAL
        self.settingsPanel.add(confInfo, c); row += 1

        # --- Log tab
        self.logArea = JTextArea(18, 100); self.logArea.setEditable(False)
        logScroll = JScrollPane(self.logArea)
        self.logPanel = JPanel(BorderLayout())
        self.logPanel.setBorder(EmptyBorder(10,10,10,10))
        self.logPanel.add(logScroll, BorderLayout.CENTER)

        # --- Tabs
        self.tabbed = JTabbedPane()
        self.tabbed.addTab("Settings", self.settingsPanel)
        self.tabbed.addTab("Log", self.logPanel)

        # autosave handlers
        self._wire_autosave_handlers()

        # Inicjalne ratio: jeśli nie będzie wczytane z configu, policzymy z preferowanych szerokości
        try:
            self._update_ratios_from_current_widths(save=False)
        except:
            pass


    def _apply_column_widths(self):
        try:
            viewport = self.tokensScroll.getViewport()
            if viewport is None:
                return
            total_w = viewport.getExtentSize().width
            if total_w <= 0:
                return

            min_w = 40

            if not getattr(self, "_col_ratios", None):
                self._update_ratios_from_current_widths(save=False)

            col_model = self.tokensTable.getColumnModel()
            cols = col_model.getColumnCount()
            ratios = list(self._col_ratios or [])
            if len(ratios) != cols:
                ratios = (ratios + [0]*(cols - len(ratios)))[:cols]
                s = sum(ratios) or 1.0
                ratios = [r/s for r in ratios]

            widths = [int(total_w * r) for r in ratios]
            diff = total_w - sum(widths)
            if widths:
                widths[-1] = max(min_w, widths[-1] + diff)

            for i in range(cols):
                c = col_model.getColumn(i)
                w = max(min_w, widths[i])
                c.setMinWidth(min_w)
                c.setPreferredWidth(w)

            # bez setPreferredSize(...) – pozwalamy Swingowi dopiąć do prawej krawędzi
            self.tokensTable.doLayout()
            self.tokensTable.revalidate()
        except Exception as ex:
            self._log("[View] _apply_column_widths error: %s" % str(ex))

    def _update_ratios_from_current_widths(self, save=True):
        """
        Przelicz self._col_ratios na podstawie aktualnych szerokości kolumn.
        Wywoływane po ręcznej zmianie szerokości kolumn (drag w headerze).
        """
        try:
            col_model = self.tokensTable.getColumnModel()
            cols = col_model.getColumnCount()
            widths = []
            for i in range(cols):
                widths.append(col_model.getColumn(i).getWidth())
            total = float(sum(widths)) or 1.0
            self._col_ratios = [w / total for w in widths]
            if save:
                self._auto_save()
        except Exception as ex:
            self._log("[View] _update_ratios_from_current_widths error: %s" % str(ex))

    def _fix_singleline(self, tf):
        tf.setMaximumSize(tf.getPreferredSize())

    def _wire_autosave_handlers(self):
        class _ItemHandler(ItemListener):
            def __init__(self, outer): self.outer = outer
            def itemStateChanged(self, e): self.outer._auto_save()
        ih = _ItemHandler(self)
        for cb in [self.cbEnableFiles, self.cbWriteFiles]:
            cb.addItemListener(ih)
        for cb in [self.cbRProxy, self.cbRRepeater, self.cbRIntruder, self.cbRScanner,
                   self.cbRTarget, self.cbRSequencer, self.cbRExtender]:
            cb.addItemListener(ih)
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
        try:
            self.gmtOffsetField.addFocusListener(fh)
        except:
            pass

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
        if getattr(self, "_unloaded", False):
            return
        if not messageIsRequest:
            return

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

            if allow_capture:
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
                        self._refresh_tokens_table_values()
                        if self.cbWriteFiles.isSelected():
                            for ph, meta in self.rules_mgr.live_values.items():
                                val = meta.get("value")
                                if val and not PLACEHOLDER_EXACT.match(val):
                                    self.file_cache.write_value(ph, val)
                        self._flash_tab_title()

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
        # reload rules from table
        self.rules_mgr.load_rules_from_dict(self._get_rules_dict_from_table())
        self._save_settings_to_file()
        self._refresh_tokens_table_values()

    # --- Helpers ---
    def _tool_allowed(self, toolFlag, mode):
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

    # ---------- Table logic ----------
    def _init_table_rows_with_defaults(self):
        self._suspend_table_events = True
        try:
            # ensure rows for __T0__ .. __T9__
            existing = set()
            for r in range(self.tokensModel.getRowCount()):
                existing.add(self.tokensModel.getValueAt(r, 0))
            for i in range(10):
                ph = "__T%d__" % i
                if ph not in existing:
                    self.tokensModel.addRow([ph, "", "", "", "", "", ""])
            # apply any regex from loaded config
            rules = getattr(self, "_loaded_rules_dict", {}) or {}
            for r in range(self.tokensModel.getRowCount()):
                ph = str(self.tokensModel.getValueAt(r, 0))
                rx = rules.get(ph, "")
                self.tokensModel.setValueAt(rx, r, 1)
        finally:
            self._suspend_table_events = False

    def _get_rules_dict_from_table(self):
        rules = {}
        for r in range(self.tokensModel.getRowCount()):
            ph = str(self.tokensModel.getValueAt(r, 0)).strip()
            rx = str(self.tokensModel.getValueAt(r, 1) or "").strip()
            if ph.startswith("__T") and ph.endswith("__"):
                if rx != "":
                    rules[ph] = rx
        return rules

    def _on_table_edited(self):
        outer = self
        class _L(TableModelListener):
            def tableChanged(self, e):
                try:
                    # jeśli trwa programatyczna aktualizacja modelu – ignoruj event
                    if getattr(outer, "_suspend_table_events", False):
                        return

                    row = e.getFirstRow()
                    col = e.getColumn()
                    if row < 0 or col < 0:
                        return

                    ph = str(outer.tokensModel.getValueAt(row, 0))

                    if col == 1:  # Regex edited
                        rx = str(outer.tokensModel.getValueAt(row, 1) or "")
                        outer.rules_mgr.set_rule(ph, rx)
                        outer._log("[Rules] %s := %s" % (ph, rx))
                        outer._auto_save()

                    elif col == 6:  # Current Value edited (manual set)
                        val = str(outer.tokensModel.getValueAt(row, 6) or "")
                        now = time.time()
                        outer.rules_mgr.live_values[ph] = {
                            "value": val,
                            "ts": now,
                            "source": "Manual"
                        }
                        outer._log("[%s] [Manual] Set %s := %s" % (hash10(val), ph, val))
                        if outer.cbWriteFiles.isSelected() and val and not PLACEHOLDER_EXACT.match(val):
                            outer.file_cache.write_value(ph, val)
                        outer._refresh_tokens_table_values()
                        outer._flash_tab_title()

                except Exception as ex:
                    outer._log("[TableEdit] Error: %s" % str(ex))
        return _L()

    def _refresh_tokens_table_values(self):
        # wycisz eventy na czas programatycznych setValueAt(...)
        self._suspend_table_events = True
        try:
            # fill computed columns for every row
            for r in range(self.tokensModel.getRowCount()):
                ph = str(self.tokensModel.getValueAt(r, 0))
                # prefer live
                meta = self.rules_mgr.get_live_meta(ph)
                src = meta.get("source")
                val = meta.get("value")
                ts = meta.get("ts")
                if not val and self.cbEnableFiles.isSelected():
                    v2, mtime = self.file_cache.get_value_and_mtime(ph)
                    if v2:
                        val = v2
                        ts = mtime or time.time()
                        src = "File"
                exp = jwt_exp_str(val or "")
                h = hash10(val or "")
                self.tokensModel.setValueAt(fmt_ts(ts) if ts else "", r, 2)  # Updated
                self.tokensModel.setValueAt(h, r, 3)                         # Hash
                self.tokensModel.setValueAt(src or "", r, 4)                 # Source
                self.tokensModel.setValueAt(exp or "", r, 5)                 # Expires
                # tylko gdy puste lub zgodne z tym co wyświetlamy – nie nadpisuj ręcznych edycji
                current_cell = self.tokensModel.getValueAt(r, 6)
                if not current_cell or current_cell == "" or current_cell == val:
                    self.tokensModel.setValueAt(val or "", r, 6)
        except Exception as ex:
            self._log("[View] Error refreshing tokens table: %s" % str(ex))
        finally:
            self._suspend_table_events = False

    # ----- Settings persistence (JSON file in plugin folder) -----
    def _save_settings_to_file(self):
        data = {
            "dir": self.dirField.getText().strip(),
            "interval": int(self.refreshSpinner.getValue()),
            "enable_files": bool(self.cbEnableFiles.isSelected()),
            "write_files": bool(self.cbWriteFiles.isSelected()),
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
            },
            "gmt_offset": self.gmtOffsetField.getText().strip() if getattr(self, "gmtOffsetField", None) is not None else "",
            "rules": self._get_rules_dict_from_table()
        }

        # NEW: zapisz proporcje kolumn (jeśli policzone)
        try:
            if getattr(self, "_col_ratios", None):
                data["table_column_ratios"] = list(self._col_ratios)
        except:
            pass

        try:
            with open(CONF_FILE, "w") as f:
                f.write(json.dumps(data, indent=2))
        except Exception as e:
            self._log("[Settings] Error writing conf: %s" % str(e))

    def _load_settings_from_file(self):
        self._loaded_rules_dict = {}
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
            self.cbEnableFiles.setSelected(bool_from(data.get("enable_files", True), True))
            self.cbWriteFiles.setSelected(bool_from(data.get("write_files", False), False))

            self.urlFilterField.setText(data.get("url_filter", ""))

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

            try:
                gmt_val = data.get("gmt_offset", None)
                if getattr(self, "gmtOffsetField", None) is not None:
                    if gmt_val is not None:
                        self.gmtOffsetField.setText(str(gmt_val))
                        ok = set_gmt_offset(gmt_val)
                        if not ok:
                            self.gmtOffsetField.setText(str(get_gmt_offset()))
                    else:
                        self.gmtOffsetField.setText(str(get_gmt_offset()))
                else:
                    if gmt_val is not None:
                        set_gmt_offset(gmt_val)
            except Exception as e:
                self._log("[Settings] GMT offset load error: %s" % str(e))

            # RULES
            rules_val = data.get("rules", {})
            if isinstance(rules_val, dict):
                self._loaded_rules_dict = {}
                for k, v in rules_val.items():
                    if str(k).startswith("__T") and str(k).endswith("__"):
                        self._loaded_rules_dict[str(k)] = str(v or "")
            else:
                self._loaded_rules_dict = {}
                self._log("[Settings] Discarded legacy/non-dict 'rules' from config; will use empty.")

            # NEW: wczytaj proporcje kolumn (opcjonalnie)
            ratios = data.get("table_column_ratios")
            if isinstance(ratios, list) and len(ratios) > 0:
                s = float(sum([float(x) for x in ratios])) or 1.0
                self._col_ratios = [float(x)/s for x in ratios]
            else:
                # jeśli brak – policz później z aktualnych szerokości
                self._col_ratios = None

            # file cache props
            self.file_cache.set_base_dir(self.dirField.getText().strip())
            try:
                self.file_cache.set_refresh_interval(int(self.refreshSpinner.getValue()))
            except:
                pass

            self._log("[Settings] Loaded from conf file")

            # Po wczytaniu configu i zbudowaniu UI zastosujemy szerokości (gdy viewport będzie gotowy)
            try:
                self._apply_column_widths()
            except:
                pass

        except Exception as e:
            self._log("[Settings] Error loading conf: %s" % str(e))

    def _log(self, msg):
        try:
            ts = fmt_ts(time.time())
            self.logArea.append("[%s] %s\n" % (ts, str(msg)))
            self.logArea.setCaretPosition(self.logArea.getDocument().getLength())
        except Exception as ex:
            print("Log error:", ex)

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
            try:
                self._timers.append(t)
            except:
                pass
        except:
            pass

    # --- IExtensionStateListener ---
    def extensionUnloaded(self):
        try:
            self._unloaded = True
            self._log("Unloading: stopping timers and releasing resources...")
            for t in list(getattr(self, "_timers", [])):
                try:
                    t.stop()
                except:
                    pass
            self._timers = []
        except Exception as e:
            try:
                self._log("Unload error: %s" % str(e))
            except:
                pass
