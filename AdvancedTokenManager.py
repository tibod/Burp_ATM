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

try:
    BASE_DIR = os.path.dirname(__file__)
except:
    BASE_DIR = os.getcwd()
    
EXTENSION_NAME = "Advanced Token Manager"
CONF_FILE = os.path.join(BASE_DIR, "AdvancedTokenManager.conf")
PLACEHOLDER_REGEX = re.compile(r'__T(\d+)__')
PLACEHOLDER_EXACT = re.compile(r'^__T\d+__$')
EXT_LOG = None
    
def set_gmt_offset(value):
    """Sets the GMT/UTC hour offset used to render timestamps."""
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
    """Returns the currently configured GMT/UTC hour offset."""
    try:
        return float(GMT_OFFSET_HOURS)
    except:
        return 0.0

def bool_from(obj, default=False):
    """Converts a truthy string or object to a boolean value."""
    try:
        s = str(obj).strip().lower()
        return s in ("1", "true", "yes", "on")
    except:
        return default

def fmt_ts(ts):
    """Formats a UNIX timestamp (seconds or milliseconds) using the GMT offset."""
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
    """Returns the first 10 characters of the SHA-256 hash of the input text."""
    if s == "":
        return ""
        
    try:
        return hashlib.sha256((s or "").encode('utf-8')).hexdigest()[:10]
    except:
        return "??????????"

def _try_log(msg):
    """Writes a message to the extension log if a logger is available."""
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
    """Decodes URL-safe Base64 input and returns a UTF-8 string."""
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
    """Extracts the core JWT token in the form header.payload.signature."""
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
    """Decodes a JWT payload into a Python dictionary."""
    core = _extract_jwt_core(token)
    if not core:
        return None
    try:
        parts = core.split('.')
        if len(parts) != 3: return None
        header_b64, payload_b64 = parts[0], parts[1]
        _ = json.loads(_b64url_to_text(header_b64))
        try:
            obj = json.loads(_b64url_to_text(payload_b64))
            return obj
        except Exception:
            return None
    except Exception:
        return None

def jwt_exp_str(token):
    """Returns the JWT expiration time formatted as a local timestamp."""
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

class TokenCache(object):
    """Caches token values in memory, backed by a directory of text files."""
    
    def __init__(self, base_dir, refresh_interval_sec=60, logger=None):
        """Internal helper function __init__."""
        self.base_dir = base_dir
        self.refresh_interval = max(1, int(refresh_interval_sec))
        self.cache = {}
        self._logger = logger

    def set_base_dir(self, base_dir): self.base_dir = base_dir
    """Sets base dir."""
    
    def set_refresh_interval(self, sec): self.refresh_interval = max(1, int(sec))
    """Sets refresh interval."""
    
    def _log(self, msg):
        """Internal helper function _log."""
        if self._logger: self._logger(msg)
        
    def _file_path(self, placeholder):
        """Internal helper function _file_path."""
        return os.path.join(self.base_dir, placeholder + ".txt")
        
    def _load_file(self, path):
        """Internal helper function _load_file."""
        with open(path, 'rb') as f:
            raw = f.read()
        first = raw.splitlines()[0] if raw else b""
        try: return first.decode('utf-8').strip()
        except: return first.decode('latin-1').strip()
        
    def get_value(self, placeholder):
        """Gets value."""
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
        """Gets value and mtime."""
        val = self.get_value(placeholder)
        if val is None: return None, None
        try:
            mtime = self.cache.get(placeholder, {}).get('mtime', None)
        except:
            mtime = None
        return val, mtime
        
    def write_value(self, placeholder, value):
        """Implements function write_value."""
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

class Rule(object):
    """Represents a live-capture rule with a token regex and optional URL filter."""
    
    def __init__(self, placeholder, regex_str, url_filter_regex=""):
        """Internal helper function __init__."""
        self.placeholder = (placeholder or "").strip()
        self.regex_str = (regex_str or "").strip()
        self.url_filter_regex = (url_filter_regex or "").strip()

        flags = re.MULTILINE | re.DOTALL

        self.pattern = None
        try:
            if self.regex_str:
                self.pattern = re.compile(self.regex_str, flags)
        except Exception:
            self.pattern = None

        try:
            uf = self.url_filter_regex if self.url_filter_regex else ".*"
            self.url_pattern = re.compile(uf)
        except Exception:
            self.url_pattern = re.compile(".*")

    def match(self, text, full_url):
        """Implements function match."""
        try:
            url_s = "" if full_url is None else str(full_url)
        except Exception:
            url_s = full_url or ""
        try:
            if self.url_pattern and not self.url_pattern.search(url_s):
                return None
        except Exception:
            pass

        if not self.pattern:
            return None
        m = self.pattern.search(text or "")
        if not m:
            return None

        try:
            if m.groups():
                return (m.group(1) or "").strip()
            return m.group(0).strip()
        except Exception:
            return m.group(0).strip()

class RulesManager(object):
    """Manages capture rules and stores current token values with metadata."""
    
    def __init__(self, logger=None):
        """Internal helper function __init__."""
        self._logger = logger
        self.rules = []
        self.rules_dict = {}
        self.live_values = {}
        
    def get_live_value(self, placeholder):
        """Zwraca aktualnie znaną wartość dla placeholdera (albo None)."""
        try:
            return (self.live_values.get(placeholder) or {}).get("value")
        except Exception:
            return None

    def get_live_meta(self, placeholder):
        """Zwraca meta-informację: {'value':..., 'ts':..., 'source':...} – zawsze słownik."""
        try:
            meta = self.live_values.get(placeholder)
            if isinstance(meta, dict):
                return meta
        except Exception:
            pass
        return {"value": "", "ts": None, "source": ""}

    def _log(self, msg):
        """Internal helper function _log."""
        if self._logger: self._logger(msg)

    def load_rules_from_dict(self, rules_dict):
        self.rules = []
        self.rules_dict = {}
        if not isinstance(rules_dict, dict):
            self._log("[Rules] Ignoring non-dict rules in config; starting fresh.")
            return

        for k, v in rules_dict.items():
            ph = str(k).strip()
            if not (ph.startswith("__T") and ph.endswith("__")):
                continue
            if isinstance(v, dict):
                rx = (v.get("regex", "") or "").strip()
                uf = (v.get("url_filter", "") or "").strip()
            else:
                rx = (v or "").strip()
                uf = ""
            self.rules_dict[ph] = {"regex": rx, "url_filter": uf}
            self.rules.append(Rule(ph, rx, uf))

    def set_rule(self, placeholder, regex_str=None, url_filter_regex=None):
        entry = self.rules_dict.get(placeholder, {"regex": "", "url_filter": ""})
        if regex_str is not None:
            entry["regex"] = (regex_str or "").strip()
        if url_filter_regex is not None:
            entry["url_filter"] = (url_filter_regex or "").strip()
        self.rules_dict[placeholder] = entry

        found = False
        for i, r in enumerate(self.rules):
            if r.placeholder == placeholder:
                self.rules[i] = Rule(placeholder, entry["regex"], entry["url_filter"])
                found = True
                break
        if not found:
            self.rules.append(Rule(placeholder, entry["regex"], entry["url_filter"]))

    def get_placeholders(self):
        """Gets placeholders."""
        return sorted(set([r.placeholder for r in self.rules] + list(self.rules_dict.keys())))

    def scan_and_update(self, raw_request_text, full_url, tool_name="Unknown"):
        """Implements function scan_and_update."""
        changed = False
        for rule in self.rules:
            val = rule.match(raw_request_text, full_url)
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

class BurpExtender(IBurpExtender, IHttpListener, ITab, IExtensionStateListener):
    """Burp Suite extension implementing UI, HTTP hooks, and settings."""
    def registerExtenderCallbacks(self, callbacks):
        """Implements function registerExtenderCallbacks."""
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

        self._load_settings_from_file()

        self._init_table_rows_with_defaults()

        self.rules_mgr.load_rules_from_dict(self._get_rules_dict_from_table())

        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)
        callbacks.registerExtensionStateListener(self)

        self._log("%s loaded." % EXTENSION_NAME)
        self._log("Placeholders available: __T0__ .. __T9__ (editable Regex/Value in table)")

        self._refresh_tokens_table_values()

    def _build_ui(self):
        """Internal helper function _build_ui."""
        self._suspend_col_resize = False

        self.settingsPanel = JPanel(GridBagLayout())
        self.settingsPanel.setBorder(EmptyBorder(10,10,10,10))
        c = GridBagConstraints()
        c.gridx = 0
        c.weightx = 1.0
        c.insets = Insets(4,4,4,4)
        c.fill = GridBagConstraints.HORIZONTAL
        row = 0

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

        combined.add(JLabel("Local time GMT offset (hrs): "))
        self.gmtOffsetField = JTextField("0", 6)
        self.gmtOffsetField.setToolTipText("Enter hours offset from UTC, e.g. +2, -6, 1.5. Valid range -12 .. +14")
        self._fix_singleline(self.gmtOffsetField)
        combined.add(self.gmtOffsetField)

        c.gridy = row; c.weighty = 0.0; c.fill = GridBagConstraints.HORIZONTAL
        self.settingsPanel.add(combined, c); row += 1

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

        try:
            d1 = lblReplace.getPreferredSize()
            d2 = lblLive.getPreferredSize()
            max_w = max(d1.width, d2.width)
            pref_h = max(d1.height, d2.height)
            dim = Dimension(max_w, pref_h)
            for lab in (lblReplace, lblLive):
                lab.setPreferredSize(dim)
                lab.setMinimumSize(dim)
        except:
            pass

        c.gridy = row; self.settingsPanel.add(row2, c); row += 1
        c.gridy = row; self.settingsPanel.add(row3, c); row += 1
        
        columns = ["Token", "Token regex", "URL filter", "Updated", "Hash", "Source", "Expires", "Current Value"]

        class TokensTableModel(DefaultTableModel):
            """Defines the TokensTableModel class."""
            def __init__(self, columns, rows):
                """Internal helper function __init__."""
                DefaultTableModel.__init__(self, columns, rows)
            def isCellEditable(self, row, col):
                """Implements function isCellEditable."""
                return col in (1, 2, 7)

        self.tokensModel = TokensTableModel(columns, 0)
        self.tokensTable = JTable(self.tokensModel)

        from javax.swing.table import DefaultTableCellRenderer
        from java.awt import Color

        outer = self
        class ExpiresRenderer(DefaultTableCellRenderer):
            """Defines the ExpiresRenderer class."""
            
            def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
                """Implements function getTableCellRendererComponent."""
                comp = DefaultTableCellRenderer.getTableCellRendererComponent(
                    self, table, value, isSelected, hasFocus, row, column
                )
                try:
                    txt = (value or "").strip()
                    bg = None
                    if txt:
                        dt = datetime.strptime(txt, "%Y-%m-%d %H:%M:%S")
                        now = datetime.strptime(fmt_ts(time.time()), "%Y-%m-%d %H:%M:%S")
                        delta = (dt - now).total_seconds()
                        if delta <= 0:
                            bg = Color(255, 128, 128)
                        elif delta <= 5*60:
                            bg = Color(255, 200, 120)
                        elif delta <= 10*60:
                            bg = Color(255, 255, 160)
                    if bg is not None and not isSelected:
                        comp.setForeground(bg)
                    else:
                        if not isSelected:
                            comp.setForeground(table.getForeground())
                except:
                    if not isSelected:
                        comp.setForeground(table.getForeground())
                return comp

        try:
            self.tokensTable.getColumnModel().getColumn(6).setCellRenderer(ExpiresRenderer())
        except:
            pass

        self._suspend_table_events = False

        self._table_listener = self._on_table_edited()
        self.tokensModel.addTableModelListener(self._table_listener)

        self.tokensTable.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS)

        try:
            self.tokensTable.getColumnModel().getColumn(0).setPreferredWidth(90)
            self.tokensTable.getColumnModel().getColumn(1).setPreferredWidth(400)
            self.tokensTable.getColumnModel().getColumn(2).setPreferredWidth(260)
            self.tokensTable.getColumnModel().getColumn(3).setPreferredWidth(135)
            self.tokensTable.getColumnModel().getColumn(4).setPreferredWidth(70)
            self.tokensTable.getColumnModel().getColumn(5).setPreferredWidth(120)
            self.tokensTable.getColumnModel().getColumn(6).setPreferredWidth(135)
            self.tokensTable.getColumnModel().getColumn(7).setPreferredWidth(500)
        except:
            pass

        self.tokensScroll = JScrollPane(self.tokensTable)

        from java.awt.event import ComponentAdapter
        class _ResizeListener(ComponentAdapter):
            """Defines the _ResizeListener class."""
            
            def componentResized(self, e):
                """Implements function componentResized."""
                try:
                    outer._apply_column_widths()
                except Exception as ex:
                    outer._log("[View] resize listener err: %s" % str(ex))

        self.tokensScroll.getViewport().addComponentListener(_ResizeListener())
        self.tokensScroll.addComponentListener(_ResizeListener())

        col_model = self.tokensTable.getColumnModel()
        from javax.swing.event import TableColumnModelListener
        class _TcmListener(TableColumnModelListener):
            """Defines the _TcmListener class."""
            
            def columnAdded(self, e): pass
            """Implements function columnAdded."""
            
            def columnRemoved(self, e): pass
            """Implements function columnRemoved."""
            
            def columnMoved(self, e): pass
            """Implements function columnMoved."""
            
            def columnSelectionChanged(self, e): pass
            """Implements function columnSelectionChanged."""
            
            def columnMarginChanged(self, e):
                """Implements function columnMarginChanged."""
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

        confInfo = JLabel("Config file: %s" % CONF_FILE)
        c.gridy = row; c.weighty = 0.0; c.fill = GridBagConstraints.HORIZONTAL
        self.settingsPanel.add(confInfo, c); row += 1

        self.logArea = JTextArea(18, 100); self.logArea.setEditable(False)
        logScroll = JScrollPane(self.logArea)
        self.logPanel = JPanel(BorderLayout())
        self.logPanel.setBorder(EmptyBorder(10,10,10,10))
        self.logPanel.add(logScroll, BorderLayout.CENTER)

        self.tabbed = JTabbedPane()
        self.tabbed.addTab("Settings", self.settingsPanel)
        self.tabbed.addTab("Log", self.logPanel)

        self._wire_autosave_handlers()

        try:
            self._update_ratios_from_current_widths(save=False)
        except:
            pass

        try:
            t = Timer(10000, lambda e: self._refresh_tokens_table_values())
            t.setRepeats(True); t.start()
            self._timers.append(t)
        except:
            pass
    
    def _apply_column_widths(self):
        """Internal helper function _apply_column_widths."""
        
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

            self.tokensTable.doLayout()
            self.tokensTable.revalidate()
        except Exception as ex:
            self._log("[View] _apply_column_widths error: %s" % str(ex))

    def _update_ratios_from_current_widths(self, save=True):
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
        """Internal helper function _fix_singleline."""
        tf.setMaximumSize(tf.getPreferredSize())

    def _wire_autosave_handlers(self):
        """Internal helper function _wire_autosave_handlers."""
        
        class _ItemHandler(ItemListener):
            """Defines the _ItemHandler class."""
            
            def __init__(self, outer): self.outer = outer
            """Internal helper function __init__."""
            
            def itemStateChanged(self, e): self.outer._auto_save()
            """Implements function itemStateChanged."""
            
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
            """Defines the _ChangeHandler class."""
            
            def __init__(self, outer): self.outer = outer
            """Internal helper function __init__."""
            
            def stateChanged(self, e): self.outer._auto_save()
            """Implements function stateChanged."""
            
        self.refreshSpinner.addChangeListener(_ChangeHandler(self))

        class _FocusHandler(FocusListener):
            """Defines the _FocusHandler class."""
            
            def __init__(self, outer): self.outer = outer
            """Internal helper function __init__."""
            
            def focusGained(self, e): pass
            """Implements function focusGained."""
            
            def focusLost(self, e): self.outer._auto_save()
            """Implements function focusLost."""
            
        fh = _FocusHandler(self)
        self.dirField.addFocusListener(fh)
        try:
            self.gmtOffsetField.addFocusListener(fh)
        except:
            pass

    def _tool_name(self, toolFlag):
        """Internal helper function _tool_name."""
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

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Implements function processHttpMessage."""
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
            try:
                full_url = str(full_url or "")
            except:
                full_url = full_url or ""

            if allow_capture:
                tool_name = self._tool_name(toolFlag)
                if self.rules_mgr.scan_and_update(raw_text, full_url, tool_name):
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

    def getTabCaption(self): return EXTENSION_NAME
    """Implements function getTabCaption."""
    
    def getUiComponent(self): return self.tabbed
    """Implements function getUiComponent."""

    def _auto_save(self):
        """Internal helper function _auto_save."""
        self.file_cache.set_base_dir(self.dirField.getText().strip())
        try:
            self.file_cache.set_refresh_interval(int(self.refreshSpinner.getValue()))
        except:
            pass
        self.rules_mgr.load_rules_from_dict(self._get_rules_dict_from_table())
        self._save_settings_to_file()
        self._refresh_tokens_table_values()

    def _tool_allowed(self, toolFlag, mode):
        """Internal helper function _tool_allowed."""
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
        else:
            if self.cbCProxy.isSelected():     allowed.append(cb.TOOL_PROXY)
            if self.cbCRepeater.isSelected():  allowed.append(cb.TOOL_REPEATER)
            if self.cbCIntruder.isSelected():  allowed.append(cb.TOOL_INTRUDER)
            if self.cbCScanner.isSelected():   allowed.append(cb.TOOL_SCANNER)
            if self.cbCTarget.isSelected():    allowed.append(cb.TOOL_TARGET)
            if self.cbCSequencer.isSelected(): allowed.append(cb.TOOL_SEQUENCER)
            if self.cbCExtender.isSelected():  allowed.append(cb.TOOL_EXTENDER)
        return toolFlag in allowed

    def _replace_in_headers(self, headers):
        """Internal helper function _replace_in_headers."""
        changed = False
        out = ArrayList()
        for h in headers:
            new_h = self._replace_placeholders(h)
            if new_h != h: changed = True
            out.add(new_h)
        return out if changed else None

    def _replace_placeholders(self, s):
        """Internal helper function _replace_placeholders."""
        
        def repl(m):
            """Implements function repl."""
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
        """Internal helper function _update_content_length."""
        out = ArrayList()
        for h in headers:
            if h is not None and h.lower().startswith("content-length:"):
                out.add("Content-Length: %d" % new_len)
            else:
                out.add(h)
        return out

    def _init_table_rows_with_defaults(self):
        """Internal helper function _init_table_rows_with_defaults."""
        self._suspend_table_events = True
        try:
            existing = set()
            for r in range(self.tokensModel.getRowCount()):
                existing.add(self.tokensModel.getValueAt(r, 0))
            for i in range(10):
                ph = "__T%d__" % i
                if ph not in existing:
                    self.tokensModel.addRow([ph, "", "", "", "", "", "", ""])

            rules = getattr(self, "_loaded_rules_dict", {}) or {}
            for r in range(self.tokensModel.getRowCount()):
                ph = str(self.tokensModel.getValueAt(r, 0))
                rv = rules.get(ph, {})
                if isinstance(rv, dict):
                    rx = rv.get("regex", "")
                    uf = rv.get("url_filter", "")
                else:
                    rx = rv or ""
                    uf = ""
                self.tokensModel.setValueAt(rx, r, 1)
                self.tokensModel.setValueAt(uf, r, 2)

            def _table_has_any_regex():
                """Internal helper function _table_has_any_regex."""
                for r in range(self.tokensModel.getRowCount()):
                    rx = str(self.tokensModel.getValueAt(r, 1) or "").strip()
                    if rx:
                        return True
                return False

            if not _table_has_any_regex():
                for r in range(self.tokensModel.getRowCount()):
                    ph = str(self.tokensModel.getValueAt(r, 0))
                    if ph == "__T0__":
                        self.tokensModel.setValueAt(r"^Authorization:\s*Bearer\s+(.*?)$", r, 1)
                        self.tokensModel.setValueAt(r".*", r, 2)
                        break
        finally:
            self._suspend_table_events = False

    def _get_rules_dict_from_table(self):
        """Internal helper function _get_rules_dict_from_table."""
        rules = {}
        for r in range(self.tokensModel.getRowCount()):
            ph = str(self.tokensModel.getValueAt(r, 0)).strip()
            rx = str(self.tokensModel.getValueAt(r, 1) or "").strip()
            uf = str(self.tokensModel.getValueAt(r, 2) or "").strip()
            if ph.startswith("__T") and ph.endswith("__"):
                if rx != "":
                    rules[ph] = {"regex": rx, "url_filter": uf}
        return rules

    def _on_table_edited(self):
        """Internal helper function _on_table_edited."""
        
        outer = self
        class _L(TableModelListener):
            """Defines the _L class."""
            
            def tableChanged(self, e):
                """Implements function tableChanged."""
                try:
                    if getattr(outer, "_suspend_table_events", False):
                        return
                    row = e.getFirstRow()
                    col = e.getColumn()
                    if row < 0 or col < 0:
                        return

                    ph = str(outer.tokensModel.getValueAt(row, 0))

                    if col == 1:
                        rx = str(outer.tokensModel.getValueAt(row, 1) or "")
                        outer.rules_mgr.set_rule(ph, regex_str=rx)
                        outer._log("[Rules] %s.regex := %s" % (ph, rx))
                        outer._auto_save()

                    elif col == 2:
                        uf = str(outer.tokensModel.getValueAt(row, 2) or "")
                        outer.rules_mgr.set_rule(ph, url_filter_regex=uf)
                        outer._log("[Rules] %s.url_filter := %s" % (ph, uf if uf else ".*"))
                        outer._auto_save()

                    elif col == 7:
                        new_val = str(outer.tokensModel.getValueAt(row, 7) or "")
                        prev_meta = outer.rules_mgr.get_live_meta(ph)
                        prev_val = (prev_meta or {}).get("value", "")

                        if new_val != (prev_val or ""):
                            now = time.time()
                            outer.rules_mgr.live_values[ph] = {
                                "value": new_val,
                                "ts": now,
                                "source": "Manual"
                            }
                            exp = jwt_exp_str(new_val or "")
                            outer.tokensModel.setValueAt(exp or "", row, 6)
                            
                            outer._log("[%s] [Manual] Set %s := %s" % (hash10(new_val), ph, new_val))
                            if outer.cbWriteFiles.isSelected() and new_val and not PLACEHOLDER_EXACT.match(new_val):
                                outer.file_cache.write_value(ph, new_val)
                            outer._refresh_tokens_table_values()
                            outer._flash_tab_title()
                        else:
                            outer._log("[Manual] %s unchanged; source/timestamp preserved." % ph)
                except Exception as ex:
                    outer._log("[TableEdit] Error: %s" % str(ex))
        return _L()

    def _refresh_tokens_table_values(self):
        """Internal helper function _refresh_tokens_table_values."""
        self._suspend_table_events = True
        try:
            for r in range(self.tokensModel.getRowCount()):
                ph = str(self.tokensModel.getValueAt(r, 0))
                meta = self.rules_mgr.get_live_meta(ph)
                src = meta.get("source")
                val = meta.get("value")
                ts  = meta.get("ts")
                if not val and self.cbEnableFiles.isSelected():
                    v2, mtime = self.file_cache.get_value_and_mtime(ph)
                    if v2:
                        val = v2
                        ts = mtime or time.time()
                        src = "File"
                exp = jwt_exp_str(val or "")
                h = hash10(val or "")
                self.tokensModel.setValueAt(fmt_ts(ts) if ts else "", r, 3)
                self.tokensModel.setValueAt(h, r, 4)
                self.tokensModel.setValueAt(src or "", r, 5)
                self.tokensModel.setValueAt(exp or "", r, 6)
                current_cell = self.tokensModel.getValueAt(r, 7)
                if not current_cell or current_cell == "" or current_cell == val:
                    self.tokensModel.setValueAt(val or "", r, 7)
        except Exception as ex:
            self._log("[View] Error refreshing tokens table: %s" % str(ex))
        finally:
            self._suspend_table_events = False

    def _save_settings_to_file(self):
        """Internal helper function _save_settings_to_file."""
        data = {
            "dir": self.dirField.getText().strip(),
            "interval": int(self.refreshSpinner.getValue()),
            "enable_files": bool(self.cbEnableFiles.isSelected()),
            "write_files": bool(self.cbWriteFiles.isSelected()),
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
        """Internal helper function _load_settings_from_file."""
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

            rules_val = data.get("rules", {})
            loaded = {}
            if isinstance(rules_val, dict):
                for k, v in rules_val.items():
                    if not (str(k).startswith("__T") and str(k).endswith("__")):
                        continue
                    if isinstance(v, dict):
                        rx = (v.get("regex", "") or "")
                        uf = (v.get("url_filter", "") or "")
                        loaded[str(k)] = {"regex": rx, "url_filter": uf}
                    else:
                        loaded[str(k)] = {"regex": (v or ""), "url_filter": ""}
            else:
                self._log("[Settings] Discarded legacy/non-dict 'rules' from config; will use empty.")
            self._loaded_rules_dict = loaded

            ratios = data.get("table_column_ratios")
            if isinstance(ratios, list) and len(ratios) > 0:
                s = float(sum([float(x) for x in ratios])) or 1.0
                self._col_ratios = [float(x)/s for x in ratios]
            else:
                self._col_ratios = None

            self.file_cache.set_base_dir(self.dirField.getText().strip())
            try:
                self.file_cache.set_refresh_interval(int(self.refreshSpinner.getValue()))
            except:
                pass

            self._log("[Settings] Loaded from conf file")

            try:
                self._apply_column_widths()
            except:
                pass

        except Exception as e:
            self._log("[Settings] Error loading conf: %s" % str(e))

    def _log(self, msg):
        """Internal helper function _log."""
        try:
            ts = fmt_ts(time.time())
            self.logArea.append("[%s] %s\n" % (ts, str(msg)))
            self.logArea.setCaretPosition(self.logArea.getDocument().getLength())
        except Exception as ex:
            print("Log error:", ex)

    def _flash_tab_title(self):
        """Internal helper function _flash_tab_title."""
        try:
            idx = self.tabbed.indexOfComponent(self.settingsPanel)
            if idx < 0: return
            original = EXTENSION_NAME
            blink = EXTENSION_NAME + " • NEW"
            self.tabbed.setTitleAt(idx, blink)
            def _revert(_e):
                """Internal helper function _revert."""
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

    def extensionUnloaded(self):
        """Implements function extensionUnloaded."""
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
