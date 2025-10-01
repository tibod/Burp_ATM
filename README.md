
# Advanced Token Manager (Burp Suite Extension)

**Advanced Token Manager** is a [Burp Suite](https://portswigger.net/burp) extension (written in Jython 2.7) for automatically handling short-lived authentication tokens.  
It can **capture tokens live from traffic** or **load them from local files**, then **replace placeholders** (`__T0__`…`__T9__`) in requests across Burp tools.

This allows you to test APIs that rely on frequently refreshed tokens without manually updating every request.

---

## ✨ Features

- **Token placeholders**  
  Use `__T0__ … __T9__` in requests. They are replaced with live-captured or file-based token values.

- **Multiple sources**  
  - **Live capture:** Regex-based rules extract tokens from Proxy/Repeater/etc.  
  - **File source:** Reads token values from text files (`__Tn__.txt`).  
  - **Optional write-back:** Captured values can be written back to files.

- **Capture vs. Replace controls**  
  You can independently choose in which Burp tools tokens are:  
  - **Captured** (scanned and updated live),  
  - **Replaced** (placeholders substituted in outgoing requests).

- **Flexible regex + URL filtering**  
  - Each placeholder can have its own regex and an optional full-URL filter.  
  - The first capture group becomes the token value.

- **JWT expiration awareness**  
  - If the token looks like a JWT, the `exp` claim is parsed.  
  - Expiry is displayed in the table and color-highlighted (red = expired, orange/yellow = near expiry).

- **Auto-persistence**  
  - Settings and table column ratios are stored in `AdvancedTokenManager.conf` (JSON).  
  - Reloads automatically on startup.

- **UI improvements**  
  - Two tabs: **Settings** (configuration, tokens table) and **Log** (recent activity).  
  - Tokens table columns: `Token`, `Regex`, `URL Filter`, `Updated`, `Hash`, `Source`, `Expires`, `Current Value`.  
  - Column widths are remembered between sessions.  
  - Manual editing of token values possible in the table.  
  - Tab title briefly flashes when a new token is captured.

- **Timezone offset**  
  - Configure GMT/UTC offset for displaying timestamps and expiration times.

---

## 🛠 Installation

1. Install **Burp Suite Professional or Community**.
2. Install **Jython 2.7**:  
   - Download `jython-standalone-2.7.x.jar` from the [official Jython releases](https://www.jython.org/download).  
   - In Burp: `Extender → Options → Python Environment → Select File` → choose the JAR.
3. Clone or download this repository.
4. In Burp: `Extender → Extensions → Add`  
   - Type: **Python**  
   - File: `AdvancedTokenManager.py`
5. A new tab **“Advanced Token Manager”** will appear.

---

## ⚙️ Configuration

### Settings Tab

- **Tokens directory** – path containing `__Tn__.txt` files.  
- **Read tokens from files** – enable/disable using values from files.  
- **File read interval (s)** – how often to refresh from disk.  
- **Write captured tokens to files** – persist live-captured values.  
- **Local time GMT offset** – hours offset (e.g., `+2`, `-6`, `1.5`).  
- **Replace tokens in** – checkboxes per tool (Proxy, Repeater, Intruder, Scanner, Target, Sequencer, Extender).  
- **Live search tokens in** – checkboxes per tool for capture.  
- **Tokens table** – edit regex rules, URL filters, or current values manually.  
- **Config file** – shows where `AdvancedTokenManager.conf` is stored.

### Log Tab

- Shows log lines (captures, replacements, file reloads, errors).

---

## 🔍 Example Workflow

1. Add a rule:  
   ```
   __T0__   Regex: ^Authorization:\s*Bearer\s+(.*?)$
   URL: .*
   ```
2. Log in through a proxied browser session.  
   The extension captures the bearer token into `__T0__`.  
3. Use `__T0__` as placeholder in Intruder/Repeater:  
   ```
   Authorization: Bearer __T0__
   ```
   is automatically replaced with the live token.

---

## 📁 Config File Example

```json
{
  "dir": "/home/user/tokens",
  "interval": 60,
  "enable_files": true,
  "write_files": false,
  "gmt_offset": "+2",
  "replace_tools": {
    "proxy": true,
    "repeater": true,
    "intruder": true,
    "scanner": true,
    "target": false,
    "sequencer": false,
    "extender": true
  },
  "capture_tools": {
    "proxy": true,
    "repeater": true,
    "intruder": true,
    "scanner": true,
    "target": false,
    "sequencer": false,
    "extender": true
  },
  "rules": {
    "__T0__": {
      "regex": "^Authorization:\\s*Bearer\\s+(.*?)$",
      "url_filter": ".*"
    }
  },
  "table_column_ratios": [0.1, 0.4, 0.2, 0.1, 0.05, 0.05, 0.1]
}
```

---

## 🚧 Notes / Limitations

- Requires **Jython 2.7**.  
- Works only on HTTP requests (not WebSockets).  
- Regex matching is done on the full raw request (headers + body).  
- Placeholders must match the `__Tn__` format.  
- Only 10 placeholders (`__T0__`…`__T9__`) are available.
