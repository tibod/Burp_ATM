# Advanced Token Manager (Burp Suite Extension)

**Advanced Token Manager** is a [Burp Suite](https://portswigger.net/burp) extension (written in Jython 2.7) that helps penetration testers and developers automatically manage dynamic authentication tokens.  

It allows you to **capture tokens live from proxy traffic** or **load them from local files**, and then **replace placeholders in requests** across Burp tools (Proxy, Repeater, Intruder, etc.).

---

## ✨ Features

- **Placeholder replacement**  
  Use placeholders like `__T1__`, `__T2__`, … in your requests.  
  They are automatically replaced by token values captured live or read from files.

- **Multiple token sources**  
  - **Live capture**: Define regex rules to extract tokens from Proxy traffic.  
  - **File source**: Read token values from text files (`__T1__.txt`, `__T2__.txt`, …).  
  - **Optional write-back**: Captured tokens can be saved into the corresponding files.

- **Per-tool control**  
  Choose where the replacement should apply: Proxy, Repeater, Intruder, Scanner, Target, Sequencer, Extender.

- **Flexible regex rules**  
  Define capture rules such as:  
  ```text
  __T1__ => Authorization:\s*Bearer\s*([^\r\n]+)
  __T2__ => X-Id-Token:\s*([^\r\n]+)
  ```
  Each rule maps a placeholder to a regex. The first capture group becomes the token value.  
  Matching is applied to the *raw request* (headers + body) with **MULTILINE** enabled.  

- **URL filtering**  
  Optionally restrict token capture to requests whose full URL matches a regex.

- **Auto-persistence**  
  All settings are saved automatically into a JSON config file:
  ```
  AdvancedTokenManager.conf
  ```
  located in the same directory as the extension.

- **UI improvements**  
  - Two tabs:  
    - **Settings**: all configuration (directory, checkboxes, regex rules, current token values).  
    - **Log**: recent activity, limited to the last 200 lines.  
  - Tooltips for regex rules.  
  - “Flash” of the tab title when a new token is captured.

---

## 🛠 Installation

1. Ensure you have **Burp Suite Professional or Community** installed.
2. Install **Jython 2.7**:
   - Download `jython-standalone-2.7.x.jar` from the [official Jython releases](https://www.jython.org/download).
   - In Burp Suite:  
     `Extender → Options → Python Environment → Select File` → choose the Jython JAR.
3. Clone or download this repository.
4. In Burp Suite:  
   `Extender → Extensions → Add`  
   - Extension type: **Python**  
   - Extension file: `AdvancedTokenManager.py`
5. After loading, a new tab **“Advanced Token Manager”** will appear.

---

## ⚙️ Configuration

### Settings Tab
1. **Tokens directory**  
   Path to the folder containing `__Tn__.txt` files.  
   Example:  
   ```
   /home/user/tokens/
   ```
2. **Enable file source**  
   Use values from `__Tn__.txt` files.
3. **Refresh interval (s)**  
   How often to reload token files (based on file modification time).
4. **Enable live capture source**  
   Enable regex-based capture from Proxy traffic.
5. **Write captured tokens to files**  
   Persist new tokens into `__Tn__.txt` under the configured directory.
6. **Apply to**  
   Select which Burp tools should apply placeholder replacement.
7. **URL filter regex (full URL)**  
   Optional regex to restrict capture only to certain URLs.
8. **Live-capture rules**  
   One per line, format:  
   ```
   __Tn__ => <regex>
   ```
   The first capture group becomes the placeholder value.
9. **Current tokens (live capture)**  
   Displays the most recently captured values.

### Log Tab
- Shows the last 200 log lines (captures, replacements, reload events, etc.).

---

## 🔍 Example Workflow

1. Configure a rule:  
   ```
   __T1__ => Authorization:\s*Bearer\s*([^\r\n]+)
   ```
2. In your browser, perform a login.  
   The extension sees the request with `Authorization: Bearer <...>` and captures the token into `__T1__`.
3. Use `__T1__` as a placeholder in Repeater or Intruder requests.  
   When the request is sent, the placeholder is replaced with the actual token.  
   Example:  
   ```
   Authorization: Bearer __T1__
   ```
   becomes  
   ```
   Authorization: Bearer eyJraWQiOiJH...
   ```

---

## 📁 Configuration File

`AdvancedTokenManager.conf` is stored in the same directory as the extension.  

It contains:
```json
{
  "dir": "/home/user/tokens",
  "interval": 60,
  "enable_files": true,
  "enable_live": true,
  "write_files": false,
  "rules": "__T1__ => ^Authorization:\\s*Bearer\\s*([^\\r\\n]+)$",
  "url_filter": "",
  "tools": {
    "proxy": true,
    "repeater": true,
    "intruder": true,
    "scanner": true,
    "target": false,
    "sequencer": false,
    "extender": true
  }
}
```

---

## 🚧 Notes / Limitations
- Designed for **Jython 2.7**; not compatible with native CPython or Java.  
- Only works with **HTTP requests** (not WebSockets).  
- Regex matching is on the raw request (headers+body).  
- Placeholders must match the format `__Tn__`.

