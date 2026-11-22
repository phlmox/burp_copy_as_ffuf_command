# -*- coding: utf-8 -*-
# Burp Suite (Jython 2.7) extension: right click a request ->
# Extensions -> Copy as FFUF Command -> pick flags in a popup -> command is copied.
import json
import re

try:
    from burp import IBurpExtender, IContextMenuFactory
except ImportError:  # running outside Burp (tests)
    class IBurpExtender(object):
        pass

    class IContextMenuFactory(object):
        pass

try:
    from javax.swing import (JMenuItem, JDialog, JPanel, JCheckBox, JTextField,
                             JButton, JTextArea, JScrollPane, BorderFactory, JLabel)
    from javax.swing.event import DocumentListener
    from java.awt import (Toolkit, GridBagLayout, GridBagConstraints, Insets,
                          BorderLayout, FlowLayout, Font, Dimension)
    from java.awt.datatransfer import StringSelection
except ImportError:  # running outside Java (tests)
    DocumentListener = object


SETTINGS_KEY = "ffuf_options_v1"

# Headers ffuf sets itself (Host is kept when it contains FUZZ, for vhost fuzzing)
SKIP_HEADERS = set(["host", "content-length", "connection", "accept-encoding", "accept"])

# key, flag, label, default value (None = on/off switch), enabled by default
OPTIONS = [
    ("mc", "-mc", "Match status codes", "200,204,301,302,307,401,403,405,500", False),
    ("fc", "-fc", "Filter status codes", "404", False),
    ("ac", "-ac", "Auto-calibrate filters", None, True),
    ("fs", "-fs", "Filter response size", "", False),
    ("fw", "-fw", "Filter word count", "", False),
    ("fl", "-fl", "Filter line count", "", False),
    ("fr", "-fr", "Filter regex", "", False),
    ("e", "-e", "Extensions", ".php,.html,.txt,.bak,.js,.json", False),
    ("t", "-t", "Threads", "40", False),
    ("rate", "-rate", "Max requests/sec", "50", False),
    ("timeout", "-timeout", "Timeout (seconds)", "10", False),
    ("r", "-r", "Follow redirects", None, False),
    ("recursion", "-recursion", "Recursion depth", "2", False),
    ("ic", "-ic", "Ignore wordlist comments", None, True),
    ("c", "-c", "Colored output", None, True),
    ("v", "-v", "Verbose (full URLs)", None, False),
    ("x", "-x", "Send through proxy", "http://127.0.0.1:8080", False),
    ("replay", "-replay-proxy", "Replay matches to proxy", "http://127.0.0.1:8080", False),
    ("o", "-o", "Save output (JSON)", "ffuf_out.json", False),
    ("extra", "", "Extra raw args", "", False),
    ("w", "-w", "Wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt", True),
]


def default_options():
    return dict((k, [enabled, value if value is not None else ""])
                for k, _f, _l, value, enabled in OPTIONS)


def shell_quote(s):
    """Wrap in bash double quotes, escaping the characters bash still expands."""
    for ch in ("\\", "\"", "$", "`"):
        s = s.replace(ch, "\\" + ch)
    return "\"" + s + "\""


def maybe_quote(s):
    if re.match(r"^[\w.,:/@%+=~-]+$", s):
        return s
    return shell_quote(s)


def parse_request(request_str):
    """Return (method, [(name, value)], body) from a raw HTTP request string."""
    head, _sep, body = request_str.partition("\r\n\r\n")
    lines = head.split("\r\n")
    method = lines[0].split()[0]
    headers = []
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, _sep, value = line.partition(":")
        name = name.strip()
        if name.lower() in SKIP_HEADERS and not (name.lower() == "host" and "FUZZ" in value):
            continue
        headers.append((name, value.strip()))
    return method, headers, body


def build_command(method, url, headers, body, opts):
    parts = ["ffuf", "-u", shell_quote(url)]
    if method != "GET":
        parts += ["-X", method]
    for name, value in headers:
        parts += ["-H", shell_quote("{}: {}".format(name, value))]
    if body:
        parts += ["-d", shell_quote(body)]

    flag_of = dict((k, f) for k, f, _l, _v, _e in OPTIONS)
    is_switch = dict((k, v is None) for k, _f, _l, v, _e in OPTIONS)
    wordlist = None
    for key, _f, _l, _v, _e in OPTIONS:
        enabled, value = opts.get(key, [False, ""])
        value = (value or "").strip()
        if not enabled:
            continue
        if key == "w":
            wordlist = value
        elif key == "extra":
            if value:
                parts.append(value)
        elif is_switch[key]:
            parts.append(flag_of[key])
        elif not value:
            continue  # checked but empty -> nothing to add
        elif key == "recursion":
            parts += ["-recursion", "-recursion-depth", maybe_quote(value)]
        elif key == "o":
            parts += ["-o", maybe_quote(value), "-of", "json"]
        elif key == "fr":
            parts += ["-fr", shell_quote(value)]
        else:
            parts += [flag_of[key], maybe_quote(value)]

    # Wordlist goes last so it is easy to swap; empty means "type it yourself"
    if wordlist:
        parts += ["-w", maybe_quote(wordlist)]
    else:
        parts.append("-w ")
    return " ".join(parts)


class _OnChange(DocumentListener):
    def __init__(self, fn):
        self._fn = fn

    def insertUpdate(self, e):
        self._fn()

    def removeUpdate(self, e):
        self._fn()

    def changedUpdate(self, e):
        self._fn()


class FfufDialog(object):
    def __init__(self, extender, method, url, headers, body):
        self._ext = extender
        self._req = (method, url, headers, body)
        self._rows = {}

        self.dialog = JDialog(None, "Copy as FFUF Command", True)
        self.dialog.setLayout(BorderLayout(8, 8))

        form = JPanel(GridBagLayout())
        form.setBorder(BorderFactory.createEmptyBorder(10, 10, 0, 10))
        c = GridBagConstraints()
        c.insets = Insets(2, 4, 2, 4)
        c.anchor = GridBagConstraints.WEST

        opts = extender.load_options()
        for row, (key, flag, label, default, _e) in enumerate(OPTIONS):
            enabled, value = opts[key]
            text = "{} ({})".format(label, flag) if flag else label
            box = JCheckBox(text, enabled, actionPerformed=lambda _e: self.refresh())
            c.gridx, c.gridy, c.weightx, c.fill = 0, row, 0, GridBagConstraints.NONE
            form.add(box, c)
            field = None
            if default is not None:
                field = JTextField(value, 32)
                field.getDocument().addDocumentListener(_OnChange(self.refresh))
                c.gridx, c.weightx, c.fill = 1, 1, GridBagConstraints.HORIZONTAL
                form.add(field, c)
            self._rows[key] = (box, field)

        self.preview = JTextArea(5, 60)
        self.preview.setLineWrap(True)
        self.preview.setEditable(False)
        self.preview.setFont(Font("Monospaced", Font.PLAIN, 12))
        bottom = JPanel(BorderLayout(4, 4))
        bottom.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10))
        bottom.add(JLabel("Preview:"), BorderLayout.NORTH)
        bottom.add(JScrollPane(self.preview), BorderLayout.CENTER)

        buttons = JPanel(FlowLayout(FlowLayout.RIGHT))
        copy_btn = JButton("Copy", actionPerformed=lambda _e: self.copy())
        buttons.add(JButton("Reset defaults", actionPerformed=lambda _e: self.reset()))
        buttons.add(JButton("Cancel", actionPerformed=lambda _e: self.dialog.dispose()))
        buttons.add(copy_btn)
        bottom.add(buttons, BorderLayout.SOUTH)

        self.dialog.add(JScrollPane(form), BorderLayout.CENTER)
        self.dialog.add(bottom, BorderLayout.SOUTH)
        self.dialog.getRootPane().setDefaultButton(copy_btn)  # Enter = Copy
        self.refresh()
        self.dialog.pack()
        size = self.dialog.getSize()
        self.dialog.setSize(Dimension(size.width, min(size.height, 820)))
        self.dialog.setLocationRelativeTo(None)

    def current_options(self):
        return dict((key, [box.isSelected(), field.getText() if field else ""])
                    for key, (box, field) in self._rows.items())

    def command(self):
        method, url, headers, body = self._req
        return build_command(method, url, headers, body, self.current_options())

    def refresh(self):
        self.preview.setText(self.command())

    def reset(self):
        for key, (enabled, value) in default_options().items():
            box, field = self._rows[key]
            box.setSelected(enabled)
            if field:
                field.setText(value)
        self.refresh()

    def copy(self):
        self._ext.save_options(self.current_options())
        clip = Toolkit.getDefaultToolkit().getSystemClipboard()
        clip.setContents(StringSelection(self.command()), None)
        self.dialog.dispose()

    def show(self):
        self.dialog.setVisible(True)


class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Copy as FFUF Command")
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        items = []
        if invocation.getInvocationContext() == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            items.append(JMenuItem("Copy as FFUF Command",
                                   actionPerformed=lambda _e: self.openDialog(invocation)))
        return items

    def load_options(self):
        opts = default_options()
        saved = self._callbacks.loadExtensionSetting(SETTINGS_KEY)
        if saved:
            try:
                for key, val in json.loads(saved).items():
                    if key in opts:
                        opts[key] = [bool(val[0]), val[1]]
            except (ValueError, TypeError, IndexError):
                pass
        return opts

    def save_options(self, opts):
        self._callbacks.saveExtensionSetting(SETTINGS_KEY, json.dumps(opts))

    def openDialog(self, invocation):
        http = invocation.getSelectedMessages()[0]
        request_str = self._helpers.bytesToString(http.getRequest())
        method, headers, body = parse_request(request_str)
        url = http.getUrl().toString()
        FfufDialog(self, method, url, headers, body).show()
