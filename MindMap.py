# -*- coding: utf-8 -*-
#
# Target Mind Map - a Burp Suite extension (Jython 2.7)
#
# A radial, referral-aware mind map of any target.
#
#   * Auto-detects the TARGET from the most common Origin/Referer across traffic.
#   * Attributes every host by REFERRAL, not by name, so a backend on a totally
#     different domain (e.g. we-api.com whose requests carry Origin: bingx.com)
#     is still recognised as part of the target.
#   * Radial layout: target root at centre, domains around it, endpoints as
#     leaves. Auto-spaced so nothing overlaps, scales to hundreds of nodes.
#   * Captures from ALL Burp tools, WebSocket upgrades, and in-flight (response
#     -less) requests; repeated endpoints collapse into one node with a xN badge.
#   * 3D glossy nodes; colour by referral-party / method / status / content-type.
#   * Save / Load a project (.mmap.json) that embeds the full req/resp bytes.
#
# Install: Extender -> Options -> Python Environment -> select the Jython jar,
#          then Extender -> Extensions -> Add -> Python -> this file.
#
from burp import (IBurpExtender, ITab, IContextMenuFactory, IHttpListener,
                  IMessageEditorController)

from javax.swing import (JPanel, JSplitPane, JButton, JCheckBox, JLabel,
                         JTextField, JMenuItem, JFileChooser, JColorChooser,
                         JPopupMenu, JOptionPane, SwingUtilities, JScrollPane,
                         JTextArea, JComboBox, JToolBar, Box, JTree,
                         BorderFactory)
from javax.swing.tree import (DefaultMutableTreeNode, DefaultTreeModel,
                              DefaultTreeCellRenderer, TreeSelectionModel)
from javax.swing.event import TreeSelectionListener
from javax.swing.filechooser import FileNameExtensionFilter
from java.awt import (BorderLayout, Color, Dimension, Font, BasicStroke,
                     RenderingHints, GradientPaint, RadialGradientPaint, Cursor,
                     Point)
from java.awt.event import MouseAdapter, ActionListener, KeyAdapter, KeyEvent
from java.awt.geom import QuadCurve2D
from java.io import File
from java.util import Base64, Random

import json
import math

EXT_NAME = "Target Mind Map"
FILE_EXT = "mmap.json"

# known third-party / tracker / telemetry registrable domains (substring match)
TRACKERS = ["facebook", "tiktok", "bytedance", "google-analytics",
            "googletagmanager", "doubleclick", "googlesyndication", "gstatic",
            "akamai", "cloudflareinsights", "cloudfront", "sentry", "segment",
            "amplitude", "mixpanel", "hotjar", "sc-static", "snapchat",
            "appsflyer", "branch.io", "adjust", "slise", "criteo", "taboola",
            "onesignal", "intercom", "zendesk", "newrelic", "datadog",
            "clarity.ms", "bugsnag", "fullstory", "optimizely",
            # cloud logging / RUM / telemetry infra
            "aliyuncs", "umeng", "alicdn", "sensorsdata", "growingio",
            "logrocket", "nr-data", "datadoghq", "mparticle", "kochava",
            "bugly", "byteoversea", "sgsnssdk", "volces"]

# multi-level public suffixes so a.b.co.uk -> b.co.uk
_TWO = set(["co", "com", "org", "net", "gov", "edu", "ac"])

# party palette (structural / referral)
PARTY = {
    "core":     (212, 175, 55),   # same registrable domain as target - gold
    "backend":  (96, 178, 122),   # referred by target, other domain  - green
    "tracker":  (128, 128, 132),  # known third-party                 - grey
    "external": (96, 118, 150),   # everything else                   - slate
    "root":     (232, 196, 74),
}
METHODC = {
    "GET": (86, 156, 214), "POST": (226, 148, 58), "PUT": (168, 120, 210),
    "DELETE": (212, 88, 88), "PATCH": (200, 158, 70), "WS": (66, 190, 178),
    "HEAD": (120, 140, 160), "OPTIONS": (120, 140, 160),
}
# tester status ring colours (untested draws no ring)
TSTATUS = ["untested", "testing", "interesting", "vuln", "ignored"]
STATUSC = {
    "untested": None, "testing": (86, 156, 214), "interesting": (240, 200, 70),
    "vuln": (235, 70, 70), "ignored": (110, 110, 110),
}
STATUS_LABEL = {"testing": "Mark testing", "interesting": "Mark interesting",
                "vuln": "Mark vulnerable", "ignored": "Mark ignored",
                "untested": "Mark untested"}
# request headers that indicate an authenticated request
AUTH_HEADERS = ["authorization", "cookie", "x-api-key", "x-auth-token",
                "x-access-token", "x-session-token", "api-key", "auth-token"]


def _b64enc(b):
    return None if b is None else Base64.getEncoder().encodeToString(b)


def _b64dec(s):
    return None if s is None else Base64.getDecoder().decode(s)


def registrable(host):
    if not host:
        return ""
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if labels[-2] in _TWO:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _lum(c):
    return (0.299 * c[0] + 0.587 * c[1] + 0.114 * c[2]) / 255.0


def _shift(c, f):
    return (max(0, min(255, int(c[0] * f))),
            max(0, min(255, int(c[1] * f))),
            max(0, min(255, int(c[2] * f))))


class MindNode(object):
    def __init__(self, nid, kind, x, y):
        self.id = nid
        self.kind = kind          # root | domain | req | note
        self.x = float(x)
        self.y = float(y)
        self.color = None         # manual override (r,g,b)
        self.notes = ""
        self.parent = None
        self.pinned = False       # user-dragged -> excluded from auto-layout
        self.collapsed = False    # domain/root: hide children to cut noise
        # attribution
        self.party = "external"   # core | backend | tracker | external
        self.origins = set()      # referral regdomains seen for this host/domain
        # request data
        self.host = ""
        self.regdom = ""
        self.port = 0
        self.https = False
        self.method = ""
        self.path = ""
        self.url = ""
        self.status = ""
        self.ctype = ""           # json|html|js|image|css|ws|other
        self.ws = False
        self.count = 1
        self.tstatus = "untested"  # tester workflow state
        self.authed = False        # request carried an auth header/cookie
        self.request = None
        self.response = None
        self.label = ""
        self._w = 120.0
        self._h = 32.0

    def display(self):
        if self.kind == "root":
            return self.label or "target"
        if self.kind == "domain":
            return self.host or "domain"
        if self.kind == "note":
            return self.label or "topic"
        t = ((self.method or "?") + " " + (self.path or "/"))
        if len(t) > 40:
            t = t[:38] + "..."
        return t

    # colour for the current view mode
    def fill(self, mode):
        if self.color:
            return self.color
        if self.kind == "root":
            return PARTY["root"]
        if self.kind == "domain":
            return PARTY.get(self.party, PARTY["external"])
        if self.kind == "note":
            return (150, 195, 120)
        # req node
        if mode == "method":
            return METHODC.get(self.method, (150, 150, 150))
        if mode == "status":
            s = self.status[:1]
            return {"2": (96, 178, 122), "3": (86, 156, 214),
                    "4": (220, 170, 60), "5": (212, 88, 88)}.get(s, (140, 140, 140))
        if mode == "ctype":
            return {"json": (96, 178, 122), "html": (86, 156, 214),
                    "js": (210, 200, 90), "css": (150, 190, 220),
                    "image": (140, 140, 140), "ws": (66, 190, 178)}.get(
                        self.ctype, (110, 130, 160))
        # party (default)
        return PARTY.get(self.party, PARTY["external"])

    def to_dict(self):
        return {"id": self.id, "kind": self.kind, "x": self.x, "y": self.y,
                "color": list(self.color) if self.color else None,
                "notes": self.notes, "parent": self.parent, "pinned": self.pinned,
                "collapsed": self.collapsed,
                "party": self.party, "origins": list(self.origins),
                "host": self.host, "regdom": self.regdom, "port": self.port,
                "https": self.https, "method": self.method, "path": self.path,
                "url": self.url, "status": self.status, "ctype": self.ctype,
                "ws": self.ws, "count": self.count, "label": self.label,
                "tstatus": self.tstatus, "authed": self.authed,
                "request": _b64enc(self.request),
                "response": _b64enc(self.response)}

    @staticmethod
    def from_dict(d):
        n = MindNode(d["id"], d["kind"], d["x"], d["y"])
        n.color = tuple(d["color"]) if d.get("color") else None
        n.notes = d.get("notes", "") or ""
        n.parent = d.get("parent")
        n.pinned = bool(d.get("pinned"))
        n.collapsed = bool(d.get("collapsed"))
        n.party = d.get("party", "external")
        n.origins = set(d.get("origins", []))
        n.host = d.get("host", "") or ""
        n.regdom = d.get("regdom", "") or ""
        n.port = d.get("port", 0) or 0
        n.https = bool(d.get("https"))
        n.method = d.get("method", "") or ""
        n.path = d.get("path", "") or ""
        n.url = d.get("url", "") or ""
        n.status = d.get("status", "") or ""
        n.ctype = d.get("ctype", "") or ""
        n.ws = bool(d.get("ws"))
        n.count = d.get("count", 1) or 1
        n.tstatus = d.get("tstatus", "untested") or "untested"
        n.authed = bool(d.get("authed"))
        n.label = d.get("label", "") or ""
        n.request = _b64dec(d.get("request"))
        n.response = _b64dec(d.get("response"))
        return n


class Canvas(JPanel):
    def __init__(self, ext):
        self.ext = ext
        self.scale = 0.7
        self.offx = 500.0
        self.offy = 350.0
        self.dragging = None
        self.panning = False
        self.last = None
        self.setBackground(Color(6, 8, 16))
        m = _CanvasMouse(self)
        self.addMouseListener(m)
        self.addMouseMotionListener(m)
        self.addMouseWheelListener(m)

    def w2s(self, wx, wy):
        return (wx * self.scale + self.offx, wy * self.scale + self.offy)

    def s2w(self, sx, sy):
        return ((sx - self.offx) / self.scale, (sy - self.offy) / self.scale)

    def node_at(self, sx, sy):
        wx, wy = self.s2w(sx, sy)
        for n in reversed(self.ext.ordered_nodes()):
            if abs(wx - n.x) <= n._w / 2 and abs(wy - n.y) <= n._h / 2:
                return n
        return None

    def _space(self, g2, w, h):
        # deep-space vertical wash + soft central nebula glow
        g2.setPaint(GradientPaint(0.0, 0.0, Color(12, 16, 32),
                                  0.0, float(h), Color(3, 4, 10)))
        g2.fillRect(0, 0, w, h)
        try:
            neb = RadialGradientPaint(
                Point(int(w * 0.5), int(h * 0.42)), float(max(w, h) * 0.6),
                [0.0, 1.0], [Color(30, 46, 90, 60), Color(30, 46, 90, 0)])
            g2.setPaint(neb)
            g2.fillRect(0, 0, w, h)
        except:
            pass
        # deterministic starfield (screen-space, stable across repaints)
        rnd = Random(1337)
        for i in range(220):
            sx = int(rnd.nextDouble() * w)
            sy = int(rnd.nextDouble() * h)
            b = 90 + int(rnd.nextDouble() * 150)
            r = 1 if rnd.nextDouble() > 0.12 else 2
            g2.setColor(Color(b, b, min(255, b + 25), 200))
            g2.fillOval(sx, sy, r, r)

    def _orbits(self, g2):
        # faint concentric "orbit" rings around each visible target root
        for n in self.ext.nodes.values():
            if n.kind != "root" or self.ext.is_hidden(n):
                continue
            cx, cy = self.w2s(n.x, n.y)
            for rw in (300.0, getattr(n, "_radius", 520.0)):
                rr = rw * self.scale
                g2.setColor(Color(70, 100, 160, 26))
                g2.setStroke(BasicStroke(max(1.0, 1.0 * self.scale)))
                g2.drawOval(int(cx - rr), int(cy - rr), int(rr * 2), int(rr * 2))

    def paintComponent(self, g):
        self.super__paintComponent(g)
        g2 = g.create()
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                            RenderingHints.VALUE_ANTIALIAS_ON)
        self._space(g2, self.getWidth(), self.getHeight())
        self._orbits(g2)
        mode = self.ext.color_mode()
        flt = self.ext.filter_text()
        base_fm = self.getFontMetrics(Font("SansSerif", Font.PLAIN, 12))
        for n in self.ext.nodes.values():
            tw = base_fm.stringWidth(n.display())
            n._w = max(64.0, tw + 26.0)
            n._h = {"root": 46.0, "domain": 38.0}.get(n.kind, 30.0)

        # edges first
        g2.setStroke(BasicStroke(max(1.0, 1.3 * self.scale)))
        for n in self.ext.nodes.values():
            if self.ext.is_hidden(n):
                continue
            if n.parent is not None and n.parent in self.ext.nodes:
                p = self.ext.nodes[n.parent]
                if self.ext.is_hidden(p):
                    continue
                col = (70, 90, 70) if n.party in ("core", "backend") else (66, 66, 72)
                g2.setColor(Color(*col))
                self._edge(g2, p, n, False)
        g2.setColor(Color(180, 110, 180))
        for a, b in self.ext.links:
            if a in self.ext.nodes and b in self.ext.nodes:
                self._edge(g2, self.ext.nodes[a], self.ext.nodes[b], True)

        font = Font("SansSerif", Font.PLAIN, max(9, int(12 * self.scale)))
        g2.setFont(font)
        for n in self.ext.ordered_nodes():
            self._node(g2, n, mode, flt)
        g2.dispose()

    def _edge(self, g2, a, b, dashed):
        ax, ay = self.w2s(a.x, a.y)
        bx, by = self.w2s(b.x, b.y)
        if dashed:
            g2.setStroke(BasicStroke(max(1.0, 1.3 * self.scale),
                         BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND,
                         1.0, [6.0, 6.0], 0.0))
        mx = (ax + bx) / 2
        my = (ay + by) / 2
        g2.draw(QuadCurve2D.Float(ax, ay, mx, my, bx, by))
        if dashed:
            g2.setStroke(BasicStroke(max(1.0, 1.3 * self.scale)))

    def _node(self, g2, n, mode, flt):
        cx, cy = self.w2s(n.x, n.y)
        w = n._w * self.scale
        h = n._h * self.scale
        x = cx - w / 2
        y = cy - h / 2
        arc = h
        base = n.fill(mode)
        dim = self.ext.is_dimmed(n, flt)
        alpha = 70 if dim else 255
        oval = n.kind in ("root", "domain")

        # tester-status ring (untested = none)
        sc = STATUSC.get(n.tstatus) if n.kind == "req" else None
        if sc and not dim:
            g2.setColor(Color(sc[0], sc[1], sc[2], 230))
            g2.setStroke(BasicStroke(max(2.0, 3.0 * self.scale)))
            self._shape(g2, x - 3, y - 3, w + 6, h + 6, arc, oval, False)

        # glow (selected or filter match) - cyan so it never reads as the vuln ring
        glow = (self.ext.selected is n) or (flt and not dim and n.kind == "req")
        if glow:
            gc = (120, 215, 255) if self.ext.selected is n else (90, 200, 255)
            for i, a in ((10, 40), (6, 60), (3, 90)):
                g2.setColor(Color(gc[0], gc[1], gc[2], a))
                self._shape(g2, x - i, y - i, w + 2 * i, h + 2 * i, arc, oval, True)

        # drop shadow
        g2.setColor(Color(0, 0, 0, 70 if not dim else 30))
        self._shape(g2, x + 3, y + 4, w, h, arc, oval, True)

        # glossy gradient body
        top = Color(_shift(base, 1.28)[0], _shift(base, 1.28)[1],
                    _shift(base, 1.28)[2], alpha)
        bot = Color(_shift(base, 0.72)[0], _shift(base, 0.72)[1],
                    _shift(base, 0.72)[2], alpha)
        g2.setPaint(GradientPaint(float(x), float(y), top, float(x), float(y + h), bot))
        self._shape(g2, x, y, w, h, arc, oval, True)
        # border
        g2.setColor(Color(_shift(base, 0.5)[0], _shift(base, 0.5)[1],
                          _shift(base, 0.5)[2], alpha))
        g2.setStroke(BasicStroke(max(1.0, 1.2 * self.scale)))
        self._shape(g2, x, y, w, h, arc, oval, False)

        # label
        fm = g2.getFontMetrics()
        txt = n.display()
        tc = (25, 25, 25) if _lum(base) > 0.6 else (240, 240, 240)
        g2.setColor(Color(tc[0], tc[1], tc[2], alpha))
        g2.drawString(txt, int(cx - fm.stringWidth(txt) / 2),
                      int(cy + fm.getAscent() / 2 - 2))

        # count badge
        if n.kind == "req" and n.count > 1 and self.scale > 0.4:
            bt = "x" + str(n.count)
            g2.setColor(Color(20, 20, 20, alpha))
            bw = fm.stringWidth(bt) + 8
            g2.fillRoundRect(int(x + w - bw), int(y - 6), int(bw), 14, 8, 8)
            g2.setColor(Color(255, 255, 255, alpha))
            g2.drawString(bt, int(x + w - bw + 4), int(y + 5))
        # status badge
        if n.kind == "req" and n.status and self.scale > 0.45:
            g2.setColor(Color(tc[0], tc[1], tc[2], alpha))
            g2.drawString(n.status, int(x + 6), int(y + fm.getAscent() - 2))
        # auth indicator: amber key-dot at the left edge when authenticated
        if n.kind == "req" and n.authed and self.ext.chk_auth.isSelected() \
                and self.scale > 0.4:
            d = max(7, int(9 * self.scale))
            g2.setColor(Color(240, 190, 70, alpha))
            g2.fillOval(int(x - d / 2), int(cy - d / 2), d, d)
            g2.setColor(Color(60, 45, 10, alpha))
            g2.setStroke(BasicStroke(1.0))
            g2.drawOval(int(x - d / 2), int(cy - d / 2), d, d)
        # collapsed-domain badge
        if n.kind in ("domain", "root") and n.collapsed:
            cnt = self.ext.child_count(n) if n.kind == "domain" \
                else sum(1 for d in self.ext.nodes.values()
                         if d.kind == "domain" and d.parent == n.id)
            bt = "+" + str(cnt)
            g2.setColor(Color(40, 40, 40, alpha))
            bw = fm.stringWidth(bt) + 8
            g2.fillRoundRect(int(x + w - bw), int(y + h - 13), int(bw), 14, 8, 8)
            g2.setColor(Color(255, 255, 255, alpha))
            g2.drawString(bt, int(x + w - bw + 4), int(y + h - 2))

    def _shape(self, g2, x, y, w, h, arc, oval, fill):
        x, y, w, h, arc = int(x), int(y), int(w), int(h), int(arc)
        if oval:
            g2.fillOval(x, y, w, h) if fill else g2.drawOval(x, y, w, h)
        else:
            (g2.fillRoundRect if fill else g2.drawRoundRect)(x, y, w, h, arc, arc)


class _CanvasMouse(MouseAdapter):
    def __init__(self, c):
        self.c = c

    def mousePressed(self, e):
        c = self.c
        c.last = (e.getX(), e.getY())
        n = c.node_at(e.getX(), e.getY())
        if e.isPopupTrigger():
            c.ext.show_popup(e, n)
            return
        if n is not None:
            c.ext.select(n)
            c.dragging = n
            c.setCursor(Cursor.getPredefinedCursor(Cursor.MOVE_CURSOR))
        else:
            c.panning = True
            c.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))

    def mouseReleased(self, e):
        c = self.c
        if e.isPopupTrigger():
            c.ext.show_popup(e, c.node_at(e.getX(), e.getY()))
        c.dragging = None
        c.panning = False
        c.setCursor(Cursor.getDefaultCursor())

    def mouseDragged(self, e):
        c = self.c
        if c.last is None:
            return
        dx = e.getX() - c.last[0]
        dy = e.getY() - c.last[1]
        c.last = (e.getX(), e.getY())
        if c.dragging is not None:
            c.dragging.x += dx / c.scale
            c.dragging.y += dy / c.scale
            c.dragging.pinned = True
            c.repaint()
        elif c.panning:
            c.offx += dx
            c.offy += dy
            c.repaint()

    def mouseClicked(self, e):
        n = self.c.node_at(e.getX(), e.getY())
        if n is None:
            return
        if e.getClickCount() == 1 and n.kind in ("domain", "root"):
            self.c.ext.toggle_collapse(n)
        elif e.getClickCount() == 2 and n.kind in ("req", "note"):
            self.c.ext.focus_node(n)

    def mouseWheelMoved(self, e):
        c = self.c
        factor = 0.9 if e.getPreciseWheelRotation() > 0 else 1.1
        wx, wy = c.s2w(e.getX(), e.getY())
        c.scale = max(0.12, min(4.0, c.scale * factor))
        sx, sy = c.w2s(wx, wy)
        c.offx += e.getX() - sx
        c.offy += e.getY() - sy
        c.repaint()


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IHttpListener,
                   IMessageEditorController):

    def registerExtenderCallbacks(self, callbacks):
        self._cb = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(EXT_NAME)

        self.nodes = {}
        self.domain_index = {}     # regdom -> domain node id
        self.req_index = {}        # (host, method, path) -> req node id
        self.links = []
        self.next_id = 1
        self.selected = None
        self.project_file = None
        self.origin_counts = {}    # referrer regdom -> hits (from Origin/Referer)
        self.host_regdoms = set()  # registrable domains we actually captured
        self.roots = {}            # target regdom -> root node id
        self.ext_root_id = None    # shared "other / 3rd-party" root
        self.forced_targets = set()  # user-promoted target regdomains
        self._last_targets = set()
        self._link_src = None

        self._build_ui()
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)

    # ---------- UI ----------
    def _build_ui(self):
        self.root_panel = JPanel(BorderLayout())
        bar = JToolBar()
        bar.setFloatable(False)

        def btn(t, fn):
            b = JButton(t)
            b.addActionListener(_Act(fn))
            bar.add(b)

        btn("New", self.act_new)
        btn("Open", self.act_open)
        btn("Save", self.act_save)
        btn("Save As", self.act_save_as)
        bar.addSeparator()
        btn("Arrange", self.act_arrange)
        btn("Fit", self.act_fit)
        btn("Add topic", self.act_add_topic)
        btn("Delete", self.act_delete)
        btn("Link", self.act_link)
        bar.addSeparator()
        self.chk_auto = JCheckBox("Auto-capture", True)
        bar.add(self.chk_auto)
        self.chk_arrange = JCheckBox("Auto-arrange", True)
        bar.add(self.chk_arrange)
        bar.add(JLabel(" 3rd-party: "))
        self.cmb_tp = JComboBox(["show", "dim", "hide"])
        self.cmb_tp.setSelectedIndex(1)
        self.cmb_tp.setMaximumSize(Dimension(80, 26))
        self.cmb_tp.addActionListener(_Act(self._refresh_views))
        bar.add(self.cmb_tp)
        self.chk_focus = JCheckBox("Focus", False)
        self.chk_focus.setToolTipText("Show only the selected node's target cluster")
        self.chk_focus.addActionListener(_Act(self._refresh_views))
        bar.add(self.chk_focus)
        self.chk_auth = JCheckBox("Auth", True)
        self.chk_auth.setToolTipText("Amber dot = request carried auth (token/cookie)")
        self.chk_auth.addActionListener(_Act(self._repaint))
        bar.add(self.chk_auth)
        bar.add(JLabel(" Show: "))
        self.cmb_view = JComboBox(["all", "untested", "flagged", "authed", "no-auth"])
        self.cmb_view.setMaximumSize(Dimension(96, 26))
        self.cmb_view.addActionListener(_Act(self._refresh_views))
        bar.add(self.cmb_view)
        bar.addSeparator()
        bar.add(JLabel(" Colour: "))
        self.cmb_color = JComboBox(["party (referral)", "method", "status", "content-type"])
        self.cmb_color.setMaximumSize(Dimension(150, 26))
        self.cmb_color.addActionListener(_Act(self._refresh_views))
        bar.add(self.cmb_color)
        bar.add(JLabel(" Filter: "))
        self.filter_field = JTextField(12)
        self.filter_field.setMaximumSize(Dimension(160, 26))
        self.filter_field.addKeyListener(_FilterKey(self))
        bar.add(self.filter_field)
        bar.add(Box.createHorizontalGlue())
        self.status_lbl = JLabel(" no project ")
        bar.add(self.status_lbl)

        # ---- PS4-style sidebar: every request, grouped target > domain ----
        self.tree_root = DefaultMutableTreeNode("targets")
        self.tree = JTree(DefaultTreeModel(self.tree_root))
        self.tree.setRootVisible(False)
        self.tree.setShowsRootHandles(True)
        self.tree.setRowHeight(26)
        self.tree.setBackground(Color(16, 18, 28))
        self.tree.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6))
        self.tree.getSelectionModel().setSelectionMode(
            TreeSelectionModel.SINGLE_TREE_SELECTION)
        self.tree.setCellRenderer(_TreeRenderer())
        self.tree.addTreeSelectionListener(_TreeSel(self))
        self._tree_count = -1
        side = JPanel(BorderLayout())
        hdr = JLabel("  MISSION  //  ALL REQUESTS")
        hdr.setForeground(Color(150, 180, 235))
        hdr.setFont(Font("SansSerif", Font.BOLD, 12))
        hdr.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))
        hdr.setOpaque(True)
        hdr.setBackground(Color(12, 14, 22))
        side.add(hdr, BorderLayout.NORTH)
        sp = JScrollPane(self.tree)
        sp.setBorder(BorderFactory.createEmptyBorder())
        side.add(sp, BorderLayout.CENTER)
        side.setPreferredSize(Dimension(280, 100))

        self.canvas = Canvas(self)
        self.req_view = self._cb.createMessageEditor(self, False)
        self.resp_view = self._cb.createMessageEditor(self, False)
        rl = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                        self.req_view.getComponent(), self.resp_view.getComponent())
        rl.setResizeWeight(0.5)
        self.notes_area = JTextArea(4, 20)
        self.notes_area.setLineWrap(True)
        self.notes_area.getDocument().addDocumentListener(_notes_listener(self))
        nw = JPanel(BorderLayout())
        nw.add(JLabel(" Node notes:"), BorderLayout.NORTH)
        nw.add(JScrollPane(self.notes_area), BorderLayout.CENTER)
        nw.setPreferredSize(Dimension(300, 120))
        right = JPanel(BorderLayout())
        right.add(rl, BorderLayout.CENTER)
        right.add(nw, BorderLayout.SOUTH)
        cr = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, self.canvas, right)
        cr.setResizeWeight(0.66)
        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, side, cr)
        split.setResizeWeight(0.2)
        self.root_panel.add(bar, BorderLayout.NORTH)
        self.root_panel.add(split, BorderLayout.CENTER)

    def getTabCaption(self):
        return EXT_NAME

    def getUiComponent(self):
        return self.root_panel

    def color_mode(self):
        return ["party", "method", "status", "ctype"][self.cmb_color.getSelectedIndex()]

    def filter_text(self):
        return self.filter_field.getText().strip().lower()

    def _repaint(self):
        self.canvas.repaint()

    def _refresh_views(self):
        self.canvas.repaint()
        self._rebuild_tree()

    def tp_mode(self):
        return ["show", "dim", "hide"][self.cmb_tp.getSelectedIndex()]

    def root_of(self, n):
        if n.kind == "root":
            return n.id
        if n.kind == "domain":
            return n.parent
        if n.kind == "req":
            d = self.nodes.get(n.parent)
            return d.parent if d else None
        return None

    def is_dimmed(self, n, flt):
        if flt:
            hay = (n.display() + " " + n.url + " " + n.host + " " + n.notes).lower()
            if flt not in hay:
                return True
        if self.tp_mode() == "dim" and n.kind in ("req", "domain") \
                and n.party in ("tracker", "external"):
            return True
        v = self.cmb_view.getSelectedItem()
        if v != "all" and n.kind == "req":
            ok = ((v == "untested" and n.tstatus == "untested")
                  or (v == "flagged" and n.tstatus in ("interesting", "vuln"))
                  or (v == "authed" and n.authed)
                  or (v == "no-auth" and not n.authed))
            if not ok:
                return True
        return False

    # ---------- node ordering / visibility ----------
    def _hidden_base(self, n):
        # collapse + hide-3rd-party rules (used by canvas AND sidebar)
        if self.tp_mode() == "hide" and n.kind in ("req", "domain") \
                and n.party in ("tracker", "external"):
            return True
        if n.kind == "root":
            return not any(c.kind == "domain" and c.parent == n.id
                           and not (self.tp_mode() == "hide"
                                    and c.party in ("tracker", "external"))
                           for c in self.nodes.values())
        if n.kind == "domain":
            r = self.nodes.get(n.parent)
            return r is not None and r.collapsed
        if n.kind == "req":
            d = self.nodes.get(n.parent)
            if d is None:
                return False
            if d.collapsed:
                return True
            r = self.nodes.get(d.parent)
            return r is not None and r.collapsed
        return False

    def is_hidden(self, n):
        # focus mode hides other clusters on the CANVAS only
        if self.chk_focus.isSelected() and self.selected is not None \
                and n.kind != "note":
            fr = self.root_of(self.selected)
            if fr is not None and self.root_of(n) != fr:
                return True
        return self._hidden_base(n)

    def child_count(self, dom):
        return sum(1 for c in self.nodes.values()
                   if c.kind == "req" and c.parent == dom.id)

    def ordered_nodes(self):
        out = []
        for k in ("root", "domain", "req", "note"):
            for n in self.nodes.values():
                if n.kind == k and n is not self.selected and not self.is_hidden(n):
                    out.append(n)
        if self.selected is not None and self.selected.id in self.nodes \
                and not self.is_hidden(self.selected):
            out.append(self.selected)
        return out

    def _new_id(self):
        i = self.next_id
        self.next_id += 1
        return i

    # ---------- capture ----------
    def createMenuItems(self, invocation):
        msgs = invocation.getSelectedMessages()
        if not msgs:
            return None
        items = []
        it = JMenuItem("Add to Mind Map (%d)" % len(msgs))
        it.addActionListener(_Act(lambda: self._ctx_add(list(msgs))))
        items.append(it)
        # distinct hosts in the selection -> offer "add whole host from site map"
        svcs = []
        seen = set()
        for m in msgs:
            s = m.getHttpService()
            if s is None:
                continue
            k = (s.getProtocol(), s.getHost(), s.getPort())
            if k not in seen:
                seen.add(k)
                svcs.append(s)
        if svcs:
            if len(svcs) == 1:
                lbl = "Add entire host '%s' from Site map" % svcs[0].getHost()
            else:
                lbl = "Add entire %d hosts from Site map" % len(svcs)
            it2 = JMenuItem(lbl)
            it2.addActionListener(_Act(lambda: self._ctx_add_hosts(svcs)))
            items.append(it2)
        return items

    def _ctx_add(self, msgs):
        data = []
        for m in msgs:
            data.append((m.getHttpService(), m.getRequest(), m.getResponse()))
        self._bulk_ingest(data)

    def _ctx_add_hosts(self, services):
        # pull every site-map entry under each selected host (off the EDT)
        import threading

        def work():
            data = []
            for s in services:
                prefix = "%s://%s" % (s.getProtocol(), s.getHost())
                try:
                    for it in self._cb.getSiteMap(prefix):
                        data.append((it.getHttpService(), it.getRequest(),
                                     it.getResponse()))
                except:
                    pass
            self._bulk_ingest(data)
        threading.Thread(target=work).start()

    def _bulk_ingest(self, data):
        def ui():
            last = None
            struct = False
            for svc, req, resp in data:
                n, s = self.ingest(svc, req, resp, True)
                struct = struct or s
                if n:
                    last = n
            if struct and self.chk_arrange.isSelected():
                self.relayout()
            if last:
                self.select(last)
            self._done_update()
        SwingUtilities.invokeLater(ui)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self.chk_auto.isSelected():
            return
        try:
            svc = messageInfo.getHttpService()
            req = messageInfo.getRequest()
            resp = None if messageIsRequest else messageInfo.getResponse()
        except:
            return
        count_it = bool(messageIsRequest)
        def ui():
            n, struct = self.ingest(svc, req, resp, count_it)
            if struct and self.chk_arrange.isSelected():
                self.relayout()
            self._done_update()
        SwingUtilities.invokeLater(ui)

    def _headers_map(self, headers):
        d = {}
        for h in headers[1:]:
            i = h.find(":")
            if i > 0:
                d[h[:i].strip().lower()] = h[i + 1:].strip()
        return d

    def ingest(self, svc, request, response, count_it):
        """Returns (node, structural_change)."""
        if svc is None or request is None:
            return None, False
        try:
            info = self._helpers.analyzeRequest(svc, request)
            url = info.getUrl()
            method = info.getMethod()
            path = url.getPath() if url else "/"
            full = url.toString() if url else ""
            hdrs = self._headers_map(info.getHeaders())
        except:
            return None, False
        host = svc.getHost()
        regd = registrable(host)
        self.host_regdoms.add(regd)
        # referral attribution
        origin = hdrs.get("origin", "") or hdrs.get("referer", "")
        oreg = ""
        if origin:
            o = origin.replace("https://", "").replace("http://", "")
            o = o.split("/")[0].split(":")[0]
            oreg = registrable(o)
            if oreg:
                self.origin_counts[oreg] = self.origin_counts.get(oreg, 0) + 1
        ws = (hdrs.get("upgrade", "").lower() == "websocket")
        if ws:
            method = "WS"

        struct = False
        dom = self._get_domain(regd)
        is_new_dom = dom.parent is None
        if oreg:
            dom.origins.add(oreg)
        # if the set of detected targets changed, re-attribute everything
        targets_now = self._targets()
        if targets_now != self._last_targets:
            self._last_targets = set(targets_now)
            self._reattribute_all()
            struct = True
        else:
            self._attribute(dom)
        if is_new_dom:
            struct = True

        key = (host, method, path)
        nid = self.req_index.get(key)
        if nid is None or nid not in self.nodes:
            n = MindNode(self._new_id(), "req", 0, 0)
            n.parent = dom.id
            n.host = host
            n.regdom = regd
            n.port = svc.getPort()
            n.https = (svc.getProtocol() == "https")
            n.method = method
            n.path = path
            n.url = full
            n.ws = ws
            self.nodes[n.id] = n
            self.req_index[key] = n.id
            struct = True
        else:
            n = self.nodes[nid]
            if count_it:
                n.count += 1
        n.request = request
        n.party = dom.party
        n.authed = any(h in hdrs for h in AUTH_HEADERS)
        if oreg:
            n.origins.add(oreg)
        if response is not None:
            n.response = response
            try:
                rinfo = self._helpers.analyzeResponse(response)
                n.status = str(rinfo.getStatusCode())
                n.ctype = self._ctype(rinfo)
            except:
                pass
        elif ws and not n.status:
            n.status = "WS"
            n.ctype = "ws"
        # re-color existing reqs of this domain if party changed
        return n, struct

    def _ctype(self, rinfo):
        ct = ""
        for h in rinfo.getHeaders()[1:]:
            if h.lower().startswith("content-type:"):
                ct = h.split(":", 1)[1].strip().lower()
                break
        if "json" in ct:
            return "json"
        if "html" in ct:
            return "html"
        if "javascript" in ct:
            return "js"
        if "css" in ct:
            return "css"
        if ct.startswith("image/"):
            return "image"
        return "other"

    def _get_domain(self, regd):
        nid = self.domain_index.get(regd)
        if nid is not None and nid in self.nodes:
            return self.nodes[nid]
        d = MindNode(self._new_id(), "domain", 0, 0)
        d.host = regd
        d.regdom = regd
        d.parent = None            # set by _attribute
        self.nodes[d.id] = d
        self.domain_index[regd] = d.id
        return d

    def _targets(self):
        # a target site = a registrable domain that referred traffic (via
        # Origin/Referer). If it's also a host we captured, 1 hit is enough;
        # otherwise require a few hits to avoid one-off external referrers
        # (e.g. a google.com landing referer). Manual overrides always count.
        auto = set(r for r, c in self.origin_counts.items()
                   if r in self.host_regdoms or c >= 3)
        return auto | self.forced_targets

    def _get_root(self, regd):
        rid = self.roots.get(regd)
        if rid is not None and rid in self.nodes:
            return self.nodes[rid]
        r = MindNode(self._new_id(), "root", 0, 0)
        r.host = regd
        r.regdom = regd
        r.label = regd
        r.party = "core"
        self.nodes[r.id] = r
        self.roots[regd] = r.id
        return r

    def _get_ext_root(self):
        if self.ext_root_id is not None and self.ext_root_id in self.nodes:
            return self.nodes[self.ext_root_id]
        r = MindNode(self._new_id(), "root", 0, 0)
        r.label = "other / 3rd-party"
        r.regdom = "*"
        r.party = "external"
        self.nodes[r.id] = r
        self.ext_root_id = r.id
        return r

    def _attribute(self, dom):
        targets = self._targets()
        regd = dom.regdom
        is_tr = any(t in regd for t in TRACKERS)
        if regd in targets:
            dom.party = "core"
            root = self._get_root(regd)
        else:
            cands = [t for t in dom.origins if t in targets]
            if cands:
                best = max(cands, key=lambda t: self.origin_counts.get(t, 0))
                dom.party = "tracker" if is_tr else "backend"
                root = self._get_root(best)
            else:
                dom.party = "tracker" if is_tr else "external"
                root = self._get_ext_root()
        dom.parent = root.id
        for c in self.nodes.values():
            if c.kind == "req" and c.parent == dom.id:
                c.party = dom.party

    def _reattribute_all(self):
        for d in [n for n in self.nodes.values() if n.kind == "domain"]:
            self._attribute(d)

    def _done_update(self):
        self._set_status()
        self.canvas.repaint()
        if len(self.nodes) != self._tree_count:
            self._tree_count = len(self.nodes)
            self._rebuild_tree()

    # ---------- sidebar request tree ----------
    def _rebuild_tree(self):
        expanded = set()
        try:
            for i in range(self.tree.getRowCount()):
                p = self.tree.getPathForRow(i)
                if self.tree.isExpanded(p):
                    o = p.getLastPathComponent().getUserObject()
                    if isinstance(o, MindNode):
                        expanded.add(o.id)
        except:
            pass
        sel_id = self.selected.id if self.selected else None
        new_root = DefaultMutableTreeNode("targets")
        roots = [n for n in self.nodes.values()
                 if n.kind == "root" and not self._hidden_base(n)]
        rank = {"core": 0, "backend": 1, "external": 2, "tracker": 3}
        roots.sort(key=lambda r: r.label)
        sel_path = [None]
        to_expand = []
        for r in roots:
            rtn = DefaultMutableTreeNode(r)
            doms = [d for d in self.nodes.values()
                    if d.kind == "domain" and d.parent == r.id
                    and not self._hidden_base(d)]
            doms.sort(key=lambda d: (rank.get(d.party, 4), d.host))
            for d in doms:
                dtn = DefaultMutableTreeNode(d)
                reqs = [c for c in self.nodes.values()
                        if c.kind == "req" and c.parent == d.id
                        and not self._hidden_base(c)]
                reqs.sort(key=lambda c: (c.method, c.path))
                for c in reqs:
                    ctn = DefaultMutableTreeNode(c)
                    dtn.add(ctn)
                rtn.add(dtn)
                if not doms or d.id in expanded or self._tree_count < 60:
                    to_expand.append(dtn)
            new_root.add(rtn)
            to_expand.append(rtn)
        self.tree_root = new_root
        self.tree.setModel(DefaultTreeModel(new_root))
        for tn in to_expand:
            try:
                self.tree.expandPath(_tree_path(tn))
            except:
                pass

    def tree_pick(self, node):
        if node is not None:
            self.focus_node(node)

    # ---------- radial layout (one cluster per target root) ----------
    def relayout(self):
        roots = [n for n in self.nodes.values() if n.kind == "root"
                 and any(c.kind == "domain" and c.parent == n.id
                         for c in self.nodes.values())]
        if not roots:
            self.canvas.repaint()
            return

        def cluster_leaves(r):
            return sum(max(1, self.child_count(d)) for d in self.nodes.values()
                       if d.kind == "domain" and d.parent == r.id)
        roots.sort(key=lambda r: (-cluster_leaves(r), r.label))
        gapx = 300.0
        cx = 0.0
        for r in roots:
            rad = self._cluster_layout(r, cx, 0.0)
            cx += 2 * rad + gapx
        self.canvas.repaint()

    def _cluster_layout(self, r, ox, oy):
        domains = [d for d in self.nodes.values()
                   if d.kind == "domain" and d.parent == r.id]
        if not domains:
            if not r.pinned:
                r.x, r.y = ox, oy
            return 150.0
        rank = {"core": 0, "backend": 1, "external": 2, "tracker": 3}
        domains.sort(key=lambda d: (rank.get(d.party, 4), d.host))
        childmap = dict((d.id, [c for c in self.nodes.values()
                                if c.kind == "req" and c.parent == d.id])
                        for d in domains)

        def weight(d):
            return 1 if d.collapsed else max(1, len(childmap[d.id]))
        total = sum(weight(d) for d in domains)
        R1 = 300.0
        gap = 0.06
        span_free = 2 * math.pi - gap * len(domains)
        ang = -math.pi / 2
        maxr = R1
        placed = []
        for d in domains:
            span = (weight(d) / float(total)) * span_free
            mid = ang + span / 2
            d._lx = R1 * math.cos(mid)
            d._ly = R1 * math.sin(mid)
            placed.append(d)
            kids = childmap[d.id]
            if d.collapsed:
                for c in kids:
                    c._lx, c._ly = d._lx, d._ly
                    placed.append(c)
            elif kids:
                n = len(kids)
                spacing = 44.0
                R2 = max(R1 + 220.0, (n * spacing) / max(span, 0.02))
                maxr = max(maxr, R2)
                ks = sorted(kids, key=lambda c: (c.method, c.path))
                if n == 1:
                    ks[0]._lx = R2 * math.cos(mid)
                    ks[0]._ly = R2 * math.sin(mid)
                    placed.append(ks[0])
                else:
                    a0 = ang + span * 0.06
                    a1 = ang + span * 0.94
                    for i, c in enumerate(ks):
                        t = a0 + (a1 - a0) * i / (n - 1)
                        c._lx = R2 * math.cos(t)
                        c._ly = R2 * math.sin(t)
                        placed.append(c)
            ang += span + gap
        if not r.pinned:
            r.x, r.y = ox + maxr, oy
        for nd in placed:
            if not nd.pinned:
                nd.x = nd._lx + ox + maxr
                nd.y = nd._ly + oy
        r._radius = maxr
        return maxr

    def act_arrange(self):
        for n in self.nodes.values():
            n.pinned = False
        self.relayout()
        self.act_fit()

    def act_fit(self):
        real = [n for n in self.nodes.values() if not self.is_hidden(n)]
        if not real:
            return
        xs = [n.x for n in real]
        ys = [n.y for n in real]
        minx, maxx = min(xs) - 120, max(xs) + 120
        miny, maxy = min(ys) - 100, max(ys) + 100
        w = self.canvas.getWidth() or 800
        h = self.canvas.getHeight() or 600
        self.canvas.scale = max(0.12, min(1.6,
                            min(w / max(1.0, maxx - minx), h / max(1.0, maxy - miny))))
        self.canvas.offx = (w - (minx + maxx) * self.canvas.scale) / 2
        self.canvas.offy = (h - (miny + maxy) * self.canvas.scale) / 2
        self.canvas.repaint()

    # ---------- selection ----------
    def select(self, n):
        self.selected = n
        empty = self._helpers.stringToBytes("")
        if n is not None and n.kind == "req":
            self.req_view.setMessage(n.request if n.request else empty, True)
            self.resp_view.setMessage(n.response if n.response else empty, False)
        else:
            self.req_view.setMessage(empty, True)
            self.resp_view.setMessage(empty, False)
        self.notes_area.setText(n.notes if n is not None else "")
        self.canvas.repaint()
        if self.chk_focus.isSelected():
            self._rebuild_tree()

    def toggle_collapse(self, n):
        n.collapsed = not n.collapsed
        if self.chk_arrange.isSelected():
            self.relayout()
        else:
            self.canvas.repaint()
        self._rebuild_tree()

    def focus_node(self, n):
        c = self.canvas
        w = c.getWidth() or 800
        h = c.getHeight() or 600
        c.offx = w / 2 - n.x * c.scale
        c.offy = h / 2 - n.y * c.scale
        self.select(n)

    # IMessageEditorController
    def getHttpService(self):
        n = self.selected
        if n is None or n.kind != "req":
            return None
        return self._helpers.buildHttpService(n.host, n.port or (443 if n.https else 80), n.https)

    def getRequest(self):
        return self.selected.request if self.selected else None

    def getResponse(self):
        return self.selected.response if self.selected else None

    # ---------- popup ----------
    def show_popup(self, e, n):
        pop = JPopupMenu()
        if n is not None:
            self.select(n)
            self._mi(pop, "Focus", lambda: self.focus_node(n))
            if n.kind == "req":
                for st in ("testing", "interesting", "vuln", "ignored", "untested"):
                    if st != n.tstatus:
                        self._mi(pop, STATUS_LABEL[st],
                                 lambda s=st: self.set_status(n, s))
                pop.addSeparator()
            self._mi(pop, "Set colour...", lambda: self._set_color(n))
            if n.color:
                self._mi(pop, "Clear colour", lambda: self._clear_color(n))
            if n.kind in ("domain", "req") and n.regdom:
                self._mi(pop, "Make '%s' a target root" % n.regdom,
                         lambda: self._promote_target(n.regdom))
            if n.kind == "root" and n.regdom and n.regdom != "*" \
                    and n.regdom in self.forced_targets:
                self._mi(pop, "Un-set as target root",
                         lambda: self._demote_target(n.regdom))
            if n.kind in ("root", "domain", "note"):
                self._mi(pop, "Rename...", lambda: self._rename(n))
            if n.pinned:
                self._mi(pop, "Unpin (auto-arrange)", lambda: self._unpin(n))
            self._mi(pop, "Set as link source", lambda: self._set_link_src(n))
            self._mi(pop, "Link from source", lambda: self._link_to(n))
            self._mi(pop, "Delete", lambda: self._delete(n))
        else:
            wx, wy = self.canvas.s2w(e.getX(), e.getY())
            self._mi(pop, "Add topic here", lambda: self._add_topic_at(wx, wy))
            self._mi(pop, "Arrange", self.act_arrange)
            self._mi(pop, "Fit", self.act_fit)
        pop.show(e.getComponent(), e.getX(), e.getY())

    def _mi(self, pop, label, fn):
        it = JMenuItem(label)
        it.addActionListener(_Act(fn))
        pop.add(it)

    def _promote_target(self, regd):
        self.forced_targets.add(regd)
        self._last_targets = set(self._targets())
        self._reattribute_all()
        if self.chk_arrange.isSelected():
            self.relayout()
        self._done_update()

    def _demote_target(self, regd):
        self.forced_targets.discard(regd)
        self._last_targets = set(self._targets())
        self._reattribute_all()
        if self.chk_arrange.isSelected():
            self.relayout()
        self._done_update()

    def set_status(self, n, st):
        n.tstatus = st
        self._refresh_views()

    def _set_color(self, n):
        c = JColorChooser.showDialog(self.root_panel, "Node colour", Color(*n.fill(self.color_mode())))
        if c is not None:
            n.color = (c.getRed(), c.getGreen(), c.getBlue())
            self.canvas.repaint()

    def _clear_color(self, n):
        n.color = None
        self.canvas.repaint()

    def _rename(self, n):
        cur = n.label if n.kind in ("root", "note") else n.host
        v = JOptionPane.showInputDialog(self.root_panel, "Name:", cur)
        if v is not None:
            if n.kind in ("root", "note"):
                n.label = v
            else:
                n.host = v
            self.canvas.repaint()

    def _unpin(self, n):
        n.pinned = False
        if self.chk_arrange.isSelected():
            self.relayout()

    def _set_link_src(self, n):
        self._link_src = n
        JOptionPane.showMessageDialog(self.root_panel,
            "Link source set. Right-click target -> 'Link from source'.")

    def _link_to(self, n):
        if self._link_src is None:
            JOptionPane.showMessageDialog(self.root_panel, "Set a link source first.")
            return
        if self._link_src.id != n.id:
            self.links.append((self._link_src.id, n.id))
            self.canvas.repaint()

    def _delete(self, n):
        if n.kind == "root":
            return
        ids = set([n.id])
        if n.kind == "domain":
            for c in list(self.nodes.values()):
                if c.parent == n.id:
                    ids.add(c.id)
        for i in ids:
            self.nodes.pop(i, None)
        self.req_index = dict((k, v) for k, v in self.req_index.items() if v not in ids)
        self.domain_index = dict((k, v) for k, v in self.domain_index.items() if v not in ids)
        self.links = [(a, b) for (a, b) in self.links if a not in ids and b not in ids]
        if self.selected and self.selected.id in ids:
            self.select(None)
        self._done_update()

    def _add_topic_at(self, wx, wy):
        v = JOptionPane.showInputDialog(self.root_panel, "Topic:", "topic")
        if v is None:
            return
        t = MindNode(self._new_id(), "note", wx, wy)
        t.label = v
        t.pinned = True
        self.nodes[t.id] = t
        self.select(t)
        self._done_update()

    # ---------- toolbar ----------
    def act_add_topic(self):
        self._add_topic_at(0, 0)

    def act_delete(self):
        if self.selected:
            self._delete(self.selected)

    def act_link(self):
        if self.selected:
            self._set_link_src(self.selected)
        else:
            JOptionPane.showMessageDialog(self.root_panel,
                "Select a source node, then right-click the target -> 'Link from source'.")

    def apply_filter(self):
        term = self.filter_text()
        if term:
            for n in self.nodes.values():
                if n.kind == "req" and term in (n.display() + " " + n.url + " " + n.host).lower():
                    self.focus_node(n)
                    return
        self.canvas.repaint()

    # ---------- status / persistence ----------
    def _set_status(self):
        name = self.project_file.getName() if self.project_file else "unsaved"
        reqs = sum(1 for n in self.nodes.values() if n.kind == "req")
        doms = sum(1 for n in self.nodes.values() if n.kind == "domain")
        tgts = sorted(self._targets())
        tstr = ", ".join(tgts) if tgts else "?"
        self.status_lbl.setText(" %s | targets: %s | %d domains, %d endpoints " %
                                (name, tstr, doms, reqs))

    def act_new(self):
        if len(self.nodes) > 0 and JOptionPane.showConfirmDialog(
                self.root_panel, "Discard current map?", "New",
                JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION:
            return
        self.nodes = {}
        self.domain_index = {}
        self.req_index = {}
        self.links = []
        self.origin_counts = {}
        self.host_regdoms = set()
        self.roots = {}
        self.ext_root_id = None
        self.forced_targets = set()
        self._last_targets = set()
        self.project_file = None
        self.select(None)
        self._done_update()

    def _chooser(self, save):
        fc = JFileChooser()
        fc.setFileFilter(FileNameExtensionFilter("Mind Map (*.%s)" % FILE_EXT, [FILE_EXT]))
        if self.project_file:
            fc.setSelectedFile(self.project_file)
        r = fc.showSaveDialog(self.root_panel) if save else fc.showOpenDialog(self.root_panel)
        if r != JFileChooser.APPROVE_OPTION:
            return None
        f = fc.getSelectedFile()
        if save and not f.getName().endswith("." + FILE_EXT):
            f = File(f.getParentFile(), f.getName() + "." + FILE_EXT)
        return f

    def act_save(self):
        if self.project_file is None:
            return self.act_save_as()
        self._write(self.project_file)

    def act_save_as(self):
        f = self._chooser(True)
        if f is None:
            return
        self.project_file = f
        self._write(f)

    def _write(self, f):
        data = {"version": 3, "next_id": self.next_id,
                "ext_root_id": self.ext_root_id,
                "origin_counts": self.origin_counts,
                "host_regdoms": list(self.host_regdoms),
                "forced_targets": list(self.forced_targets),
                "view": {"scale": self.canvas.scale, "offx": self.canvas.offx,
                         "offy": self.canvas.offy},
                "links": [list(l) for l in self.links],
                "nodes": [n.to_dict() for n in self.nodes.values()]}
        try:
            fw = open(f.getAbsolutePath(), "w")
            fw.write(json.dumps(data))
            fw.close()
            self._set_status()
            JOptionPane.showMessageDialog(self.root_panel, "Saved:\n" + f.getAbsolutePath())
        except Exception as ex:
            JOptionPane.showMessageDialog(self.root_panel, "Save failed: " + str(ex))

    def act_open(self):
        f = self._chooser(False)
        if f is None:
            return
        try:
            fr = open(f.getAbsolutePath(), "r")
            data = json.loads(fr.read())
            fr.close()
        except Exception as ex:
            JOptionPane.showMessageDialog(self.root_panel, "Open failed: " + str(ex))
            return
        self.nodes = {}
        self.domain_index = {}
        self.req_index = {}
        self.roots = {}
        self.ext_root_id = data.get("ext_root_id")
        for d in data.get("nodes", []):
            n = MindNode.from_dict(d)
            self.nodes[n.id] = n
            if n.kind == "domain":
                self.domain_index[n.regdom or n.host] = n.id
            elif n.kind == "req":
                self.req_index[(n.host, n.method, n.path)] = n.id
            elif n.kind == "root" and n.regdom and n.regdom != "*":
                self.roots[n.regdom] = n.id
        self.links = [tuple(l) for l in data.get("links", [])]
        self.next_id = data.get("next_id", len(self.nodes) + 1)
        self.origin_counts = data.get("origin_counts", {}) or {}
        self.forced_targets = set(data.get("forced_targets", []))
        self.host_regdoms = set(data.get("host_regdoms", []))
        if not self.host_regdoms:
            self.host_regdoms = set(n.regdom for n in self.nodes.values()
                                    if n.kind == "req" and n.regdom)
        self._last_targets = set(self._targets())
        v = data.get("view", {})
        self.canvas.scale = v.get("scale", 0.7)
        self.canvas.offx = v.get("offx", 500.0)
        self.canvas.offy = v.get("offy", 350.0)
        self.project_file = f
        self.select(None)
        self._done_update()


class _Act(ActionListener):
    def __init__(self, fn):
        self.fn = fn
    def actionPerformed(self, e):
        self.fn()


class _FilterKey(KeyAdapter):
    def __init__(self, ext):
        self.ext = ext
    def keyReleased(self, e):
        if e.getKeyCode() == KeyEvent.VK_ENTER:
            self.ext.apply_filter()
        else:
            self.ext.canvas.repaint()


def _tree_path(tn):
    from javax.swing.tree import TreePath
    return TreePath(tn.getPath())


def _hex(c):
    return "#%02x%02x%02x" % (c[0], c[1], c[2])


class _TreeRenderer(DefaultTreeCellRenderer):
    def __init__(self):
        self.setBackgroundNonSelectionColor(Color(16, 18, 28))
        self.setBackgroundSelectionColor(Color(10, 90, 190))
        self.setTextNonSelectionColor(Color(210, 216, 230))
        self.setTextSelectionColor(Color(255, 255, 255))
        self.setBorderSelectionColor(Color(10, 90, 190))
        self.setFont(Font("SansSerif", Font.PLAIN, 12))

    def getTreeCellRendererComponent(self, tree, value, sel, exp, leaf, row, foc):
        DefaultTreeCellRenderer.getTreeCellRendererComponent(
            self, tree, value, sel, exp, leaf, row, foc)
        self.setIcon(None)
        try:
            o = value.getUserObject()
        except:
            o = None
        if isinstance(o, MindNode):
            n = o
            if n.kind == "root":
                self.setText("* " + n.display())
                self.setFont(Font("SansSerif", Font.BOLD, 13))
                if not sel:
                    self.setForeground(Color(232, 196, 74))
            elif n.kind == "domain":
                self.setText("- " + n.display())
                self.setFont(Font("SansSerif", Font.BOLD, 12))
                if not sel:
                    c = PARTY.get(n.party, PARTY["external"])
                    self.setForeground(Color(c[0], c[1], c[2]))
            elif n.kind == "req":
                mark = {"testing": "~ ", "interesting": "* ", "vuln": "! ",
                        "ignored": "- ", "untested": "  "}.get(n.tstatus, "  ")
                txt = mark + "%-6s %s" % (n.method, n.path)
                if n.status:
                    txt += "   " + n.status
                if n.count > 1:
                    txt += "   x" + str(n.count)
                if n.authed:
                    txt += "  @"
                self.setText(txt)
                self.setFont(Font("Monospaced", Font.PLAIN, 12))
                if not sel:
                    c = STATUSC.get(n.tstatus) if n.tstatus == "vuln" \
                        else METHODC.get(n.method, (175, 180, 195))
                    c = c or METHODC.get(n.method, (175, 180, 195))
                    self.setForeground(Color(c[0], c[1], c[2]))
        return self


class _TreeSel(TreeSelectionListener):
    def __init__(self, ext):
        self.ext = ext
    def valueChanged(self, e):
        p = e.getNewLeadSelectionPath()
        if p is None:
            return
        try:
            o = p.getLastPathComponent().getUserObject()
        except:
            return
        if isinstance(o, MindNode):
            self.ext.tree_pick(o)


def _notes_listener(ext):
    from javax.swing.event import DocumentListener

    class _L(DocumentListener):
        def _sync(self):
            if ext.selected is not None:
                ext.selected.notes = ext.notes_area.getText()
        def insertUpdate(self, e): self._sync()
        def removeUpdate(self, e): self._sync()
        def changedUpdate(self, e): self._sync()
    return _L()
