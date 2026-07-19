# Target Mind Map — Burp Suite extension

<img width="1913" height="1106" alt="image" src="https://github.com/user-attachments/assets/b67b1a5c-f2d8-4280-b188-9a5c98a14e80" />



A radial, **referral-aware** mind map of any target. Works on any site with no
per-target rules.

## The smart part: referral attribution

Modern targets fan out across many backend domains that don't share a name with
the main site (e.g. BingX uses `we-api.com`, `qq-os.com`, `acc-de.com`,
`bb-os.com`…). The extension reads each request's **`Origin` / `Referer`** to
work out where it *came from*:

- It auto-detects each **target** = a registrable domain that you actually
  browsed *and* that shows up as an Origin/Referer. Browse several programs and
  each gets its **own root cluster** side by side (multi-target); domains sort
  under whichever target referred them. No need to reset between programs.
- Every host is coloured by its relationship to its target:
  - **core** (gold) — same registrable domain as the target
  - **backend** (green) — different domain, but its requests are referred by the
    target (the hidden API surface you actually want)
  - **tracker** (grey) — known third-parties (facebook, tiktok, akamai, …)
  - **external** (slate) — everything else
- The centre root is named after the detected target automatically.

## Install

1. Get the **Jython standalone jar** (https://www.jython.org/download).
2. Burp → **Extender → Options → Python Environment** → select that jar.
3. Burp → **Extender → Extensions → Add** → type **Python** → `MindMap.py`.

## Capture (reads everything)

- **Auto-capture** (toolbar, on by default): pulls traffic from **all Burp
  tools**, not just Proxy.
- **WebSocket upgrades** and **response-less / in-flight** requests are captured.
- Repeated calls to the same endpoint collapse into **one node with a `×N`
  badge** instead of dozens of duplicates.
- Or right-click any request anywhere → **Add to Mind Map** (multi-select ok).

## Layout & view

- **Radial map**: target root in the centre, domains around it, endpoints as
  leaves, auto-spaced by traffic volume so nothing overlaps.
- **Arrange** re-runs the layout and frames it; **Fit** just frames.
- Drag a node to move it (it becomes *pinned* and auto-arrange leaves it alone;
  right-click → *Unpin* to release). Drag empty space to pan, wheel to zoom,
  double-click to centre.
- **Deep-space canvas**: starfield + nebula wash + faint orbit rings around each
  target root, so the structure reads at a glance and stays easy on the eyes.
- **Colour** dropdown: party (referral) / method / status / content-type — switch
  live.
- **3rd-party** dropdown: `show` / `dim` / `hide` — fully remove trackers &
  external hosts from both the canvas and the sidebar, or just fade them.
- **Focus** toggle: show only the selected node's target cluster on the canvas
  (the sidebar still lists everything).
- **Filter** box: type to dim non-matches (highlights matching endpoints); Enter
  jumps to the first match.

## Sidebar — every request

The left panel lists all captured requests as a tree: **target → domain →
endpoint**, with coloured method chips, status, and `×N` counts. Click any entry
to centre it on the canvas and load its request/response. It stays in sync as
traffic streams in and respects the 3rd-party show/dim/hide setting.

## Focus & notes

- Click a node → its request & response load into Burp's own editors (so
  Send-to-Repeater etc. work), and you can write per-node **notes**.
- **Add topic** creates a free node for your own thinking; **Link** connects any
  two nodes (set a source, then right-click the target → *Link from source*).

## Projects

- **Save / Save As** → `*.mmap.json` with node positions, colours, notes, links,
  the detected target, and the base64-embedded request/response bytes.
- **Open** restores everything; **New** clears the map.

> The `.mmap.json` embeds raw traffic — treat it as sensitive.
