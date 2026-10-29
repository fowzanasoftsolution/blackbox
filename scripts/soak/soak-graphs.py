#!/usr/bin/env python3
"""Generate the v1.1.2 soak comparison charts (pure-stdlib SVG, deterministic).

Usage:
    python scripts/soak/soak-graphs.py RUN1_RAW RUN2_RAW [--out DIR]

    RUN1_RAW  raw/ directory of the failing run-1 evidence (required; the
              dated evidence directory is kept outside this repository)
    RUN2_RAW  raw/ directory of the passing re-verification run (required)
    --out     output directory, default <repo>/docs/soak

Reads samples.jsonl (kernel-VmRSS samples, ~10 s cadence) from each evidence
directory and writes two SVG charts plus nothing else:

    rss-timeline.svg      Node A / Node B RSS timelines, run-1 vs re-run,
                          with the supervisor watermark lines
    soak-comparison.svg   peak RSS / sampled-out / checks panels

No third-party dependencies; the same command reproduces the committed SVGs
byte-for-byte on any Python >= 3.9 (SVG text is generated deterministically).
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# Supervisor watermark facts (48 MiB budget): Warn75 = 36 MiB, Shed85 = 40.8,
# v1.1.2 PASS target = 45 MiB. Order: value, label, dash pattern, color.
WATERMARKS = [
    (48.0, "budget 48", "", "#c0392b"),
    (45.0, "v1.1.2 target 45", "2 3", "#7f8c8d"),
    (40.8, "Shed85 40.8", "6 3", "#e67e22"),
    (36.0, "Warn75 36", "2 3", "#c9a227"),
]
C_RUN1, C_RUN2 = "#d9534f", "#2e9e44"
CRASHES = (600, 1200)


def load(root: Path):
    rows = [json.loads(l) for l in (root / "samples.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    out = {}
    for node in ("a", "b"):
        pts = [(float(r["elapsed_s"]), r["nodes"][node]["kernel_rss_kb"] / 1024.0, r["nodes"][node]["ram"]["level"])
               for r in rows if "error" not in r["nodes"][node]]
        out[node] = pts
    final = rows[-1]["nodes"]
    return {
        "series": out,
        "peak": {n: max(p[1] for p in out[n]) for n in ("a", "b")},
        "sampled_out": {n: final[n]["ingress"]["sampled_out"] for n in ("a", "b")},
        "checks": json.loads((root.parent / "metrics.json").read_text(encoding="utf-8"))["checks"],
    }


class Svg:
    def __init__(self, w, h, title):
        self.w, self.h = w, h
        self.parts = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
            f'viewBox="0 0 {w} {h}" font-family="Segoe UI, Helvetica, Arial, sans-serif">',
            f"<title>{esc(title)}</title>",
            f'<rect width="{w}" height="{h}" fill="white"/>',
        ]

    def add(self, s): self.parts.append(s)

    def text(self, x, y, s, size=12, fill="#333", anchor="start", weight="normal", style="normal"):
        self.add(f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" fill="{fill}" '
                 f'text-anchor="{anchor}" font-weight="{weight}" font-style="{style}">{esc(s)}</text>')

    def line(self, x1, y1, x2, y2, stroke, width=1, dash=""):
        d = f' stroke-dasharray="{dash}"' if dash else ""
        self.add(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.2f}" y2="{y2:.1f}" '
                 f'stroke="{stroke}" stroke-width="{width}"{d}/>')

    def polyline(self, pts, stroke, width=1.8, dash=""):
        s = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
        d = f' stroke-dasharray="{dash}"' if dash else ""
        self.add(f'<polyline points="{s}" fill="none" stroke="{stroke}" '
                 f'stroke-width="{width}" stroke-linejoin="round"{d}/>')

    def save(self, path):
        self.parts.append("</svg>")
        path.write_text("\n".join(self.parts), encoding="utf-8")


def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def timeline_chart(runs):
    """runs: [(label, color, data)] -> two stacked panels, one per node."""
    W, H = 960, 810
    s = Svg(W, H, "v1.1.2 soak - Node RSS timeline: run-1 vs re-verification run")
    s.text(20, 30, "v1.1.2 soak - kernel VmRSS timeline: run-1 vs re-verification run", 17, "#111", weight="bold")
    s.text(20, 50, "48 MiB supervisor budget; every sample is a /proc VmRSS read (~10 s cadence), 189 samples per node per run", 11, "#666")

    panel = {"x": 70, "w": 830, "h": 280}
    y_max = 52.0
    for pi, node in enumerate(("a", "b")):
        px, py = panel["x"], 78 + pi * 330
        ph = panel["h"]

        def X(t): return px + t / 1830.0 * panel["w"]
        def Y(v): return py + ph - v / y_max * ph

        s.text(px, py - 12, f"Node {'A' if node == 'a' else 'B'} - "
              + ("blackbox run (8 MiB effective segment cap)" if node == "a" else "blackbox serve (2 MiB segments)"),
              13, "#111", weight="bold")

        # y grid + labels
        for v in (0, 12, 24, 36, 48):
            s.line(px, Y(v), px + panel["w"], Y(v), "#e8e8e8", 1)
            s.text(px - 8, Y(v) + 4, f"{v:.0f}", 10, "#888", anchor="end")
        # watermark lines + right labels
        for v, lab, dash, col in WATERMARKS:
            s.line(px, Y(v), px + panel["w"], Y(v), col, 1.2, dash)
            s.text(px + panel["w"] + 6, Y(v) + 4, lab, 9.5, col)
        # x ticks + crash markers
        for t in range(0, 1801, 300):
            s.line(X(t), py + ph, X(t), py + ph + 4, "#888", 1)
            s.text(X(t), py + ph + 17, f"{t // 60}m", 10, "#888", anchor="middle")
        for c in CRASHES:
            s.line(X(c), py, X(c), py + ph, "#b0b0b0", 1, "3 4")
            s.text(X(c) + 3, py + 11, "crash", 9, "#999")
        # series
        for label, color, data in runs:
            s.polyline([(X(t), Y(v)) for t, v, _ in data[node]], color, 1.6)

    # legend (below both panels and their x labels)
    lx = 90
    for i, (label, color, _) in enumerate(runs):
        s.line(lx, 728 + i * 22, lx + 26, 728 + i * 22, color, 3)
        s.text(lx + 32, 732 + i * 22, label, 11.5, "#333")
    for i, (col, dash, lab) in enumerate([("#c0392b", "", "budget 48"),
                                          ("#e67e22", "6 3", "Shed85 (head-sampling finalizer)"),
                                          ("#c9a227", "2 3", "Warn75"),
                                          ("#7f8c8d", "2 3", "v1.1.2 target 45")]):
        x = (420, 500, 730, 830)[i]
        s.line(x, 728, x + 24, 728, col, 2, dash)
        s.text(x + 30, 732, lab, 10.5, col)

    # sampled-out event marker on Node A, run-1
    a1 = runs[0][2]["a"]
    t_ev = min(((t, v) for t, v, _ in a1 if t >= 1450), key=lambda p: abs(p[0] - 1492))
    _, py, ph, = 78, 78, panel["h"]
    xev = 70 + t_ev[0] / 1830.0 * panel["w"]
    yev = py + ph - t_ev[1] / y_max * ph
    s.add(f'<circle cx="{xev:.1f}" cy="{yev:.1f}" r="4.5" fill="{C_RUN1}" stroke="white" stroke-width="1.5"/>')
    s.text(xev - 6, yev - 10, "7 records sampled out (t = 1492 s)", 11, C_RUN1, anchor="end", weight="bold")

    s.text(20, H - 12, "Generated by scripts/soak/soak-graphs.py from raw soak evidence (samples.jsonl); "
          "raw archives live in the dated report directories outside this repo.", 9.5, "#999")
    return s


def comparison_chart(run1, run2):
    W, H = 1000, 430
    s = Svg(W, H, "v1.1.2 soak - run-1 vs re-verification comparison")
    s.text(20, 30, "v1.1.2 soak - run-1 (2026-10-27) vs re-verification run (2026-10-28)", 17, "#111", weight="bold")
    s.text(20, 50, "Peak kernel VmRSS per node, records sampled out by the Shed85 finalizer, soak checks passed (of 20)", 11, "#666")

    bars = [
        ("Peak RSS (MiB)", 50.0, "MiB",
         [(f"A", run1["peak"]["a"], C_RUN1), ("A", run2["peak"]["a"], C_RUN2),
          ("B", run1["peak"]["b"], C_RUN1), ("B", run2["peak"]["b"], C_RUN2)],
         [(45.0, "target 45", "#7f8c8d", "2 3"), (48.0, "budget 48", "#c0392b", "")]),
        ("Records sampled out", 8.0, "records",
         [("A", run1["sampled_out"]["a"], C_RUN1), ("A", run2["sampled_out"]["a"], C_RUN2),
          ("B", run1["sampled_out"]["b"], C_RUN1), ("B", run2["sampled_out"]["b"], C_RUN2)], []),
        ("Checks passed (of 20)", 20.0, "checks",
         [("run-1", sum(1 for v in run1["checks"].values() if v), C_RUN1),
          ("re-run", sum(1 for v in run2["checks"].values() if v), C_RUN2)], []),
    ]
    pw, gap = 280, 40
    for pi, (title, y_max, unit, items, lines) in enumerate(bars):
        px = 50 + pi * (pw + gap)
        py, ph = 90, 250

        def Y(v): return py + ph - v / y_max * ph

        s.text(px, py - 14, title, 13, "#111", weight="bold")
        for v in range(0, int(y_max) + 1, 10 if y_max > 10 else 2):
            s.line(px + 46, Y(v), px + pw, Y(v), "#e8e8e8", 1)
            s.text(px + 40, Y(v) + 4, f"{v:.0f}", 10, "#888", anchor="end")
        for v, lab, col, dash in lines:
            s.line(px + 46, Y(v), px + pw, Y(v), col, 1.3, dash)
            s.text(px + pw - 2, Y(v) - 5, lab, 9.5, col, anchor="end")
        s.line(px + 46, py + ph, px + pw, py + ph, "#555", 1.2)

        bw, bgap = 44, 18
        n = len(items)
        x0 = px + 46 + (pw - 46 - n * bw - (n - 1) * bgap) / 2
        for i, (lab, val, col) in enumerate(items):
            x = x0 + i * (bw + bgap)
            h = max(1.0, (py + ph) - Y(val))
            s.add(f'<rect x="{x:.1f}" y="{Y(val):.1f}" width="{bw}" height="{h:.1f}" fill="{col}" opacity="0.85"/>')
            s.text(x + bw / 2, Y(val) - 6, f"{round(float(val), 2):g}", 11.5, "#222", anchor="middle", weight="bold")
            s.text(x + bw / 2, py + ph + 15, lab, 10.5, "#555", anchor="middle")
        # run-color legend under first panel's bars
    lx, ly = 50, 405
    for i, (lab, col) in enumerate([("run-1 (FAIL 19/20, 7 sampled out)", C_RUN1),
                                    ("re-run (PASS 20/20, 0 sampled out)", C_RUN2)]):
        s.add(f'<rect x="{lx + i * 430}" y="{ly - 10}" width="14" height="10" fill="{col}" opacity="0.85"/>')
        s.text(lx + i * 430 + 20, ly - 1, lab, 11, "#333")
    s.text(20, H - 8, "Generated by scripts/soak/soak-graphs.py from raw soak evidence; A = blackbox run, B = blackbox serve.", 9.5, "#999")
    return s


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) < 2:
        sys.exit("usage: soak-graphs.py RUN1_RAW RUN2_RAW [--out DIR]\n"
                 "both raw evidence directories are required; they live in the "
                 "dated soak report directories outside this repository")
    run1_dir = Path(args[0])
    run2_dir = Path(args[1])
    out_dir = Path(args[2]) if len(args) > 2 else REPO / "docs" / "soak"
    out_dir.mkdir(parents=True, exist_ok=True)

    run1, run2 = load(run1_dir), load(run2_dir)
    runs = [
        (f"run-1 v1.1.2 (FAIL: {run1['sampled_out']['a'] + run1['sampled_out']['b']} sampled out)", C_RUN1, run1["series"]),
        (f"re-run v1.1.2 (PASS: 0 sampled out)", C_RUN2, run2["series"]),
    ]
    p1 = out_dir / "rss-timeline.svg"
    p2 = out_dir / "soak-comparison.svg"
    timeline_chart(runs).save(p1)
    comparison_chart(run1, run2).save(p2)
    print(f"wrote {p1} ({p1.stat().st_size} bytes)")
    print(f"wrote {p2} ({p2.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
