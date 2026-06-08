import curses
import threading
import time

from src.node.stats import format_bytes, format_rate


TABS = ["Overview", "Network", "Resources", "Connections", "Events"]
BAR_BLOCKS = " ▁▂▃▄▅▆▇█"


class NodeDashboard:
    def __init__(self, stats, stop_event: threading.Event):
        self.stats = stats
        self.stop_event = stop_event
        self.tab = 0
        self.scroll = 0
        self._sampler_stop = threading.Event()

    def start_sampler(self):
        def loop():
            while not self._sampler_stop.is_set():
                self.stats.tick_rates()
                time.sleep(1)

        threading.Thread(target=loop, daemon=True).start()

    def stop_sampler(self):
        self._sampler_stop.set()

    def run(self):
        self.start_sampler()
        try:
            curses.wrapper(self._main)
        finally:
            self.stop_sampler()

    def _main(self, stdscr):
        curses.curs_set(0)
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_GREEN, -1)
        curses.init_pair(2, curses.COLOR_GREEN, -1)

        stdscr.timeout(150)
        while not self.stop_event.is_set():
            self._draw(stdscr)
            key = stdscr.getch()
            if key == -1:
                continue
            if key in (ord("q"), ord("Q"), 27):
                self.stop_event.set()
                break
            if key == curses.KEY_RIGHT:
                self.tab = (self.tab + 1) % len(TABS)
                self.scroll = 0
            elif key == curses.KEY_LEFT:
                self.tab = (self.tab - 1) % len(TABS)
                self.scroll = 0
            elif key == curses.KEY_UP:
                self.scroll = max(0, self.scroll - 1)
            elif key == curses.KEY_DOWN:
                self.scroll += 1

    def _draw(self, stdscr):
        stdscr.erase()
        height, width = stdscr.getmaxyx()
        snap = self.stats.snapshot()
        green = curses.color_pair(1)
        bright = curses.color_pair(2) | curses.A_BOLD

        title = f" OnionSocket {snap['role'].upper()} NODE "
        stdscr.addstr(0, max(0, (width - len(title)) // 2), title[: width - 1], bright)

        addr = f"{snap['advertise_host']}:{snap['port']}"
        stdscr.addstr(1, 2, f"Address: {addr}"[: width - 3], green)
        stdscr.addstr(2, 2, f"Uptime: {snap['uptime']}"[: width - 3], green)

        tab_line = "  "
        for idx, name in enumerate(TABS):
            label = f"[{name}]" if idx == self.tab else f" {name} "
            tab_line += label + " "
        stdscr.addstr(3, 2, tab_line[: width - 3], bright if self.tab else green)

        body_top = 5
        body_height = max(0, height - body_top - 2)
        body_width = max(0, width - 4)

        if self.tab == 0:
            self._draw_overview(stdscr, snap, body_top, 2, body_width, body_height, green, bright)
        elif self.tab == 1:
            self._draw_network(stdscr, snap, body_top, 2, body_width, body_height, green, bright)
        elif self.tab == 2:
            self._draw_resources(stdscr, snap, body_top, 2, body_width, body_height, green, bright)
        elif self.tab == 3:
            self._draw_connections(stdscr, snap, body_top, 2, body_width, body_height, green, bright)
        else:
            self._draw_events(stdscr, snap, body_top, 2, body_width, body_height, green, bright)

        footer = " ←/→ tabs   ↑/↓ scroll   Q quit "
        stdscr.addstr(height - 1, max(0, (width - len(footer)) // 2), footer[: width - 1], green)
        stdscr.refresh()

    def _safe_addstr(self, win, y, x, text, attr=0):
        try:
            max_y, max_x = win.getmaxyx()
            if y < 0 or y >= max_y or x >= max_x:
                return
            win.addstr(y, x, text[: max(0, max_x - x - 1)], attr)
        except curses.error:
            pass

    def _draw_overview(self, stdscr, snap, y, x, w, h, green, bright):
        lines = [
            ("Registry", snap["registry"] or "disabled"),
            ("Mode", snap["mode"] or "relay forward"),
            ("Active connections", str(snap["active_connections"])),
            ("Total connections", str(snap["total_connections"])),
            ("Bytes received", format_bytes(snap["bytes_in"])),
            ("Bytes sent", format_bytes(snap["bytes_out"])),
        ]
        if snap["role"] == "relay":
            lines.extend(
                [
                    ("Circuits forwarded", str(snap["circuits_forwarded"])),
                    ("Onion entries", str(snap["onion_entries"])),
                    ("Relay hops", str(snap["relay_hops"])),
                    ("Discovery probes", str(snap["probes"])),
                ]
            )
        else:
            lines.extend(
                [
                    ("Active sessions", str(snap["sessions_active"])),
                    ("Messages handled", str(snap["messages"])),
                    ("Discovery probes", str(snap["probes"])),
                ]
            )

        for idx, (label, value) in enumerate(lines[:h]):
            self._safe_addstr(stdscr, y + idx, x, f"{label:<22}", green)
            self._safe_addstr(stdscr, y + idx, x + 22, value, bright)

        chart_y = y + min(len(lines) + 1, h - 6)
        if chart_y < y + h - 4:
            self._safe_addstr(stdscr, chart_y, x, "Live throughput", bright)
            self._draw_horizontal_bars(
                stdscr,
                chart_y + 1,
                x,
                w,
                snap["current_in_rate"],
                snap["current_out_rate"],
                max(snap["peak_in_rate"], snap["peak_out_rate"], 1),
                green,
                bright,
            )

    def _draw_network(self, stdscr, snap, y, x, w, h, green, bright):
        self._safe_addstr(stdscr, y, x, "Current traffic rate", bright)
        peak = max(snap["peak_in_rate"], snap["peak_out_rate"], 1)
        self._draw_horizontal_bars(
            stdscr, y + 1, x, w, snap["current_in_rate"], snap["current_out_rate"], peak, green, bright
        )

        self._safe_addstr(stdscr, y + 4, x, f"Peak in:  {format_rate(snap['peak_in_rate'])}", green)
        self._safe_addstr(stdscr, y + 5, x, f"Peak out: {format_rate(snap['peak_out_rate'])}", green)
        self._safe_addstr(stdscr, y + 6, x, f"Total in: {format_bytes(snap['bytes_in'])}", green)
        self._safe_addstr(stdscr, y + 7, x, f"Total out: {format_bytes(snap['bytes_out'])}", green)

        chart_y = y + 9
        chart_h = max(4, h - 10)
        self._safe_addstr(stdscr, chart_y, x, "Traffic history (60s) — inbound / outbound", bright)
        self._draw_history_chart(
            stdscr,
            chart_y + 1,
            x,
            w,
            chart_h,
            snap["rate_history"],
            green,
            bright,
        )

    def _draw_resources(self, stdscr, snap, y, x, w, h, green, bright):
        lines = [
            ("Process memory", f"{snap['memory_mb']:.1f} MB"),
            ("CPU time", f"{snap['cpu_seconds']:.2f} s"),
            ("Active threads", str(snap["threads"])),
            ("Uptime", snap["uptime"]),
            ("Connections (active)", str(snap["active_connections"])),
        ]
        if snap["role"] == "relay":
            lines.append(("Circuits forwarded", str(snap["circuits_forwarded"])))
        else:
            lines.append(("Client sessions", str(snap["sessions_active"])))

        for idx, (label, value) in enumerate(lines[: max(0, h - 8)]):
            self._safe_addstr(stdscr, y + idx, x, f"{label:<22}", green)
            self._safe_addstr(stdscr, y + idx, x + 22, value, bright)

        meter_y = y + len(lines) + 2
        if meter_y + 4 < y + h:
            self._safe_addstr(stdscr, meter_y, x, "Memory pressure", bright)
            mem_pct = min(100, int(snap["memory_mb"] / 256 * 100))
            self._draw_meter(stdscr, meter_y + 1, x, w - 4, mem_pct, green, bright, f"{snap['memory_mb']:.1f} MB")

            self._safe_addstr(stdscr, meter_y + 3, x, "Thread load", bright)
            thread_pct = min(100, snap["threads"] * 8)
            self._draw_meter(stdscr, meter_y + 4, x, w - 4, thread_pct, green, bright, str(snap["threads"]))

    def _draw_connections(self, stdscr, snap, y, x, w, h, green, bright):
        header = f"{'ID':<5}{'Address':<22}{'Kind':<10}{'In':<10}{'Out':<10}{'State':<8}"
        self._safe_addstr(stdscr, y, x, header[: w], bright)
        rows = snap["connections"]
        max_scroll = max(0, len(rows) - max(0, h - 2))
        self.scroll = min(self.scroll, max_scroll)
        visible = rows[self.scroll : self.scroll + max(0, h - 2)]
        for idx, row in enumerate(visible):
            state = "closed" if row.closed else "open"
            line = (
                f"{row.conn_id:<5}"
                f"{row.addr:<22}"
                f"{row.kind:<10}"
                f"{format_bytes(row.bytes_in):<10}"
                f"{format_bytes(row.bytes_out):<10}"
                f"{state:<8}"
            )
            self._safe_addstr(stdscr, y + 1 + idx, x, line[: w], green)

    def _draw_events(self, stdscr, snap, y, x, w, h, green, bright):
        rows = snap["events"]
        max_scroll = max(0, len(rows) - max(0, h - 1))
        self.scroll = min(self.scroll, max_scroll)
        visible = rows[self.scroll : self.scroll + max(0, h - 1)]
        for idx, line in enumerate(visible):
            self._safe_addstr(stdscr, y + idx, x, line[: w], green)

    def _draw_horizontal_bars(self, stdscr, y, x, w, in_rate, out_rate, peak, green, bright):
        bar_w = max(10, min(40, w - 18))
        for label, rate in (("IN ", in_rate), ("OUT", out_rate)):
            filled = int((rate / peak) * bar_w) if peak else 0
            bar = "█" * filled + "░" * (bar_w - filled)
            self._safe_addstr(stdscr, y, x, f"{label} ", green)
            self._safe_addstr(stdscr, y, x + 4, bar, bright)
            self._safe_addstr(stdscr, y, x + 5 + bar_w, format_rate(rate), green)
            y += 1

    def _draw_history_chart(self, stdscr, y, x, w, h, history, green, bright):
        if h < 3:
            return
        samples = history[-min(50, w - 4) :]
        if not samples:
            self._safe_addstr(stdscr, y + h // 2, x, "Waiting for traffic samples...", green)
            return

        max_rate = max((max(s[1], s[2]) for s in samples), default=1.0) or 1.0
        chart_h = h - 2
        mid = y + 1 + chart_h // 2

        for col, (_, in_rate, out_rate) in enumerate(samples):
            px = x + col
            in_level = int((in_rate / max_rate) * (chart_h // 2 - 1))
            out_level = int((out_rate / max_rate) * (chart_h // 2 - 1))
            for row in range(in_level + 1):
                self._safe_addstr(stdscr, mid - row, px, "│", bright)
            for row in range(out_level + 1):
                self._safe_addstr(stdscr, mid + 1 + row, px, "│", green)
            self._safe_addstr(stdscr, mid, px, "─", green)

        self._safe_addstr(stdscr, y + h - 1, x, "in ↑", green)
        self._safe_addstr(stdscr, y + h - 1, x + 8, "out ↓", bright)

    def _draw_meter(self, stdscr, y, x, w, percent, green, bright, label):
        filled = int((percent / 100) * w)
        bar = "█" * filled + "░" * (w - filled)
        self._safe_addstr(stdscr, y, x, bar, bright)
        self._safe_addstr(stdscr, y, x + w + 2, label, green)
