"""The window on screens of different sizes and scalings (Windows' 100%, 150%, 200%... display scaling). Skipped without a display."""
import os
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    import tkinter as tk
    _r = tk.Tk()
    _r.destroy()
    HAVE_DISPLAY = True
except Exception:
    HAVE_DISPLAY = False

if HAVE_DISPLAY:
    from tkinter import font as tkfont
    from tkinter import ttk
    import frontier as fr
    import webcrawler_gui as g

# Tk's "scaling" is pixels per point: 1.333 on a 96-dpi screen (Windows 100%), 2.0 at 150%, 2.667 at 200%, 4.0 at 300%
SCENARIOS = [("100% on a small laptop", 1.333, 1366, 768), ("100% on full HD", 1.333, 1920, 1080), ("150% on full HD", 2.0, 1920, 1080),
             ("200% on 4K", 2.667, 3840, 2160), ("300% on 1440p", 4.0, 2560, 1440), ("125% on a small laptop", 1.667, 1366, 768)]


class Fitting(unittest.TestCase):
    def test_a_window_never_exceeds_a_share_of_the_screen(self):
        self.assertEqual(g.fit_to_screen(1300, 900, 1920, 1080), (1300, 900))
        self.assertEqual(g.fit_to_screen(1300, 900, 1366, 768), (1256, 706))
        self.assertEqual(g.fit_to_screen(1300, 900, 1366, 728, 0.90), (1229, 655))
        self.assertEqual(g.fit_to_screen(5000, 5000, 1000, 1000, 0.5), (500, 500))


@unittest.skipUnless(HAVE_DISPLAY, "no display available for Tk")
class Scaling(unittest.TestCase):
    def app(self, scaling, sw, sh):
        old = os.environ.get("WEBCRAWLER_TK_SCALING")
        os.environ["WEBCRAWLER_TK_SCALING"] = str(scaling)
        self.addCleanup(lambda: os.environ.pop("WEBCRAWLER_TK_SCALING", None) if old is None else os.environ.__setitem__("WEBCRAWLER_TK_SCALING", old))
        patch = mock.patch.object(g, "work_area", return_value=(0, 0, sw, sh))
        patch.start()
        self.addCleanup(patch.stop)
        a = g.App("https://example.com")
        self.addCleanup(self.close, a)
        a.update()
        return a

    @staticmethod
    def close(w):
        try:
            (w._close if hasattr(w, "_close") else w.destroy)()
        except tk.TclError:
            pass                                                           # already closed

    @staticmethod
    def geom(a):
        w, h, x, y = map(int, re.match(r"(\d+)x(\d+)([+-]\d+)([+-]\d+)", a.geometry()).groups())
        return w, h, x, y

    def test_the_window_fits_the_screen_and_keeps_its_parts(self):
        for name, scaling, sw, sh in SCENARIOS:
            with self.subTest(name):
                a = self.app(scaling, sw, sh)
                w, h, x, y = self.geom(a)
                self.assertLessEqual(w, sw * 0.90 + 1, name)
                self.assertLessEqual(h, sh * 0.90 + 1, name)
                self.assertGreaterEqual((x, y), (0, 0), name)
                self.assertAlmostEqual(g.UI, scaling / (96 / 72), delta=0.03)       # Tk rounds the scaling a little
                minw, minh = a.minsize()
                self.assertLessEqual((minw, minh), (sw * 0.85 + 1, sh * 0.85 + 1), name)
                self.assertLessEqual(minw, w)
                for child in a.winfo_children():             # nothing was squeezed out of the window
                    if isinstance(child, (ttk.Frame, ttk.Notebook)) and child.winfo_manager() == "pack":
                        self.assertTrue(child.winfo_ismapped(), f"{name}: {child} is not shown")
                self.close(a)

    def test_rows_are_tall_enough_for_the_text(self):
        for name, scaling, sw, sh in SCENARIOS:
            with self.subTest(name):
                a = self.app(scaling, sw, sh)
                rowheight = int(ttk.Style(a).lookup("Treeview", "rowheight"))
                linespace = tkfont.Font(a, font=g.FONT).metrics("linespace")
                self.assertGreaterEqual(rowheight, linespace + 2, f"{name}: rows would clip their text")
                col = a.ftv.column("title", "width")
                self.assertGreaterEqual(col, int(380 * g.UI * 0.99))
                self.assertGreaterEqual(g.px(300), 300 * g.UI - 1)
                self.close(a)

    def test_a_short_window_drops_the_thumbnails_to_leave_room_for_the_lists(self):
        for name, scaling, sw, sh in SCENARIOS:
            with self.subTest(name):
                a = self.app(scaling, sw, sh)
                wanted_h = g.fit_to_screen(1300 * g.UI, 900 * g.UI, sw, sh, 0.90)[1]            # what the window asked for (this test machine's real screen may be smaller)
                self.assertEqual(a.compact, wanted_h / g.UI < 780, name)
                self.assertEqual(a.thumbs["sentinel"] is None, a.compact, name)
                if a.compact:
                    self.assertTrue(a.skin_buttons["sentinel"].winfo_ismapped())            # still pickable, as a text button
                self.assertGreater(a.nb.winfo_height(), 200 * min(g.UI, 1.5), f"{name}: the lists get a usable amount of room")
                self.close(a)

    def test_crisp_images_on_big_screens(self):
        small = self.app(1.333, 1920, 1080)
        self.assertEqual(small.thumbs["sentinel"].width(), 56)
        self.close(small)
        big = self.app(2.667, 3840, 2160)
        self.assertEqual(big.thumbs["sentinel"].width(), 112)             # doubled, not stretched

    def test_the_settings_dialog_scrolls_instead_of_running_off_the_screen(self):
        for name, scaling, sw, sh in SCENARIOS:
            with self.subTest(name):
                a = self.app(scaling, sw, sh)
                dlg = g.AdvancedDialog(a, fr.CrawlOptions(), False, None, "example.com")
                self.addCleanup(self.close, dlg)
                a.update()
                dlg.update()
                w, h, x, y = self.geom(dlg)
                self.assertLessEqual(w, sw * 0.94 + 1, name)
                self.assertLessEqual(h, sh * 0.86 + 1, name)
                body = dlg.body
                need_w, need_h = body.inner.winfo_reqwidth(), body.inner.winfo_reqheight()
                x0, y0, x1, y1 = (int(float(v)) for v in body.canvas.cget("scrollregion").split())
                self.assertGreaterEqual((x1, y1), (need_w, need_h), f"{name}: the dialog's scroll area is smaller than its contents")
                if need_h > h:
                    self.assertTrue(body.vs.winfo_ismapped(), f"{name}: needs a vertical scrollbar")
                self.close(dlg)
                self.close(a)

    def test_a_dialog_still_works_when_scrolled(self):
        a = self.app(4.0, 1366, 768)                                       # 300% on a small screen: the worst case
        dlg = g.AdvancedDialog(a, fr.CrawlOptions(), False, None, "example.com")
        self.addCleanup(self.close, dlg)
        dlg.update()
        dlg.v["check_dns"].set(True)
        self.assertTrue(dlg.parse()["check_dns"])
        dlg.body.canvas.yview_moveto(1.0)
        dlg.update()
        self.assertGreater(dlg.body.canvas.yview()[0], 0)                   # it really scrolled
        dlg.destroy()

    def test_the_map_scales_its_nodes(self):
        a = self.app(2.667, 3840, 2160)
        import test_graph
        gr, _ = test_graph.shop(3, 20)
        a.graph.load_state(gr.to_state())
        a.nb.select(1)
        a.update()
        a._map_fit()
        a.update()
        ovals = [i for i in a.canvas.find_all() if a.canvas.type(i) == "oval"]
        self.assertTrue(ovals)
        x0, y0, x1, y1 = a.canvas.coords(ovals[-1])
        self.assertGreaterEqual(x1 - x0, 2 * g.px(4))                        # at least a scaled minimum radius


if __name__ == "__main__":
    unittest.main()
