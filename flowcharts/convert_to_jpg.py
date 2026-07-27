"""Convert SVG flowcharts to JPG format using svglib + reportlab."""
import os
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

pdfmetrics.registerFont(TTFont("SimHei", "C:/Windows/Fonts/simhei.ttf"))
pdfmetrics.registerFont(TTFont("MicrosoftYaHei", "C:/Windows/Fonts/msyh.ttc", subfontIndex=0))

from svglib.svglib import svg2rlg
from reportlab.graphics import renderPM
from reportlab.lib.colors import HexColor

svg_dir = r"C:\Users\txz\url_shorterner_9-3\flowcharts"
output_dir = r"C:\Users\txz\url_shorterner_9-3\flowcharts\jpg"
os.makedirs(output_dir, exist_ok=True)

svg_files = [
    "func_01_product_overview.svg",
    "func_02_create_link.svg",
    "func_03_click_redirect.svg",
    "func_04_manage_analytics.svg",
]

for svg_file in svg_files:
    svg_path = os.path.join(svg_dir, svg_file)
    jpg_path = os.path.join(output_dir, svg_file.replace(".svg", ".jpg"))

    if not os.path.exists(svg_path):
        print(f"SKIP (not found): {svg_file}")
        continue

    try:
        drawing = svg2rlg(svg_path)
        if drawing is None:
            print(f"FAIL: {svg_file} — svg2rlg returned None")
            continue

        renderPM.drawToFile(drawing, jpg_path, fmt="JPEG", dpi=144, bg=0xFFFFFF)
        size_kb = os.path.getsize(jpg_path) / 1024
        print(f"OK: {svg_file} -> {os.path.basename(jpg_path)} ({size_kb:.0f} KB)")

    except Exception as e:
        print(f"FAIL: {svg_file} — {e}")

print("\nDone!")
