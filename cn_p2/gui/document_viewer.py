"""PDF viewer that draws a recipient/time watermark on every displayed page."""

from datetime import datetime
from pathlib import Path
import io
import tkinter as tk
from tkinter import ttk

import pymupdf as fitz
from PIL import Image, ImageDraw, ImageFont
from .theme import COLORS


def render_page_with_watermark(page, recipient: str, timestamp: str, scale=1.15) -> bytes:
    """Rasterize one PDF page and return PNG bytes containing the visible watermark."""
    pix = page.get_pixmap(matrix=fitz.Matrix(scale, scale), alpha=False)
    image = Image.open(io.BytesIO(pix.tobytes("png"))).convert("RGBA")
    overlay = Image.new("RGBA", image.size, (255, 255, 255, 0))
    draw = ImageDraw.Draw(overlay)
    label = f"{recipient}  ·  {timestamp}"
    try:
        font = ImageFont.truetype("arial.ttf", max(14, image.width // 45))
    except OSError:
        font = ImageFont.load_default()
    for y in range(40, image.height, 190):
        for x in range(15, image.width, 340):
            draw.text((x, y), label, fill=(169, 133, 229, 115), font=font)
    image = Image.alpha_composite(image, overlay)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


class DocumentViewer(tk.Toplevel):
    def __init__(self, master, path, recipient: str):
        super().__init__(master)
        self.title(f"Document · {Path(path).name}")
        self.geometry("900x720")
        self.document = fitz.open(path)
        self.recipient = recipient
        self.timestamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
        self.index = 0
        bar = ttk.Frame(self, padding=8)
        bar.pack(fill="x")
        ttk.Button(bar, text="Previous", command=self.previous).pack(side="left")
        self.counter = ttk.Label(bar, text="")
        self.counter.pack(side="left", padx=12)
        ttk.Button(bar, text="Next", command=self.next).pack(side="left")
        ttk.Label(bar, text="Screenshots and external capture cannot be reliably prevented.").pack(side="right")
        self.configure(bg=COLORS["background"])
        self.canvas = tk.Canvas(self, bg=COLORS["card"], highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self.image_ref = None
        self.bind("<Configure>", lambda _e: self.render())
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.render()

    def render(self):
        if not self.winfo_exists() or not self.document:
            return
        page = self.document[self.index]
        png = render_page_with_watermark(page, self.recipient, self.timestamp)
        self.image_ref = tk.PhotoImage(data=png)
        self.canvas.delete("all")
        self.canvas.create_image(max(0, (self.winfo_width() - self.image_ref.width()) // 2), 8, image=self.image_ref, anchor="nw")
        self.counter.configure(text=f"Page {self.index + 1} / {len(self.document)}")

    def previous(self):
        if self.index:
            self.index -= 1
            self.render()

    def next(self):
        if self.index + 1 < len(self.document):
            self.index += 1
            self.render()

    def close(self):
        self.document.close()
        self.destroy()
