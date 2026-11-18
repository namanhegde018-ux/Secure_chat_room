import io
import pymupdf
from PIL import Image, ImageChops
from gui.document_viewer import render_page_with_watermark


def test_pdf_watermark_rasterization_changes_page_image():
    doc = pymupdf.open()
    page = doc.new_page(width=595, height=842)
    page.insert_text((80, 120), "Confidential document", fontsize=18)
    clean = Image.open(io.BytesIO(page.get_pixmap(matrix=pymupdf.Matrix(1.15, 1.15)).tobytes("png"))).convert("RGB")
    marked = Image.open(io.BytesIO(render_page_with_watermark(page, "Recipient", "2026-11-03 10:00 IST"))).convert("RGB")
    assert ImageChops.difference(clean, marked).getbbox() is not None
    doc.close()
