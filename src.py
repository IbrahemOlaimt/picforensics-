
import os
import sys
import io
import shutil
import datetime
import tempfile
import webbrowser
from pathlib import Path
from tkinter import (
    Tk, Frame, Menu, Button, Label, Text, BOTH, LEFT, RIGHT, TOP, BOTTOM, X, Y, NW,
    filedialog, messagebox, ttk, StringVar, Toplevel
)
from PIL import Image, ImageTk, ImageChops, ImageOps
import piexif
import numpy as np
import cv2
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas
import folium

def desktop_report_folder():
    p = Path.home() / "Desktop" / "PicForensics_Report"
    p.mkdir(parents=True, exist_ok=True)
    return p

def safe_save_image(img_pil, path, quality=90):
    img_pil.save(path, "JPEG", quality=quality)

def ensure_bytes_to_str(value):
    if isinstance(value, bytes):
        try:
            return value.decode(errors='ignore')
        except:
            return str(value)
    return str(value)

def extract_exif_dict(img_path):
    try:
        exif = piexif.load(img_path)
    except Exception:
        return {}
    readable = {}
    for ifd in exif:
        try:
            for tag, val in exif[ifd].items():
                tagname = piexif.TAGS.get(ifd, {}).get(tag, {}).get("name", str(tag))
                readable[f"{ifd}:{tagname}"] = val
        except Exception:
            continue
    return readable

def get_common_exif_fields(exif_dict):
    def find(name):
        for k, v in exif_dict.items():
            if name in k:
                return ensure_bytes_to_str(v)
        return None
    dt_original = find("DateTimeOriginal")
    dt = find("DateTime")
    make = find("Make")
    model = find("Model")
    width = find("ImageWidth") or find("PixelXDimension")
    height = find("ImageLength") or find("PixelYDimension")
    gps_lat = exif_dict.get("GPS:GPSLatitude")
    gps_lat_ref = exif_dict.get("GPS:GPSLatitudeRef")
    gps_lon = exif_dict.get("GPS:GPSLongitude")
    gps_lon_ref = exif_dict.get("GPS:GPSLongitudeRef")
    gps = None
    if gps_lat and gps_lon and gps_lat_ref and gps_lon_ref:
        try:
            lat = dms_to_deg(gps_lat)
            if ensure_bytes_to_str(gps_lat_ref).upper().startswith("S"):
                lat = -lat
            lon = dms_to_deg(gps_lon)
            if ensure_bytes_to_str(gps_lon_ref).upper().startswith("W"):
                lon = -lon
            gps = (lat, lon)
        except Exception:
            gps = None
    return {
        "DateTimeOriginal": dt_original,
        "DateTime": dt,
        "Make": make,
        "Model": model,
        "Dimensions": f"{width}x{height}" if width and height else None,
        "GPS": gps
    }

def dms_to_deg(dms):
    try:
        d = dms[0][0] / dms[0][1]
        m = dms[1][0] / dms[1][1]
        s = dms[2][0] / dms[2][1]
        return d + m/60.0 + s/3600.0
    except Exception:
        raise

def perform_ela_pil(img_path, quality=90):
    orig = Image.open(img_path).convert("RGB")
    temp = tempfile.NamedTemporaryFile(delete=False, suffix=".jpg")
    temp.close()
    orig.save(temp.name, "JPEG", quality=quality)
    resaved = Image.open(temp.name).convert("RGB")
    ela = ImageChops.difference(orig, resaved)
    arr = np.array(ela).astype(np.int32)
    arr = np.clip(arr * 10, 0, 255).astype(np.uint8)
    ela_img = Image.fromarray(arr)
    os.unlink(temp.name)
    return ela_img

def noise_residual(img_path):
    img = cv2.imdecode(np.fromfile(img_path, dtype=np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise RuntimeError("Cannot read image for noise residual")
    img_gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    den = cv2.fastNlMeansDenoising(img_gray, None, h=10, templateWindowSize=7, searchWindowSize=21)
    resid = cv2.subtract(img_gray, den)
    resid_norm = cv2.normalize(resid, None, 0, 255, cv2.NORM_MINMAX)
    resid_color = cv2.applyColorMap(resid_norm, cv2.COLORMAP_JET)
    pil = Image.fromarray(cv2.cvtColor(resid_color, cv2.COLOR_BGR2RGB))
    return pil

def image_histogram_pil(img_path):
    img = Image.open(img_path).convert("RGB")
    plt.figure(figsize=(4,2.5))
    colors = ('r','g','b')
    for i, col in enumerate(colors):
        hist = img.getchannel(i).histogram()
        plt.plot(hist, color=col)
    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format='PNG')
    plt.close()
    buf.seek(0)
    return Image.open(buf)

def produce_timeline_plot(exif_dict):
    dates = []
    labels = []
    d_orig = None
    d_mod = None
    for k, v in exif_dict.items():
        if "DateTimeOriginal" in k and v:
            try:
                d_orig = parse_exif_date(ensure_bytes_to_str(v))
            except:
                pass
        if "DateTime" in k and v:
            try:
                d_mod = parse_exif_date(ensure_bytes_to_str(v))
            except:
                pass
    if not d_orig and not d_mod:
        plt.figure(figsize=(4,1.4))
        plt.text(0.1, 0.5, "No timestamps available", fontsize=10)
        plt.axis('off')
        buf = io.BytesIO()
        plt.savefig(buf, format='PNG', bbox_inches='tight')
        plt.close()
        buf.seek(0)
        return Image.open(buf)
    x = []
    y = []
    ticks = []
    if d_orig:
        x.append(d_orig)
        y.append(1)
        ticks.append(("Original", d_orig))
    if d_mod:
        x.append(d_mod)
        y.append(1)
        ticks.append(("Modified", d_mod))
    xs = matplotlib.dates.date2num(x)
    plt.figure(figsize=(4,1.4))
    plt.hlines(1, xs.min()-0.1, xs.max()+0.1)
    plt.scatter(xs, y)
    for i, (lab, dt) in enumerate(ticks):
        plt.text(xs[i], 1.05, f"{lab}\n{dt.strftime('%Y-%m-%d %H:%M')}", ha='center', fontsize=8)
    plt.gca().yaxis.set_visible(False)
    plt.gca().xaxis.set_visible(False)
    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format='PNG', bbox_inches='tight')
    plt.close()
    buf.seek(0)
    return Image.open(buf)

def parse_exif_date(s):
    try:
        return datetime.datetime.strptime(s.strip(), "%Y:%m:%d %H:%M:%S")
    except:
        try:
            return datetime.datetime.strptime(s.strip(), "%Y:%m:%d")
        except:
            raise

def generate_warnings(exif_common, file_info):
    warnings = []
    dt_orig = exif_common.get("DateTimeOriginal")
    dt_mod = exif_common.get("DateTime")
    gps = exif_common.get("GPS")
    if dt_orig and dt_mod:
        try:
            d1 = parse_exif_date(dt_orig) if isinstance(dt_orig, str) else parse_exif_date(ensure_bytes_to_str(dt_orig))
            d2 = parse_exif_date(dt_mod) if isinstance(dt_mod, str) else parse_exif_date(ensure_bytes_to_str(dt_mod))
            if d2 < d1:
                warnings.append("Modification timestamp is earlier than creation timestamp.")
        except Exception:
            warnings.append("Timestamp parsing issue.")
    if not dt_orig and dt_mod:
        warnings.append("DateTimeOriginal missing; only Modify date present.")
    if not dt_orig and not dt_mod:
        warnings.append("No EXIF timestamps found.")
    if gps:
        lat, lon = gps
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            warnings.append("GPS coordinates out of range.")
    else:
        warnings.append("No GPS coordinates found in EXIF.")
    size_mb = file_info.get("size_mb", 0)
    dims = file_info.get("dimensions")
    if dims:
        try:
            w, h = dims
            mega_pixels = (w * h) / 1e6
            if mega_pixels > 6 and size_mb < 0.2:
                warnings.append("High-resolution image with very small file size (possible aggressive recompression).")
        except:
            pass
    return warnings

class ToolTip(object):
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tipwin = None
        widget.bind("<Enter>", self.show)
        widget.bind("<Leave>", self.hide)

    def show(self, _=None):
        if self.tipwin or not self.text:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + 20
        self.tipwin = tw = Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry("+%d+%d" % (x, y))
        label = Label(tw, text=self.text, justify='left', background="#ffffe0", relief='solid', borderwidth=1, font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)

    def hide(self, _=None):
        if self.tipwin:
            self.tipwin.destroy()
            self.tipwin = None

class PicForensicsApp:
    def __init__(self, master):
        self.master = master
        master.title("PicForensics")
        master.geometry("1100x700")
        self.theme = StringVar(value="light")
        self.create_menu()
        self.left_frame = Frame(master, width=700, relief="sunken", bd=1)
        self.left_frame.pack(side=LEFT, fill=BOTH, expand=True, padx=6, pady=6)

        self.right_frame = Frame(master, width=380, relief="sunken", bd=1)
        self.right_frame.pack(side=RIGHT, fill=Y, padx=6, pady=6)

        toolbar = Frame(self.left_frame)
        toolbar.pack(side=TOP, fill=X, padx=4, pady=4)
        btn_upload = Button(toolbar, text="Upload", bg="#2ecc71", command=self.upload_image)
        btn_ela = Button(toolbar, text="ELA", bg="#3498db", command=self.show_ela_view)
        btn_noise = Button(toolbar, text="Noise", bg="#e67e22", command=self.show_noise_view)
        btn_pixel = Button(toolbar, text="Pixel", bg="#9b59b6", command=self.show_original_view)
        btn_hist = Button(toolbar, text="Histogram", bg="#95a5a6", command=self.show_hist_view)
        btn_save = Button(toolbar, text="Save Report", bg="#34495e", fg="white", command=self.generate_report)
        btn_upload.pack(side=LEFT, padx=3); ToolTip(btn_upload, "Open image file(s) from disk (single or batch).")
        btn_ela.pack(side=LEFT, padx=3); ToolTip(btn_ela, "Show Error Level Analysis (ELA) view.")
        btn_noise.pack(side=LEFT, padx=3); ToolTip(btn_noise, "Show Noise Residual analysis (approx PRNU).")
        btn_pixel.pack(side=LEFT, padx=3); ToolTip(btn_pixel, "Show original image pixel view.")
        btn_hist.pack(side=LEFT, padx=3); ToolTip(btn_hist, "Show RGB histogram.")
        btn_save.pack(side=LEFT, padx=3); ToolTip(btn_save, "Generate and save a PDF report to Desktop/PicForensics_Report/")

        self.preview_label = Label(self.left_frame, text="Upload Image Here", bg="#dfe6e9", width=80, height=20, anchor="center")
        self.preview_label.pack(fill=BOTH, expand=True, padx=6, pady=6)

        self.status_label = Label(self.left_frame, text="Ready", anchor="w")
        self.status_label.pack(side=BOTTOM, fill=X)

        self.file_info_box = Text(self.right_frame, height=6, width=46)
        self.file_info_box.pack(padx=6, pady=6)
        self.file_info_box.config(state='disabled')

        lbl_meta = Label(self.right_frame, text="Metadata & Geo Tags", font=("Arial", 10, "bold"))
        lbl_meta.pack(anchor=NW, padx=6)
        self.meta_box = Text(self.right_frame, height=10, width=46)
        self.meta_box.pack(padx=6, pady=4)
        self.meta_box.config(state='disabled')

        lbl_results = Label(self.right_frame, text="Analysis Results", font=("Arial", 10, "bold"))
        lbl_results.pack(anchor=NW, padx=6)
        self.results_box = Text(self.right_frame, height=6, width=46)
        self.results_box.pack(padx=6, pady=4)
        self.results_box.config(state='disabled')

        lbl_timeline = Label(self.right_frame, text="Timeline", font=("Arial", 10, "bold"))
        lbl_timeline.pack(anchor=NW, padx=6)
        self.timeline_label = Label(self.right_frame, text="No timeline yet", width=40, height=4, bg="#ecf0f1")
        self.timeline_label.pack(padx=6, pady=4)

        self.warning_label = Label(master, text="", bg="#ffdddd", fg="darkred", font=("Arial", 10, "bold"))
        self.warning_label.pack(side=BOTTOM, fill=X, padx=6, pady=(0,6))

        self.current_image_path = None
        self.current_image_pil = None
        self.current_views = {}

        theme_btn = Button(self.right_frame, text="Toggle Theme", command=self.toggle_theme)
        theme_btn.pack(pady=6)

        self.batch_list = []
        self.current_batch_index = 0

    def create_menu(self):
        menubar = Menu(self.master)
        file_menu = Menu(menubar, tearoff=0)
        file_menu.add_command(label="Open Image(s)...", command=self.upload_image)
        file_menu.add_command(label="Save Report (PDF)", command=self.generate_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.master.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        analysis_menu = Menu(menubar, tearoff=0)
        analysis_menu.add_command(label="Run Integrity Check", command=self.check_integrity)
        analysis_menu.add_command(label="Show ELA", command=self.show_ela_view)
        analysis_menu.add_command(label="Show Noise Residual", command=self.show_noise_view)
        menubar.add_cascade(label="Analysis", menu=analysis_menu)

        view_menu = Menu(menubar, tearoff=0)
        view_menu.add_command(label="Show Original", command=self.show_original_view)
        view_menu.add_command(label="Show Histogram", command=self.show_hist_view)
        menubar.add_cascade(label="View", menu=view_menu)

        help_menu = Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=lambda: messagebox.showinfo("About", "PicForensics \nEXIF, ELA, Noise, Timeline, Report"))
        help_menu.add_command(label="Help/Manual", command=self.show_help_window)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.master.config(menu=menubar)

    def toggle_theme(self):
        if self.theme.get() == "light":
            self.theme.set("dark")
            self.master.configure(bg="#2c3e50")
            self.preview_label.configure(bg="#34495e", fg="white")
            self.status_label.configure(bg="#2c3e50", fg="white")
        else:
            self.theme.set("light")
            self.master.configure(bg="SystemButtonFace")
            self.preview_label.configure(bg="#dfe6e9", fg="black")
            self.status_label.configure(bg=self.master.cget("bg"), fg="black")

    def show_help_window(self):
        text = (
            "PicForensics Help\n\n"
            "1. Open Image(s): Select single or multiple images to analyze.\n"
            "2. Use toolbar to view Original, ELA, Noise, Histogram.\n"
            "3. Run 'Run Integrity Check' for automated checks and warnings.\n"
            "4. Generate Report saves PDF and copies image(s) to Desktop/PicForensics_Report.\n"
            "Notes: Noise Residual is an approximation. True PRNU requires camera references."
        )
        messagebox.showinfo("Help / Manual", text)

    def upload_image(self):
        paths = filedialog.askopenfilenames(filetypes=[("Image files","*.jpg;*.jpeg;*.png;*.tif;*.tiff")])
        if not paths:
            return
        self.batch_list = list(paths)
        self.current_batch_index = 0
        self.load_current_batch_image()

    def load_current_batch_image(self):
        if not self.batch_list:
            return
        path = self.batch_list[self.current_batch_index]
        self.load_image(path)

    def load_image(self, path):
        try:
            pil = Image.open(path).convert("RGB")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open image: {e}")
            return
        self.current_image_path = path
        self.current_image_pil = pil
        self.current_views['original'] = pil.copy()
        preview = pil.copy()
        preview.thumbnail((760, 520))
        tkimg = ImageTk.PhotoImage(preview)
        self.preview_label.config(image=tkimg, text="")
        self.preview_label.image = tkimg

        stat = Path(path).stat()
        size_mb = stat.st_size / (1024 * 1024)
        try:
            dims = pil.size
        except:
            dims = None
        self.file_info_box.config(state='normal')
        self.file_info_box.delete(1.0, "end")
        self.file_info_box.insert("end", f"File: {os.path.basename(path)}\n")
        self.file_info_box.insert("end", f"Path: {path}\n")
        self.file_info_box.insert("end", f"Size: {size_mb:.2f} MB\n")
        self.file_info_box.insert("end", f"Format: {pil.format}\n")
        self.file_info_box.insert("end", f"Dimensions: {dims}\n")
        self.file_info_box.config(state='disabled')

        exif = extract_exif_dict(path)
        self.meta_box.config(state='normal')
        self.meta_box.delete(1.0, "end")
        if exif:
            common = get_common_exif_fields(exif)
            self.meta_box.insert("end", f"Make: {common.get('Make')}\n")
            self.meta_box.insert("end", f"Model: {common.get('Model')}\n")
            self.meta_box.insert("end", f"DateTimeOriginal: {common.get('DateTimeOriginal')}\n")
            self.meta_box.insert("end", f"DateTime: {common.get('DateTime')}\n")
            self.meta_box.insert("end", f"Dimensions: {common.get('Dimensions')}\n")
            self.meta_box.insert("end", f"GPS: {common.get('GPS')}\n")
        else:
            self.meta_box.insert("end", "No EXIF metadata found.\n")
        self.meta_box.config(state='disabled')

        self.results_box.config(state='normal')
        self.results_box.delete(1.0, "end")
        self.results_box.config(state='disabled')
        self.warning_label.config(text="")

        tl_img = produce_timeline_plot(exif)
        tl_img.thumbnail((320, 90))
        tk_tl = ImageTk.PhotoImage(tl_img)
        self.timeline_label.config(image=tk_tl, text="")
        self.timeline_label.image = tk_tl

        self.status_label.config(text=f"Loaded: {os.path.basename(path)} ({self.current_batch_index+1}/{len(self.batch_list)})")

    def show_original_view(self):
        if not self.current_image_pil:
            return
        self._show_preview(self.current_views.get('original'))

    def show_ela_view(self):
        if not self.current_image_path:
            messagebox.showwarning("No image", "Please open an image first.")
            return
        if 'ela' not in self.current_views:
            self.status_label.config(text="Computing ELA...")
            ela_img = perform_ela_pil(self.current_image_path)
            self.current_views['ela'] = ela_img
            self.status_label.config(text="ELA ready.")
        self._show_preview(self.current_views['ela'])

    def show_noise_view(self):
        if not self.current_image_path:
            messagebox.showwarning("No image", "Please open an image first.")
            return
        if 'noise' not in self.current_views:
            self.status_label.config(text="Computing noise residual...")
            try:
                noise_img = noise_residual(self.current_image_path)
                self.current_views['noise'] = noise_img
            except Exception as e:
                messagebox.showerror("Noise Error", f"Noise residual failed: {e}")
                self.current_views['noise'] = None
            self.status_label.config(text="Noise ready.")
        if self.current_views['noise']:
            self._show_preview(self.current_views['noise'])

    def show_hist_view(self):
        if not self.current_image_path:
            return
        if 'hist' not in self.current_views:
            hist_img = image_histogram_pil(self.current_image_path)
            self.current_views['hist'] = hist_img
        self._show_preview(self.current_views['hist'])

    def _show_preview(self, pil_img):
        if pil_img is None:
            return
        img = pil_img.copy()
        img.thumbnail((760, 520))
        tkimg = ImageTk.PhotoImage(img)
        self.preview_label.config(image=tkimg, text="")
        self.preview_label.image = tkimg

    def check_integrity(self):
        if not self.current_image_path:
            messagebox.showwarning("No image", "Please open an image first.")
            return
        exif = extract_exif_dict(self.current_image_path)
        common = get_common_exif_fields(exif)
        stat = Path(self.current_image_path).stat()
        file_info = {"size_mb": stat.st_size/(1024*1024), "dimensions": self.current_image_pil.size}
        warnings = generate_warnings(common, file_info)
        ela_img = perform_ela_pil(self.current_image_path)
        noise_img = None
        try:
            noise_img = noise_residual(self.current_image_path)
        except:
            pass
        res_lines = []
        res_lines.append("Integrity Check Results:")
        res_lines.append(f"DateTimeOriginal: {common.get('DateTimeOriginal')}")
        res_lines.append(f"DateTime: {common.get('DateTime')}")
        res_lines.append(f"Make/Model: {common.get('Make')}/{common.get('Model')}")
        res_lines.append(f"GPS: {common.get('GPS')}")
        res_lines.append(f"Warnings: {len(warnings)}")
        self.results_box.config(state='normal')
        self.results_box.delete(1.0, "end")
        for r in res_lines:
            self.results_box.insert("end", r + "\n")
        if warnings:
            self.results_box.insert("end", "\nDetailed warnings:\n")
            for w in warnings:
                self.results_box.insert("end", " - " + w + "\n")
            self.warning_label.config(text="⚠ Suspicious findings detected. See Analysis Results.")
        else:
            self.warning_label.config(text="No suspicious automatic findings.")
        self.results_box.config(state='disabled')

        self.current_views['ela'] = ela_img
        if noise_img:
            self.current_views['noise'] = noise_img

    def open_map(self):
        if not self.current_image_path:
            messagebox.showwarning("No image", "Load an image with GPS first.")
            return
        exif = extract_exif_dict(self.current_image_path)
        common = get_common_exif_fields(exif)
        gps = common.get("GPS")
        if not gps:
            messagebox.showwarning("No GPS", "No GPS data in EXIF.")
            return
        lat, lon = gps
        m = folium.Map(location=[lat, lon], zoom_start=16)
        folium.Marker([lat, lon], popup=os.path.basename(self.current_image_path)).add_to(m)
        tmp = desktop_report_folder() / "map_preview.html"
        m.save(str(tmp))
        webbrowser.open(str(tmp))

    def generate_report(self):
        if not self.batch_list:
            messagebox.showwarning("No images", "Please load image(s) first.")
            return
        folder = desktop_report_folder()
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        outdir = folder / f"PicForensics_{timestamp}"
        outdir.mkdir(parents=True, exist_ok=True)

        for idx, imgpath in enumerate(self.batch_list, start=1):
            try:
                self.load_image(imgpath)
                exif = extract_exif_dict(imgpath)
                common = get_common_exif_fields(exif)
                ela = perform_ela_pil(imgpath)
                try:
                    noise = noise_residual(imgpath)
                except:
                    noise = None
                hist = image_histogram_pil(imgpath)
                timeline = produce_timeline_plot(exif)

                base = Path(imgpath).stem
                copy_img_path = outdir / f"{base}_original.jpg"
                orig_img = Image.open(imgpath).convert("RGB")
                orig_img.save(copy_img_path, "JPEG", quality=95)

                ela_path = outdir / f"{base}_ela.jpg"
                ela.save(ela_path, "JPEG", quality=90)
                if noise:
                    noise_path = outdir / f"{base}_noise.jpg"
                    noise.save(noise_path, "JPEG", quality=90)
                hist_path = outdir / f"{base}_hist.png"
                hist.save(hist_path, "PNG")
                tl_path = outdir / f"{base}_timeline.png"
                timeline.save(tl_path, "PNG")

                pdf_path = outdir / f"{base}_report.pdf"
                self._create_pdf_report(str(pdf_path), imgpath, exif, common, str(copy_img_path),
                                        str(ela_path), str(noise_path if noise else ""), str(hist_path), str(tl_path))
            except Exception as e:
                print("Report error:", e)

        messagebox.showinfo("Report", f"Reports and assets saved in:\n{outdir}")
        webbrowser.open(str(outdir))

    def _create_pdf_report(self, pdf_path, imgpath, exif, common, orig_copy, ela_path, noise_path, hist_path, tl_path):
        c = canvas.Canvas(pdf_path, pagesize=A4)
        w, h = A4
        c.setFont("Helvetica-Bold", 16)
        c.drawString(40, h - 50, "PicForensics - Analysis Report")
        c.setFont("Helvetica", 10)
        c.drawString(40, h - 70, f"Source Image: {os.path.basename(imgpath)}")
        c.drawString(40, h - 85, f"Generated: {datetime.datetime.now().isoformat()}")
        try:
            im = Image.open(orig_copy)
            aspect = im.width / im.height
            iw = 220
            ih = iw / aspect
            c.drawImage(ImageReader(im), 40, h - 90 - ih, width=iw, height=ih)
        except Exception:
            pass
        try:
            tl = Image.open(tl_path)
            c.drawImage(ImageReader(tl), 300, h - 140, width=240, height=80)
        except:
            pass

        y = h - 250
        c.setFont("Helvetica-Bold", 12)
        c.drawString(40, y, "Extracted Metadata (selected)")
        y -= 14
        c.setFont("Helvetica", 9)
        c.drawString(40, y, f"Make: {common.get('Make')}, Model: {common.get('Model')}")
        y -= 12
        c.drawString(40, y, f"DateTimeOriginal: {common.get('DateTimeOriginal')}")
        y -= 12
        c.drawString(40, y, f"GPS: {common.get('GPS')}")
        y -= 20

        warnings = generate_warnings(common, {"size_mb": Path(imgpath).stat().st_size/(1024*1024),
                                             "dimensions": Image.open(imgpath).size})
        c.setFont("Helvetica-Bold", 12)
        c.drawString(40, y, "Analysis Summary")
        y -= 14
        c.setFont("Helvetica", 9)
        if warnings:
            for wmsg in warnings:
                c.drawString(40, y, f" - {wmsg}")
                y -= 12
        else:
            c.drawString(40, y, "No automated warnings detected.")
            y -= 12

        xthumb = 40
        ythumb = y - 10
        try:
            ela = Image.open(ela_path)
            ela.thumbnail((200, 150))
            c.drawImage(ImageReader(ela), xthumb, ythumb - 150, width=200, height=150)
            c.drawString(xthumb, ythumb - 160, "ELA")
            xthumb += 220
        except:
            pass
        try:
            if noise_path:
                noise = Image.open(noise_path)
                noise.thumbnail((200, 150))
                c.drawImage(ImageReader(noise), xthumb, ythumb - 150, width=200, height=150)
                c.drawString(xthumb, ythumb - 160, "Noise Residual")
            xthumb += 220
        except:
            pass

        c.showPage()
        c.save()

    def show_about(self):
        messagebox.showinfo("About", "PicForensics \nBuilt for image metadata & tamper analysis.")

def main():
    root = Tk()
    app = PicForensicsApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
