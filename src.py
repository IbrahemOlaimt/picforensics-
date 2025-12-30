import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog, Toplevel
from PIL import Image, ImageTk, ImageEnhance, ImageChops
import os
import numpy as np
import cv2
import shutil
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
import json
import io
import warnings
import pyexiv2
from PIL.ExifTags import TAGS
from datetime import datetime, timedelta
import tempfile
import exifread
from geopy.geocoders import Nominatim
from geopy.exc import GeocoderTimedOut
import hashlib
from pathlib import Path
from dataclasses import dataclass
from skimage.util import view_as_blocks
import matplotlib

# Use Agg backend for matplotlib to avoid GUI issues
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

warnings.filterwarnings('ignore')


# ========== HASH FUNCTIONS ==========
def compute_image_hash(file_path: str) -> str:
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    return sha.hexdigest()


def _load_hash_registry(registry_file: str):
    try:
        if os.path.exists(registry_file):
            with open(registry_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
    except Exception:
        pass
    return []


def _save_hash_registry(registry_file: str, registry_list):
    # atomic-ish save
    tmp = registry_file + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(registry_list, f, indent=4, ensure_ascii=False)
    os.replace(tmp, registry_file)


def save_hash_to_registry(registry_file: str, key: str, img_hash: str, meta: dict | None = None):
    registry = _load_hash_registry(registry_file)
    registry = [e for e in registry if e.get("key") != key]
    entry = {
        "key": key,
        "hash": img_hash,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    if meta:
        entry.update(meta)
    registry.append(entry)
    _save_hash_registry(registry_file, registry)


def get_previous_hash(registry_file: str, key: str):
    registry = _load_hash_registry(registry_file)
    for e in registry:
        if e.get("key") == key:
            return e.get("hash")
    return None


def compare_hashes(old_hash: str | None, new_hash: str) -> str:
    if old_hash is None:
        return "FIRST"
    if old_hash == new_hash:
        return "MATCH"
    return "MODIFIED"


def compute_case_hash(image_paths: list[str]) -> str:
    pairs = []
    for p in sorted(image_paths, key=lambda x: os.path.basename(x).lower()):
        try:
            pairs.append(f"{os.path.basename(p)}:{compute_image_hash(p)}")
        except Exception:
            pairs.append(f"{os.path.basename(p)}:ERROR")
    combined = "\n".join(pairs).encode("utf-8", errors="ignore")
    return hashlib.sha256(combined).hexdigest()


# ========== END HASH FUNCTIONS ==========

def compute_ela(image_path, q=90):
    try:
        if isinstance(image_path, str):
            orig = Image.open(image_path).convert('RGB')
        else:
            orig = image_path.convert('RGB') if hasattr(image_path, 'convert') else Image.open(
                io.BytesIO(image_path)).convert('RGB')
        buffer = io.BytesIO()
        orig.save(buffer, "JPEG", quality=q)
        buffer.seek(0)
        recompressed = Image.open(buffer)
        diff = ImageChops.difference(orig, recompressed)
        extrema = diff.getextrema()
        max_diff = max([e[1] for e in extrema]) or 1
        scale = 255.0 / max_diff
        ela_img = ImageEnhance.Brightness(diff).enhance(scale)
        return ela_img
    except Exception as e:
        return None


def extract_noise_stat(img):
    if isinstance(img, str):
        img = Image.open(img)
    gray = img.convert("L")
    arr = np.asarray(gray).astype(np.float32)
    lap = cv2.Laplacian(arr, cv2.CV_32F)
    return lap


def derive_key_from_password(password, salt):
    key = PBKDF2(password, salt, dkLen=16, count=100000)
    return key


def encrypt_image_data(image_data, password):
    try:
        salt = get_random_bytes(16)
        key = derive_key_from_password(password, salt)
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(pad(image_data, AES.block_size))
        return salt + iv + encrypted_data
    except Exception as e:
        return None


def decrypt_image_data(encrypted_data, password):
    try:
        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        encrypted_content = encrypted_data[32:]
        key = derive_key_from_password(password, salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_content), AES.block_size)
        return decrypted_data
    except Exception as e:
        return None


@dataclass
class ForensicAnalysis:
    tampering_indicators: list
    consistency_score: float
    editing_software_detected: list


class AdvancedMetadataExtractor:
    def __init__(self, enable_cache: bool = True, enable_geocoding: bool = True):
        self.enable_cache = enable_cache
        self.enable_geocoding = enable_geocoding
        self.cache = {}
        self.geolocator = None

        if enable_geocoding:
            try:
                self.geolocator = Nominatim(user_agent="metadata_extractor_v1")
            except:
                self.geolocator = None

        self.editing_software_indicators = [
            'photoshop', 'adobe', 'lightroom', 'gimp', 'paint.net',
            'affinity', 'coreldraw', 'photoscape', 'paintshop', 'capture'
        ]

        self.camera_brand_patterns = {
            'canon': ['canon', 'eos', 'powershot', 'ixus'],
            'nikon': ['nikon', 'd', 'coolpix', 'z'],
            'sony': ['sony', 'dsc', 'alpha', 'cyber-shot'],
            'fujifilm': ['fujifilm', 'finepix', 'x-', 'gf'],
            'panasonic': ['panasonic', 'lumix'],
            'olympus': ['olympus', 'om-d', 'pen'],
            'apple': ['apple', 'iphone', 'ipad'],
            'samsung': ['samsung', 'galaxy']
        }

    def extract_comprehensive_metadata(self, image_path):
        try:
            cache_key = self._generate_cache_key(image_path)
            if self.enable_cache and cache_key in self.cache:
                return self.cache[cache_key]

            if not self._validate_file(image_path):
                return {"error": "Invalid image file or file not found"}

            metadata = self._extract_all_exif_data(image_path)

            if not metadata:
                return {"error": "No metadata found in image"}

            result = {
                "file_information": self._get_file_information(image_path),
                "camera_information": self._extract_camera_info(metadata),
                "shooting_parameters": self._extract_shooting_parameters(metadata),
                "image_properties": self._extract_image_properties(metadata),
                "gps_data": self._extract_gps_data(metadata),
                "date_time_information": self._extract_datetime_info(metadata),
                "software_info": self._extract_software_info(metadata),
                "forensic_analysis": self._perform_forensic_analysis(metadata)
            }

            result = {k: v for k, v in result.items() if v}

            if self.enable_cache:
                self.cache[cache_key] = result

            return result

        except Exception as e:
            return {"error": f"Extraction failed: {str(e)}"}

    def _validate_file(self, image_path):
        if not os.path.exists(image_path):
            return False

        valid_extensions = {'.jpg', '.jpeg', '.png', '.tiff', '.tif', '.heic', '.webp', '.bmp', '.gif'}
        return Path(image_path).suffix.lower() in valid_extensions

    def _generate_cache_key(self, file_path):
        try:
            stat = os.stat(file_path)
            key_data = f"{file_path}_{stat.st_size}_{stat.st_mtime}"
            return hashlib.md5(key_data.encode()).hexdigest()
        except:
            return hashlib.md5(file_path.encode()).hexdigest()

    def _extract_all_exif_data(self, image_path):
        metadata = {}

        try:
            with open(image_path, 'rb') as f:
                tags = exifread.process_file(f, details=False)

                for tag, value in tags.items():
                    if tag not in ['JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote']:
                        metadata[str(tag)] = self._clean_value(value)

        except Exception:
            return {}

        return metadata

    def _clean_value(self, value):
        if hasattr(value, 'printable'):
            return str(value.printable)
        elif isinstance(value, bytes):
            try:
                return value.decode('utf-8', errors='ignore').strip()
            except:
                return str(value)[:100]
        return str(value)

    def _get_file_information(self, image_path):
        try:
            stat = os.stat(image_path)
            info = {
                "file_name": os.path.basename(image_path),
                "file_size_bytes": stat.st_size,
                "file_size_human": self._format_bytes(stat.st_size),
                "file_extension": Path(image_path).suffix.lower(),
                "last_modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "file_hash_md5": self._calculate_file_hash(image_path)
            }
            return info
        except:
            return {}

    def _calculate_file_hash(self, file_path):
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except:
            return ""

    def _extract_camera_info(self, metadata):
        info = {}

        camera_mapping = {
            'Make': 'make',
            'Model': 'model',
            'BodySerialNumber': 'serial_number',
            'LensModel': 'lens_model',
            'LensSerialNumber': 'lens_serial',
            'LensMake': 'lens_make',
            'FocalLength': 'focal_length'
        }

        for exif_field, output_field in camera_mapping.items():
            for prefix in ['', 'EXIF ', 'Image ']:
                key = f"{prefix}{exif_field}"
                if key in metadata and metadata[key]:
                    info[output_field] = metadata[key]
                    break

        return info if info else {}

    def _extract_shooting_parameters(self, metadata):
        params = {}

        shooting_mapping = {
            'ExposureTime': 'exposure_time',
            'FNumber': 'f_number',
            'ISOSpeedRatings': 'iso',
            'ExposureProgram': 'exposure_program',
            'ExposureMode': 'exposure_mode',
            'ExposureBiasValue': 'exposure_compensation',
            'MeteringMode': 'metering_mode',
            'Flash': 'flash',
            'WhiteBalance': 'white_balance'
        }

        for exif_field, output_field in shooting_mapping.items():
            for prefix in ['', 'EXIF ']:
                key = f"{prefix}{exif_field}"
                if key in metadata and metadata[key]:
                    params[output_field] = metadata[key]
                    break

        return params if params else {}

    def _extract_image_properties(self, metadata):
        props = {}

        property_mapping = {
            'ImageWidth': 'width',
            'ImageLength': 'height',
            'ExifImageWidth': 'exif_width',
            'ExifImageHeight': 'exif_height',
            'XResolution': 'x_resolution',
            'YResolution': 'y_resolution',
            'Orientation': 'orientation',
            'ColorSpace': 'color_space'
        }

        for exif_field, output_field in property_mapping.items():
            for prefix in ['', 'Image ', 'EXIF ']:
                key = f"{prefix}{exif_field}"
                if key in metadata and metadata[key]:
                    props[output_field] = metadata[key]
                    break

        return props if props else {}

    def _extract_gps_data(self, metadata):
        gps_data = {}

        try:
            lat_key = 'GPS GPSLatitude'
            lat_ref_key = 'GPS GPSLatitudeRef'
            lon_key = 'GPS GPSLongitude'
            lon_ref_key = 'GPS GPSLongitudeRef'

            if lat_key in metadata and lat_ref_key in metadata and lon_key in metadata and lon_ref_key in metadata:
                lat = self._convert_gps_coordinate(metadata[lat_key])
                lat_ref = str(metadata[lat_ref_key])
                if lat_ref.upper() == 'S':
                    lat = -lat

                lon = self._convert_gps_coordinate(metadata[lon_key])
                lon_ref = str(metadata[lon_ref_key])
                if lon_ref.upper() == 'W':
                    lon = -lon

                if -90 <= lat <= 90 and -180 <= lon <= 180:
                    gps_data["latitude"] = lat
                    gps_data["longitude"] = lon

                    if self.geolocator:
                        try:
                            location = self.geolocator.reverse(
                                f"{lat}, {lon}",
                                timeout=5
                            )
                            if location and location.address:
                                gps_data["address"] = location.address[:200]
                        except:
                            pass

            altitude_key = 'GPS GPSAltitude'
            if altitude_key in metadata:
                try:
                    alt_str = str(metadata[altitude_key])
                    if ' ' in alt_str:
                        alt_str = alt_str.split()[0]
                    altitude = float(alt_str)
                    gps_data["altitude"] = altitude
                except:
                    pass

        except:
            return {}

        return gps_data if gps_data else {}

    def _convert_gps_coordinate(self, gps_str):
        try:
            if isinstance(gps_str, str):
                gps_str = gps_str.replace('[', '').replace(']', '')
                parts = [p.strip() for p in gps_str.split(',')]

                if len(parts) == 3:
                    def parse_part(part):
                        if '/' in part:
                            num, den = part.split('/')
                            return float(num) / float(den)
                        return float(part)

                    degrees = parse_part(parts[0])
                    minutes = parse_part(parts[1])
                    seconds = parse_part(parts[2])

                    return degrees + (minutes / 60.0) + (seconds / 3600.0)
        except:
            pass

        try:
            return float(gps_str)
        except:
            return 0.0

    def _extract_datetime_info(self, metadata):
        datetime_info = {}

        datetime_mapping = {
            'DateTimeOriginal': 'original_date',
            'DateTimeDigitized': 'digitized_date',
            'DateTime': 'file_modification_date',
            'CreateDate': 'creation_date'
        }

        for exif_field, output_field in datetime_mapping.items():
            for prefix in ['', 'EXIF ', 'Image ']:
                key = f"{prefix}{exif_field}"
                if key in metadata and metadata[key]:
                    datetime_info[output_field] = metadata[key]
                    break

        return datetime_info if datetime_info else {}

    def _extract_software_info(self, metadata):
        software_info = {}

        if 'Software' in metadata and metadata['Software']:
            software_info["software"] = metadata['Software']

        if 'Copyright' in metadata and metadata['Copyright']:
            software_info["copyright"] = metadata['Copyright']

        if 'Artist' in metadata and metadata['Artist']:
            software_info["artist"] = metadata['Artist']

        return software_info if software_info else {}

    def _perform_forensic_analysis(self, metadata):
        analysis = {
            "consistency_score": 1.0,
            "editing_software_detected": []
        }

        software = str(metadata.get('EXIF Software', '')).lower()
        if software:
            detected = []
            for indicator in self.editing_software_indicators:
                if indicator in software:
                    detected.append(indicator.title())
            if detected:
                analysis["editing_software_detected"] = detected
                analysis["consistency_score"] *= 0.9

        time_issues = self._analyze_time_inconsistencies(metadata)
        if time_issues:
            analysis["consistency_score"] *= 0.8

        device_issues = self._analyze_device_inconsistencies(metadata)
        if device_issues:
            analysis["consistency_score"] *= 0.85

        analysis["consistency_score"] = round(max(0.0, min(1.0, analysis["consistency_score"])), 2)

        return analysis

    def _analyze_time_inconsistencies(self, metadata):
        issues = []

        time_data = {}
        time_keys = [
            ('EXIF DateTimeOriginal', 'original'),
            ('EXIF CreateDate', 'creation'),
            ('EXIF ModifyDate', 'modification'),
            ('Image DateTime', 'file_modification')
        ]

        for key, name in time_keys:
            if key in metadata and metadata[key]:
                try:
                    dt_str = str(metadata[key])
                    dt = datetime.strptime(dt_str, '%Y:%m:%d %H:%M:%S')
                    time_data[name] = dt
                except:
                    pass

        if len(time_data) >= 2:
            times = list(time_data.values())
            time_diff = max(times) - min(times)

            if time_diff > timedelta(days=365):
                issues.append(f"Time discrepancy > 1 year")
            elif time_diff > timedelta(days=30):
                issues.append(f"Time discrepancy > 30 days")

        return issues

    def _analyze_device_inconsistencies(self, metadata):
        issues = []

        make = str(metadata.get('EXIF Make', '')).lower().strip()
        model = str(metadata.get('EXIF Model', '')).lower().strip()

        if not make or not model:
            return issues

        brand_found = False
        for brand, patterns in self.camera_brand_patterns.items():
            if brand in make:
                brand_found = True
                if not any(pattern in model for pattern in patterns):
                    issues.append("Device model inconsistency")
                break

        if not brand_found and len(make) > 2:
            issues.append("Unknown camera brand")

        return issues

    def _format_bytes(self, bytes_num):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_num < 1024.0 or unit == 'GB':
                return f"{bytes_num:.2f} {unit}"
            bytes_num /= 1024.0
        return f"{bytes_num:.2f} TB"


class AIDetectionAnalyzer:
    def __init__(self):
        self.BLOCK_SIZE = 8
        self.T_BLOCKS = 64
        self.LAPLACIAN = np.array([
            [0, 1, 0],
            [1, -4, 1],
            [0, 1, 0]
        ])

    def analyze_noise_correlation(self, image_path):
        try:
            img = cv2.imread(image_path)
            if img is None:
                return None

            # Ensure image has proper dimensions for analysis
            if img.shape[0] < self.BLOCK_SIZE or img.shape[1] < self.BLOCK_SIZE:
                # Resize small images
                min_size = max(self.BLOCK_SIZE * 2, 32)
                if img.shape[0] < min_size or img.shape[1] < min_size:
                    scale = max(min_size / img.shape[0], min_size / img.shape[1])
                    new_width = int(img.shape[1] * scale)
                    new_height = int(img.shape[0] * scale)
                    img = cv2.resize(img, (new_width, new_height))

            img = cv2.cvtColor(img, cv2.COLOR_BGR2YCrCb)
            Y, Cr, Cb = cv2.split(img)

            channels = {
                "Y": Y,
                "Cb": Cb,
                "Cr": Cr
            }

            correlation_results = {}

            for name, channel in channels.items():
                noise = cv2.filter2D(channel.astype(np.float32), -1, self.LAPLACIAN)

                h, w = noise.shape
                h_trim = h - (h % self.BLOCK_SIZE)
                w_trim = w - (w % self.BLOCK_SIZE)
                noise = noise[:h_trim, :w_trim]

                blocks = view_as_blocks(noise, block_shape=(self.BLOCK_SIZE, self.BLOCK_SIZE))
                blocks = blocks.reshape(-1, self.BLOCK_SIZE * self.BLOCK_SIZE)

                means = np.mean(blocks, axis=1)
                variances = np.var(blocks, axis=1)

                idx_mean = np.argsort(np.abs(means))[:self.T_BLOCKS]
                idx_var = np.argsort(variances)[:self.T_BLOCKS]

                selected_idx = np.unique(np.concatenate([idx_mean, idx_var]))
                selected_blocks = blocks[selected_idx]

                if selected_blocks.shape[0] < self.T_BLOCKS:
                    selected_blocks = blocks[np.argsort(variances)[:self.T_BLOCKS]]

                corr_matrix = np.corrcoef(selected_blocks, rowvar=False)
                corr_matrix = np.nan_to_num(corr_matrix)

                correlation_results[name] = corr_matrix

            return correlation_results
        except Exception as e:
            print(f"AI Detection Error: {str(e)}")
            return None

    def visualize_results(self, correlation_results, parent_window=None):
        """Visualize results within the tool's interface"""
        try:
            if parent_window is None:
                # Create a new window
                fig, axes = plt.subplots(1, 3, figsize=(15, 5))
                fig.suptitle("Noise Correlation Matrices (Y / Cb / Cr)", fontsize=14)

                for idx, (name, corr_matrix) in enumerate(correlation_results.items()):
                    ax = axes[idx]
                    im = ax.imshow(corr_matrix, cmap="hot")
                    ax.set_title(f"{name} Channel")
                    ax.axis("off")
                    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)

                plt.tight_layout()
                plt.show()
            else:
                # Display in the tool's interface
                self.display_in_tool_interface(correlation_results, parent_window)

        except Exception as e:
            print(f"Visualization Error: {str(e)}")
            if parent_window:
                messagebox.showerror("Visualization Error", f"Failed to display AI detection results: {str(e)}")

    def display_in_tool_interface(self, correlation_results, parent_window):
        """Display AI detection results in the tool's interface"""
        try:
            # Create a new window for AI detection results
            ai_window = tk.Toplevel(parent_window)
            ai_window.title("AI Detection - Noise Correlation Analysis")
            ai_window.geometry("900x600")
            ai_window.configure(bg="white")

            # Create a frame for the plots
            plot_frame = tk.Frame(ai_window, bg="white")
            plot_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            # Create matplotlib figure
            fig, axes = plt.subplots(1, 3, figsize=(12, 4))
            fig.suptitle("Noise Correlation Matrices (Y / Cb / Cr)", fontsize=14)

            for idx, (name, corr_matrix) in enumerate(correlation_results.items()):
                ax = axes[idx]
                im = ax.imshow(corr_matrix, cmap="hot")
                ax.set_title(f"{name} Channel", fontsize=12)
                ax.axis("off")
                fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)

            plt.tight_layout()

            # Embed matplotlib figure in tkinter window
            canvas = FigureCanvasTkAgg(fig, master=plot_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

            # Add analysis information
            info_frame = tk.Frame(ai_window, bg="white")
            info_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

            info_text = """
            AI Detection Analysis Results:

            • Y Channel (Luminance): Shows brightness correlations
            • Cb Channel (Blue-Yellow): Shows color correlations in blue-yellow axis
            • Cr Channel (Red-Green): Shows color correlations in red-green axis

            Interpretation:
            - Natural images typically show random noise patterns
            - AI-generated or heavily edited images may show regular patterns
            - Uniform or grid-like patterns may indicate digital manipulation
            """

            info_label = tk.Label(info_frame, text=info_text, justify=tk.LEFT,
                                  font=("Arial", 9), bg="white", fg="#333")
            info_label.pack(side=tk.LEFT, padx=10)

            # Add close button
            close_btn = tk.Button(ai_window, text="Close", command=ai_window.destroy,
                                  bg="#2196f3", fg="white", font=("Arial", 10))
            close_btn.pack(pady=10)

            # Store reference to prevent garbage collection
            ai_window.fig = fig
            ai_window.canvas = canvas

        except Exception as e:
            print(f"Interface Display Error: {str(e)}")
            messagebox.showerror("Display Error", f"Failed to display AI detection results: {str(e)}")


class AdvancedImageTimelineAnalyzer:
    def __init__(self):
        self.date_format = "%Y:%m:%d %H:%M:%S"

    class ImageAnalysisResult:
        def __init__(self, file_name):
            self.file_name = file_name
            self.date_time_results = {}
            self.file_system_dates = {}
            self.exif_dates = {}
            self.best_guess_date = ""
            self.camera_info = {}
            self.gps_info = {}

    def analyze_image(self, image_path):
        result = self.ImageAnalysisResult(os.path.basename(image_path))
        try:
            self.analyze_file_system_dates(image_path, result)
            self.analyze_exif_metadata(image_path, result)
            self.analyze_camera_info(image_path, result)
            self.analyze_gps_info(image_path, result)
            self.determine_best_guess_date(result)
            self.compile_all_results(result)
        except Exception as e:
            result.date_time_results["ERROR"] = f"Failed to analyze image: {str(e)}"
        return result

    def analyze_file_system_dates(self, image_path, result):
        try:
            stat_info = os.stat(image_path)
            creation_time = datetime.fromtimestamp(stat_info.st_ctime)
            modified_time = datetime.fromtimestamp(stat_info.st_mtime)
            access_time = datetime.fromtimestamp(stat_info.st_atime)
            result.file_system_dates["FileCreationTime"] = creation_time.strftime(self.date_format)
            result.file_system_dates["FileModifiedTime"] = modified_time.strftime(self.date_format)
            result.file_system_dates["FileAccessTime"] = access_time.strftime(self.date_format)
        except Exception as e:
            result.file_system_dates["ERROR"] = "File system analysis failed"

    def analyze_exif_metadata(self, image_path, result):
        try:
            self.extract_exif_with_pil(image_path, result)
            self.extract_exif_with_pyexiv2(image_path, result)
        except Exception as e:
            result.exif_dates["ERROR"] = "EXIF metadata analysis failed"

    def analyze_camera_info(self, image_path, result):
        try:
            with pyexiv2.Image(image_path) as img:
                exif_data = img.read_exif()
                camera_tags = {
                    'Exif.Image.Make': 'Camera Make',
                    'Exif.Image.Model': 'Camera Model',
                    'Exif.Photo.FNumber': 'Aperture',
                    'Exif.Photo.ExposureTime': 'Exposure Time',
                    'Exif.Photo.ISOSpeedRatings': 'ISO',
                    'Exif.Photo.FocalLength': 'Focal Length'
                }
                for exif_tag, friendly_name in camera_tags.items():
                    if exif_tag in exif_data:
                        result.camera_info[friendly_name] = exif_data[exif_tag]
        except:
            pass

    def analyze_gps_info(self, image_path, result):
        try:
            with pyexiv2.Image(image_path) as img:
                exif_data = img.read_exif()
                gps_tags = {
                    'Exif.GPSInfo.GPSLatitude': 'Latitude',
                    'Exif.GPSInfo.GPSLongitude': 'Longitude',
                    'Exif.GPSInfo.GPSAltitude': 'Altitude'
                }
                for exif_tag, friendly_name in gps_tags.items():
                    if exif_tag in exif_data:
                        result.gps_info[friendly_name] = exif_data[exif_tag]
        except:
            pass

    def extract_exif_with_pil(self, image_path, result):
        try:
            with Image.open(image_path) as img:
                exif_data = img._getexif()
                if exif_data:
                    for tag_id, value in exif_data.items():
                        tag_name = TAGS.get(tag_id, tag_id)
                        if "date" in tag_name.lower() or "time" in tag_name.lower():
                            try:
                                if isinstance(value, str):
                                    result.exif_dates[tag_name] = value
                            except:
                                pass
        except:
            pass

    def extract_exif_with_pyexiv2(self, image_path, result):
        try:
            with pyexiv2.Image(image_path) as img:
                exif_data = img.read_exif()
                date_tags = {
                    'Exif.Photo.DateTimeOriginal': 'DateTimeOriginal',
                    'Exif.Photo.DateTimeDigitized': 'DateTimeDigitized',
                    'Exif.Image.DateTime': 'DateTime',
                    'Exif.Image.ModifyDate': 'ModifyDate'
                }
                for exif_tag, friendly_name in date_tags.items():
                    if exif_tag in exif_data:
                        result.exif_dates[friendly_name] = exif_data[exif_tag]
        except:
            pass

    def determine_best_guess_date(self, result):
        priority_order = [
            "DateTimeOriginal",
            "DateTimeDigitized",
            "DateTime",
            "ModifyDate",
            "FileCreationTime",
            "FileModifiedTime"
        ]
        for date_type in priority_order:
            date_value = self.find_date_in_sources(date_type, result)
            if date_value:
                result.best_guess_date = f"{date_value} ({date_type})"
                return
        result.best_guess_date = "No reliable date found"

    def find_date_in_sources(self, date_type, result):
        if date_type in result.exif_dates:
            return result.exif_dates[date_type]
        if date_type in result.file_system_dates:
            return result.file_system_dates[date_type]
        return None

    def compile_all_results(self, result):
        result.date_time_results["=== COMPREHENSIVE ANALYSIS ==="] = ""
        result.date_time_results["--- EXIF METADATA DATES ---"] = ""
        if not result.exif_dates:
            result.date_time_results["No EXIF dates found"] = ""
        else:
            for key, value in result.exif_dates.items():
                result.date_time_results[f"{key}:"] = value
        result.date_time_results["--- FILE SYSTEM DATES ---"] = ""
        for key, value in result.file_system_dates.items():
            result.date_time_results[f"{key}:"] = value
        result.date_time_results["--- CAMERA INFORMATION ---"] = ""
        if not result.camera_info:
            result.date_time_results["No camera info found"] = ""
        else:
            for key, value in result.camera_info.items():
                result.date_time_results[f"{key}:"] = value
        result.date_time_results["--- GPS INFORMATION ---"] = ""
        if not result.gps_info:
            result.date_time_results["No GPS info found"] = ""
        else:
            for key, value in result.gps_info.items():
                result.date_time_results[f"{key}:"] = value
        result.date_time_results["--- BEST GUESS DATE ---"] = ""
        result.date_time_results["Most reliable date:"] = result.best_guess_date


class PicForensicsApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PicForensics")
        self.root.geometry("800x600")
        self.root.configure(bg="#e3f2fd")

        self.current_image = None
        self.image_label = None
        self.uploaded_images = []
        self.current_image_index = -1
        self.current_case_folder = None
        self.current_case_id = None
        self.current_case_name = None
        self.temp_images = {}
        self.timeline_analyzer = AdvancedImageTimelineAnalyzer()
        self.metadata_extractor = AdvancedMetadataExtractor(enable_cache=True, enable_geocoding=True)
        self.ai_detector = AIDetectionAnalyzer()
        self.case_config_file = "cases.json"
        self.cases = self.load_cases()
        self.image_source_paths = {}
        self.encryption_status = {}
        self.case_passwords = {}

        self.action_buttons_frame = None
        self.open_btn = None
        self.delete_btn = None
        self.encrypt_btn = None
        self.delete_case_btn = None
        self.case_hash_btn = None  # Added for case hash button

        self.create_widgets()
        self.hide_action_buttons()

    def load_cases(self):
        if os.path.exists(self.case_config_file):
            with open(self.case_config_file, 'r') as f:
                return json.load(f)
        return {}

    def save_cases(self):
        with open(self.case_config_file, 'w') as f:
            json.dump(self.cases, f)

    # ========== HASH METHODS ==========
    def _hash_registry_file(self) -> str | None:
        if not self.current_case_folder:
            return None
        return os.path.join(self.current_case_folder, "hash_registry.json")

    def auto_save_hash_for_current_image(self, show_popup: bool = False):
        try:
            if not getattr(self, "current_image", None) or not getattr(self, "current_case_folder", None):
                return

            registry_file = self._hash_registry_file()
            if not registry_file:
                return

            origin_path = self.image_source_paths.get(self.current_image, self.current_image)
            key = f"IMG::{origin_path}"

            file_to_hash = self.current_image
            if self.current_image.endswith(".enc"):
                if self.current_image not in self.temp_images or not os.path.exists(
                        self.temp_images[self.current_image]):
                    return
                file_to_hash = self.temp_images[self.current_image]

            if not os.path.exists(file_to_hash):
                return

            new_hash = compute_image_hash(file_to_hash)
            old_hash = get_previous_hash(registry_file, key)
            state = compare_hashes(old_hash, new_hash)

            if state == "FIRST":
                save_hash_to_registry(
                    registry_file,
                    key,
                    new_hash,
                    meta={
                        "type": "image",
                        "origin_path": origin_path,
                        "case_id": getattr(self, "current_case_id", None),
                        "case_name": getattr(self, "current_case_name", None),
                    },
                )
                if show_popup:
                    self.show_analysis_results(
                        "Hash Auto Check",
                        f"🟡 First time.\nBaseline hash saved.\n\nHASH:\n{new_hash}",
                    )
                return

            if state == "MATCH":
                if show_popup:
                    self.show_analysis_results(
                        "Hash Auto Check",
                        f"🟢 MATCH — No tampering detected.\n\nHASH:\n{new_hash}",
                    )
                return

            # MODIFIED
            if show_popup:
                self.show_analysis_results(
                    "Hash Auto Check",
                    "🔴 MODIFIED — Hash mismatch detected.\n\n"
                    f"OLD (baseline) → {old_hash}\n"
                    f"NEW (current)  → {new_hash}",
                )
        except Exception:
            return

    def hash_compare_integrity(self):
        if not getattr(self, "current_image", None):
            messagebox.showwarning("No Image Loaded", "⚠ Please open an image first.")
            return

        if not getattr(self, "current_case_folder", None):
            messagebox.showwarning("No Case", "⚠ Please open/create a case first.")
            return

        registry_file = self._hash_registry_file()
        if not registry_file:
            messagebox.showwarning("No Registry", "⚠ Hash registry file not available.")
            return

        origin_path = self.image_source_paths.get(self.current_image, self.current_image)
        key = f"IMG::{origin_path}"

        file_to_hash = self.current_image
        if self.current_image.endswith(".enc"):
            if self.current_image not in self.temp_images or not os.path.exists(self.temp_images[self.current_image]):
                messagebox.showwarning(
                    "Encrypted Image",
                    "⚠ This is an encrypted file.\nDecrypt for analysis first, then run Hash Check.",
                )
                return
            file_to_hash = self.temp_images[self.current_image]

        if not os.path.exists(file_to_hash):
            messagebox.showwarning("Missing File", "⚠ Image file not found on disk.")
            return

        new_hash = compute_image_hash(file_to_hash)
        old_hash = get_previous_hash(registry_file, key)
        state = compare_hashes(old_hash, new_hash)

        if state == "FIRST":
            save_hash_to_registry(
                registry_file,
                key,
                new_hash,
                meta={
                    "type": "image",
                    "origin_path": origin_path,
                    "case_id": getattr(self, "current_case_id", None),
                    "case_name": getattr(self, "current_case_name", None),
                },
            )
            self.show_analysis_results(
                "Hash Integrity Result",
                f"🟡 No previous hash found for this image.\n"
                f"A baseline hash has now been saved.\n\n"
                f"NEW HASH:\n{new_hash}",
            )
        elif state == "MATCH":
            self.show_analysis_results(
                "Hash Integrity Result",
                f"🟢 Image is ORIGINAL — No tampering detected.\n\nHASH MATCH:\n{new_hash}",
            )
        else:
            self.show_analysis_results(
                "Hash Integrity Result",
                f"🔴 HASH MISMATCH — File appears modified.\n\n"
                f"OLD → {old_hash}\n"
                f"NEW → {new_hash}",
            )

    def case_hash_integrity(self):
        if not self.current_case_folder or not self.uploaded_images:
            messagebox.showwarning("No Case", "⚠ Open a case and upload images first.")
            return

        registry_file = self._hash_registry_file()
        if not registry_file:
            messagebox.showwarning("No Registry", "⚠ Hash registry file not available.")
            return

        key = f"CASE::{getattr(self, 'current_case_id', self.current_case_folder)}"

        current_case_hash = compute_case_hash([p for p in self.uploaded_images if os.path.exists(p)])
        old_case_hash = get_previous_hash(registry_file, key)
        state = compare_hashes(old_case_hash, current_case_hash)

        if state == "FIRST":
            save_hash_to_registry(
                registry_file,
                key,
                current_case_hash,
                meta={
                    "type": "case",
                    "case_id": getattr(self, "current_case_id", None),
                    "case_name": getattr(self, "current_case_name", None),
                    "image_count": len(self.uploaded_images),
                },
            )
            msg = (
                "🟡 No previous CASE hash found.\n"
                "A baseline CASE hash has now been saved.\n\n"
                f"CASE HASH:\n{current_case_hash}"
            )
            self.show_analysis_results("Case Hash Result", msg)

        elif state == "MATCH":
            msg = f"🟢 CASE OK — No changes detected.\n\nCASE HASH:\n{current_case_hash}"
            self.show_analysis_results("Case Hash Result", msg)

        else:
            msg = (
                "🔴 CASE HASH MISMATCH — case contents changed.\n\n"
                f"OLD → {old_case_hash}\n"
                f"NEW → {current_case_hash}"
            )
            self.show_analysis_results("Case Hash Result", msg)

    # ========== END HASH METHODS ==========

    def create_widgets(self):
        nav_frame = tk.Frame(self.root, bg="#1976d2", height=40)
        nav_frame.pack(fill=tk.X, padx=10, pady=5)
        nav_frame.pack_propagate(False)

        nav_items = ["HOME", "About", "Help", "Exit"]
        for item in nav_items:
            btn = tk.Button(nav_frame, text=item, relief=tk.FLAT, bg="#1976d2",
                            fg="white", font=("Arial", 9),
                            command=lambda i=item: self.nav_action(i))
            btn.pack(side=tk.LEFT, padx=10)

        separator = ttk.Separator(self.root, orient=tk.HORIZONTAL)
        separator.pack(fill=tk.X, padx=10, pady=5)

        main_content = tk.Frame(self.root, bg="#e3f2fd")
        main_content.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        content_row = tk.Frame(main_content, bg="#e3f2fd")
        content_row.pack(fill=tk.BOTH, expand=True)

        left_frame = tk.Frame(content_row, bg="#e3f2fd")
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.image_frame = tk.Frame(left_frame, width=400, height=300, relief=tk.RAISED,
                                    bd=2, bg='white')
        self.image_frame.pack(pady=10)
        self.image_frame.pack_propagate(False)

        self.image_placeholder = tk.Label(self.image_frame,
                                          text="No Case Open\nClick 'Open/Create Case' to start",
                                          fg="gray", font=("Arial", 10), bg='white')
        self.image_placeholder.pack(expand=True)

        self.navigation_frame = tk.Frame(left_frame, bg="#e3f2fd")
        self.navigation_frame.pack(fill=tk.X, pady=5)

        self.prev_btn = tk.Button(self.navigation_frame, text="◀ Previous", command=self.previous_image,
                                  state="disabled", bg="#2196f3", fg="white", font=("Arial", 9))
        self.prev_btn.pack(side=tk.LEFT, padx=5)

        self.next_btn = tk.Button(self.navigation_frame, text="Next ▶", command=self.next_image,
                                  state="disabled", bg="#2196f3", fg="white", font=("Arial", 9))
        self.next_btn.pack(side=tk.LEFT, padx=5)

        self.verify_btn = tk.Button(self.navigation_frame, text="Verify Integrity", command=self.verify_integrity,
                                    state="disabled", bg="#ff9800", fg="white", font=("Arial", 9))
        self.verify_btn.pack(side=tk.LEFT, padx=5)

        # REMOVED: Hash button from navigation frame
        # self.hash_btn = tk.Button(self.navigation_frame, text="Hash Check", command=self.hash_compare_integrity,
        #                           state="disabled", bg="#9c27b0", fg="white", font=("Arial", 9))
        # self.hash_btn.pack(side=tk.LEFT, padx=5)

        self.image_counter = tk.Label(self.navigation_frame, text="No case open", bg="#e3f2fd", font=("Arial", 9))
        self.image_counter.pack(side=tk.LEFT, padx=10)

        self.info_frame = tk.LabelFrame(left_frame, text="Image Info", padx=10, pady=10,
                                        bg="#e3f2fd", fg="#1976d2", font=("Arial", 10, "bold"))
        self.info_frame.pack(fill=tk.X, pady=(10, 0))

        self.info_data = {
            "File Size": "No image loaded",
            "File Format": "No image loaded",
            "File Path": "No image loaded"
        }

        self.info_labels = {}
        row = 0
        for key, value in self.info_data.items():
            tk.Label(self.info_frame, text=f"{key}:", font=("Arial", 9, "bold"),
                     bg="#e3f2fd", fg="#1976d2").grid(row=row, column=0, sticky=tk.W, pady=1)
            value_label = tk.Label(self.info_frame, text=value, font=("Arial", 9),
                                   bg="#e3f2fd")
            value_label.grid(row=row, column=1, sticky=tk.W, pady=1)
            self.info_labels[key] = value_label
            row += 1

        tools_frame = tk.Frame(content_row, width=200, bg="#e3f2fd")
        tools_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(20, 0))
        tools_frame.pack_propagate(False)

        self.analysis_var = tk.StringVar(value="Analysis Results ▼")
        analysis_menu = tk.Menubutton(tools_frame, textvariable=self.analysis_var,
                                      relief=tk.RAISED, width=18, height=1,
                                      font=("Arial", 10), bg="#2196f3", fg="white")
        analysis_menu.pack(pady=5, fill=tk.X)

        analysis_dropdown = tk.Menu(analysis_menu, tearoff=0)
        analysis_dropdown.add_command(label="Meta Data", command=self.meta_data_analysis)
        analysis_dropdown.add_separator()
        analysis_dropdown.add_command(label="Time line", command=self.timeline_analysis)
        analysis_dropdown.add_separator()
        analysis_dropdown.add_command(label="AI detection", command=self.ai_detection_analysis)
        # Added hash to analysis dropdown
        analysis_dropdown.add_separator()
        analysis_dropdown.add_command(label="Hash Check", command=self.hash_compare_integrity)

        analysis_menu.configure(menu=analysis_dropdown)

        self.tools_var = tk.StringVar(value="Analysis Tools ▼")
        tools_menu = tk.Menubutton(tools_frame, textvariable=self.tools_var,
                                   relief=tk.RAISED, width=18, height=1,
                                   font=("Arial", 10), bg="#2196f3", fg="white")
        tools_menu.pack(pady=5, fill=tk.X)

        tools_dropdown = tk.Menu(tools_menu, tearoff=0)
        tools_dropdown.add_command(label="ELA", command=self.ela_analysis)
        tools_dropdown.add_separator()
        tools_dropdown.add_command(label="Noise", command=self.noise_analysis)
        tools_dropdown.add_separator()
        tools_dropdown.add_command(label="Histogram", command=self.histogram_analysis)

        tools_menu.configure(menu=tools_dropdown)

        spacer = tk.Frame(tools_frame, height=20, bg="#e3f2fd")
        spacer.pack(fill=tk.X)

        self.case_btn = tk.Button(main_content, text="Open/Create Case", command=self.manage_case,
                                  bg="#4CAF50", fg="white", font=("Arial", 10),
                                  relief=tk.RAISED, bd=2)
        self.case_btn.pack(pady=5)

        self.open_old_btn = tk.Button(main_content, text="Open Old Case", command=self.open_old_case,
                                      bg="#2196f3", fg="white", font=("Arial", 10),
                                      relief=tk.RAISED, bd=2)
        self.open_old_btn.pack(pady=5)

        self.action_buttons_frame = tk.Frame(main_content, bg="#e3f2fd")
        self.action_buttons_frame.pack(pady=10)

    def hide_action_buttons(self):
        for widget in self.action_buttons_frame.winfo_children():
            widget.destroy()
        self.case_hash_btn = None  # Reset case hash button reference

    def show_action_buttons(self):
        self.hide_action_buttons()

        self.open_btn = tk.Button(self.action_buttons_frame, text="Upload Folder", command=self.open_folder,
                                  bg="#2196f3", fg="white", font=("Arial", 10),
                                  relief=tk.RAISED, bd=2)
        self.open_btn.pack(side=tk.LEFT, padx=5)

        self.delete_btn = tk.Button(self.action_buttons_frame, text="Delete Image", command=self.delete_image,
                                    bg="#2196f3", fg="white", font=("Arial", 10),
                                    relief=tk.RAISED, bd=2)
        self.delete_btn.pack(side=tk.LEFT, padx=5)

        self.encrypt_btn = tk.Button(self.action_buttons_frame, text="Encrypt/Decrypt",
                                     command=self.encrypt_decrypt_menu,
                                     bg="#FF5722", fg="white", font=("Arial", 10),
                                     relief=tk.RAISED, bd=2)
        self.encrypt_btn.pack(side=tk.LEFT, padx=5)

        # Added case hash button - only appears when case is open
        self.case_hash_btn = tk.Button(self.action_buttons_frame, text="Case Hash", command=self.case_hash_integrity,
                                       bg="#673ab7", fg="white", font=("Arial", 10),
                                       relief=tk.RAISED, bd=2)
        self.case_hash_btn.pack(side=tk.LEFT, padx=5)

        self.delete_case_btn = tk.Button(self.action_buttons_frame, text="Delete Case", command=self.delete_case,
                                         bg="#f44336", fg="white", font=("Arial", 10),
                                         relief=tk.RAISED, bd=2)
        self.delete_case_btn.pack(side=tk.LEFT, padx=5)

    def nav_action(self, item):
        if item == "Exit":
            self.cleanup_temp_files()
            self.root.quit()
        elif item == "HOME":
            self.show_home_dashboard()
        elif item == "About":
            self.show_about_info()
        elif item == "Help":
            self.show_help_info()

    def cleanup_temp_files(self):
        for temp_path in self.temp_images.values():
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except:
                pass
        self.temp_images.clear()

    def show_home_dashboard(self):
        home_window = tk.Toplevel(self.root)
        home_window.title("PicForensics - Dashboard")
        home_window.geometry("600x400")
        home_window.configure(bg="#f5f5f5")

        header = tk.Label(home_window, text="📷 PicForensics",
                          font=("Arial", 16, "bold"), bg="#f5f5f5", fg="#1976d2")
        header.pack(pady=20)

        stats_frame = tk.Frame(home_window, bg="#f5f5f5")
        stats_frame.pack(pady=10)

        current_case = f"{self.current_case_name} ({self.current_case_id})" if self.current_case_name else "None"
        encrypted_count = sum(1 for img in self.uploaded_images if img.endswith('.enc'))
        decrypted_count = len(self.uploaded_images) - encrypted_count

        stats = [
            f"📁 Current Case: {current_case}",
            f"📷 Total Images: {len(self.uploaded_images)}",
            f"🔒 Encrypted Images: {encrypted_count}",
            f"🔓 Decrypted Images: {decrypted_count}",
            f"🛠️ Tools Available: 5 Analysis Methods",
            f"📊 Cases Saved: {len(self.cases)}"
        ]

        for stat in stats:
            lbl = tk.Label(stats_frame, text=stat, font=("Arial", 11),
                           bg="#f5f5f5", fg="#333")
            lbl.pack(pady=5)

        close_btn = tk.Button(home_window, text="Close Dashboard",
                              command=home_window.destroy,
                              bg="#2196f3", fg="white", font=("Arial", 10))
        close_btn.pack(pady=10)

    def show_about_info(self):
        about_text = """PicForensics

Version: 5.0 with Complete Encryption System
Advanced Image Forensics & Security Tool

Features:
• Case-based management with full encryption
• Images encrypted both in tool and source location
• Cannot view encrypted images without password
• Decryption restores images in both locations
• AES-128 Secure Image Encryption
• Advanced Metadata Extraction with exifread
• AI Detection using Noise Correlation Analysis
• Hash Detection using SHA-256"""  # Added hash feature to about text
        messagebox.showinfo("About PicForensics", about_text)

    def show_help_info(self):
        help_text = """PicForensics Help Guide

Complete Encryption System:
• Encrypt Current Image: Encrypts image in tool AND original location
• Decrypt for Analysis: Temporary decryption for analysis only
• Encrypt Entire Folder: Encrypts all images in source folder
• Decrypt All: Permanently decrypts all images in case

New Features:
• Advanced Metadata Extraction using exifread library
• AI Detection using Noise Correlation Analysis
• Forensic analysis with consistency scoring
• GPS geocoding and reverse geolocation
• Hash Detection using SHA-256 for tamper detection

Security Features:
• Images encrypted in both tool AND source location
• Cannot view encrypted images without password
• When opening old case: encrypted images remain encrypted
• Decryption restores images in both locations
• No images visible until decrypted
• Hash Detection for image integrity verification"""  # Added hash feature to help text
        messagebox.showinfo("Help Guide", help_text)

    def verify_integrity(self):
        if not self.current_image:
            messagebox.showwarning("No Image", "Please load an image first!")
            return

        try:
            if self.current_image.endswith('.enc'):
                if self.current_image not in self.temp_images:
                    messagebox.showwarning("Encrypted Image", "Please decrypt the image for analysis first!")
                    return
                image_to_check = self.temp_images[self.current_image]
            else:
                image_to_check = self.current_image

            integrity_report = "Integrity Verification Report\n\n"

            file_size = os.path.getsize(image_to_check) / (1024 * 1024)
            integrity_report += f"File Size: {file_size:.2f} MB\n"

            image = Image.open(image_to_check)
            integrity_report += f"Dimensions: {image.width} x {image.height}\n"
            integrity_report += f"Format: {image.format}\n\n"

            timeline_result = self.timeline_analyzer.analyze_image(image_to_check)
            integrity_report += f"Best Guess Date: {timeline_result.best_guess_date}\n"

            if self.current_image.endswith('.enc'):
                integrity_report += "\n⚠️ NOTE: This is a decrypted temporary copy\n"
                integrity_report += "Original file remains encrypted (.enc)\n"

            if file_size < 0.1 and image.width * image.height > 1000000:
                integrity_report += "\nWARNING: High resolution with small file size\n"

            messagebox.showinfo("Integrity Verification", integrity_report)

        except Exception as e:
            messagebox.showerror("Error", f"Integrity verification failed: {str(e)}")

    def update_navigation_buttons(self):
        if len(self.uploaded_images) <= 1:
            self.prev_btn.config(state="disabled")
            self.next_btn.config(state="disabled")
        else:
            self.prev_btn.config(state="normal")
            self.next_btn.config(state="normal")

        if self.uploaded_images:
            self.image_counter.config(text=f"Image {self.current_image_index + 1} of {len(self.uploaded_images)}")
            self.verify_btn.config(state="normal")
        else:
            self.image_counter.config(text="No images in case")
            self.verify_btn.config(state="disabled")

    def previous_image(self):
        if self.uploaded_images and self.current_image_index > 0:
            self.current_image_index -= 1
            self.load_current_image()

    def next_image(self):
        if self.uploaded_images and self.current_image_index < len(self.uploaded_images) - 1:
            self.current_image_index += 1
            self.load_current_image()

    def load_current_image(self):
        if 0 <= self.current_image_index < len(self.uploaded_images):
            image_path = self.uploaded_images[self.current_image_index]

            if image_path.endswith('.enc'):
                self.current_image = image_path
                self.update_image_info(image_path)
                self.image_placeholder.config(
                    text="🔒 ENCRYPTED IMAGE\n\nCannot be viewed without decryption\n\nClick 'Decrypt for Analysis' to view\nClick 'Decrypt All' to restore all images")
                self.image_placeholder.pack(expand=True)
                if self.image_label:
                    self.image_label.destroy()
                    self.image_label = None
            else:
                self.load_and_display_image(image_path)
                self.update_image_info(image_path)
            # Added auto hash check
            self.auto_save_hash_for_current_image()
            self.update_navigation_buttons()

    def load_and_display_image(self, file_path):
        self.image_placeholder.pack_forget()
        try:
            image = Image.open(file_path)
            frame_width = 380
            frame_height = 280
            image.thumbnail((frame_width, frame_height), Image.Resampling.LANCZOS)
            photo = ImageTk.PhotoImage(image)
            if self.image_label:
                self.image_label.destroy()
            self.image_label = tk.Label(self.image_frame, image=photo, bg='white')
            self.image_label.image = photo
            self.image_label.pack(expand=True)
            self.current_image = file_path
        except Exception as e:
            self.image_placeholder.config(text="Cannot display image\nFile may be corrupted")
            self.image_placeholder.pack(expand=True)
            self.current_image = file_path

    def update_image_info(self, file_path):
        try:
            file_size = os.path.getsize(file_path) / (1024 * 1024)
            file_name = os.path.basename(file_path)
            if file_path.endswith('.enc'):
                file_ext = "ENCRYPTED (.enc)"
                display_name = file_name
            else:
                file_ext = os.path.splitext(file_name)[1].upper().replace(".", "")
                display_name = file_name
            self.info_labels["File Size"].config(text=f"{file_size:.2f}MB")
            self.info_labels["File Format"].config(text=file_ext)
            self.info_labels["File Path"].config(text=display_name)
        except Exception as e:
            pass

    def open_folder(self):
        folder_path = filedialog.askdirectory(title="Select Folder with Images")
        if folder_path:
            image_extensions = ('.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff', '.tif')
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    if file.lower().endswith(image_extensions):
                        src_path = os.path.join(root, file)
                        self.image_source_paths[src_path] = src_path
                        dest_path = os.path.join(self.current_case_folder, file)
                        shutil.copy2(src_path, dest_path)
                        self.uploaded_images.append(dest_path)
                        self.encryption_status[dest_path] = False

            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    if file.lower().endswith('.enc'):
                        src_path = os.path.join(root, file)
                        self.image_source_paths[src_path] = src_path
                        dest_path = os.path.join(self.current_case_folder, file)
                        shutil.copy2(src_path, dest_path)
                        self.uploaded_images.append(dest_path)
                        self.encryption_status[dest_path] = True

            if self.uploaded_images:
                self.current_image_index = 0
                self.load_current_image()
            else:
                messagebox.showinfo("No Images", "No images found in the selected folder")

            self.save_case_state()

    def delete_image(self):
        if not self.current_image:
            messagebox.showwarning("Delete Image", "No image to delete!")
            return

        image_path = self.uploaded_images[self.current_image_index]
        is_encrypted = image_path.endswith('.enc')

        warning_msg = "Are you sure you want to delete this image from the case?"
        if is_encrypted:
            warning_msg += "\n\n⚠️ This is an encrypted image (.enc)\nIt cannot be recovered once deleted!"

        result = messagebox.askyesno("Delete Image", warning_msg)

        if result:
            if 0 <= self.current_image_index < len(self.uploaded_images):
                try:
                    os.remove(self.uploaded_images[self.current_image_index])
                except:
                    pass
                self.uploaded_images.pop(self.current_image_index)
                if self.uploaded_images:
                    if self.current_image_index >= len(self.uploaded_images):
                        self.current_image_index = len(self.uploaded_images) - 1
                    self.load_current_image()
                else:
                    if self.image_label:
                        self.image_label.destroy()
                        self.image_label = None
                    self.image_placeholder.config(text="No images in case\nUpload folder to add images")
                    self.image_placeholder.pack(expand=True)
                    for key in self.info_labels:
                        self.info_labels[key].config(text="No image loaded")
                    self.current_image = None
                    self.current_image_index = -1
                    self.update_navigation_buttons()
                self.save_case_state()
                messagebox.showinfo("Delete Image", "Image deleted successfully!")

    def manage_case(self):
        case_window = tk.Toplevel(self.root)
        case_window.title("Create/Open Case")
        case_window.geometry("400x300")
        case_window.configure(bg="#f5f5f5")

        tk.Label(case_window, text="Case Management", font=("Arial", 14, "bold"),
                 bg="#f5f5f5", fg="#1976d2").pack(pady=20)

        tk.Label(case_window, text="Case ID:", bg="#f5f5f5").pack(pady=5)
        case_id_entry = tk.Entry(case_window, width=30)
        case_id_entry.pack(pady=5)

        tk.Label(case_window, text="Case Name:", bg="#f5f5f5").pack(pady=5)
        case_name_entry = tk.Entry(case_window, width=30)
        case_name_entry.pack(pady=5)

        def create_open_case():
            case_id = case_id_entry.get().strip()
            case_name = case_name_entry.get().strip()

            if not case_id or not case_name:
                messagebox.showwarning("Input Error", "Please enter both Case ID and Case Name")
                return

            case_folder = f"Case_{case_id}_{case_name}"
            if not os.path.exists(case_folder):
                os.makedirs(case_folder)

            self.current_case_folder = case_folder
            self.current_case_id = case_id
            self.current_case_name = case_name

            self.cases[case_id] = {
                "name": case_name,
                "folder": case_folder,
                "images": []
            }
            self.save_cases()

            self.uploaded_images = []
            self.image_source_paths = {}
            self.encryption_status = {}

            for file in os.listdir(case_folder):
                if file.lower().endswith(('.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff', '.tif', '.enc')):
                    file_path = os.path.join(case_folder, file)
                    self.uploaded_images.append(file_path)
                    if file.endswith('.enc'):
                        self.encryption_status[file_path] = True

            self.current_image_index = 0 if self.uploaded_images else -1
            self.cleanup_temp_files()

            if self.uploaded_images:
                self.load_current_image()
            else:
                self.image_placeholder.config(text="Case Created\nUpload folder to add images")

            self.show_action_buttons()
            self.update_navigation_buttons()

            case_window.destroy()
            messagebox.showinfo("Success", f"Case '{case_name}' created successfully!")

        tk.Button(case_window, text="Create/Open Case", command=create_open_case,
                  bg="#4CAF50", fg="white", font=("Arial", 10)).pack(pady=20)

        tk.Button(case_window, text="Cancel", command=case_window.destroy,
                  bg="#f44336", fg="white", font=("Arial", 10)).pack(pady=5)

    def open_old_case(self):
        if not self.cases:
            messagebox.showinfo("No Cases", "No previous cases found.")
            return

        case_window = tk.Toplevel(self.root)
        case_window.title("Open Old Case")
        case_window.geometry("500x400")
        case_window.configure(bg="#f5f5f5")

        tk.Label(case_window, text="Select Case to Open", font=("Arial", 14, "bold"),
                 bg="#f5f5f5", fg="#1976d2").pack(pady=20)

        list_frame = tk.Frame(case_window, bg="#f5f5f5")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        case_list = tk.Listbox(list_frame, yscrollcommand=scrollbar.set,
                               font=("Arial", 11), height=10)
        case_list.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=case_list.yview)

        for case_id, case_info in self.cases.items():
            case_list.insert(tk.END, f"{case_id}: {case_info['name']}")

        def open_selected_case():
            selection = case_list.curselection()
            if not selection:
                messagebox.showwarning("No Selection", "Please select a case")
                return

            selected_item = case_list.get(selection[0])
            case_id = selected_item.split(":")[0].strip()

            if case_id in self.cases:
                case_info = self.cases[case_id]
                self.current_case_folder = case_info["folder"]
                self.current_case_id = case_id
                self.current_case_name = case_info["name"]

                self.uploaded_images = []
                self.image_source_paths = {}
                self.encryption_status = {}

                for file in os.listdir(self.current_case_folder):
                    if file.lower().endswith(('.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff', '.tif', '.enc')):
                        file_path = os.path.join(self.current_case_folder, file)
                        self.uploaded_images.append(file_path)
                        if file.endswith('.enc'):
                            self.encryption_status[file_path] = True

                self.current_image_index = 0 if self.uploaded_images else -1
                self.cleanup_temp_files()

                if self.uploaded_images:
                    self.load_current_image()
                else:
                    self.image_placeholder.config(text="Case Loaded\nNo images in case")
                    if self.image_label:
                        self.image_label.destroy()
                        self.image_label = None

                self.show_action_buttons()
                self.update_navigation_buttons()

                case_window.destroy()
                messagebox.showinfo("Success",
                                    f"Case '{case_info['name']}' loaded successfully!\n\nEncrypted images remain encrypted until decrypted.")

        btn_frame = tk.Frame(case_window, bg="#f5f5f5")
        btn_frame.pack(fill=tk.X, padx=20, pady=10)

        tk.Button(btn_frame, text="Open Selected Case", command=open_selected_case,
                  bg="#2196f3", fg="white", font=("Arial", 10)).pack(side=tk.LEFT, padx=5)

        tk.Button(btn_frame, text="Cancel", command=case_window.destroy,
                  bg="#f44336", fg="white", font=("Arial", 10)).pack(side=tk.RIGHT, padx=5)

    def encrypt_decrypt_menu(self):
        menu_window = tk.Toplevel(self.root)
        menu_window.title("Encryption/Decryption")
        menu_window.geometry("300x300")
        menu_window.configure(bg="#f5f5f5")

        tk.Label(menu_window, text="Select Operation", font=("Arial", 12, "bold"),
                 bg="#f5f5f5", fg="#1976d2").pack(pady=20)

        tk.Button(menu_window, text="Encrypt Current Image",
                  command=lambda: [self.encrypt_current_image(), menu_window.destroy()],
                  bg="#FF5722", fg="white", font=("Arial", 10), width=20).pack(pady=5)

        tk.Button(menu_window, text="Decrypt for Analysis",
                  command=lambda: [self.decrypt_for_analysis(), menu_window.destroy()],
                  bg="#2196f3", fg="white", font=("Arial", 10), width=20).pack(pady=5)

        tk.Button(menu_window, text="Encrypt Entire Folder",
                  command=lambda: [self.encrypt_entire_folder(), menu_window.destroy()],
                  bg="#9C27B0", fg="white", font=("Arial", 10), width=20).pack(pady=5)

        tk.Button(menu_window, text="Permanently Decrypt",
                  command=lambda: [self.permanently_decrypt(), menu_window.destroy()],
                  bg="#4CAF50", fg="white", font=("Arial", 10), width=20).pack(pady=5)

        tk.Button(menu_window, text="Decrypt All",
                  command=lambda: [self.decrypt_all_images(), menu_window.destroy()],
                  bg="#FF9800", fg="white", font=("Arial", 10), width=20).pack(pady=5)

        tk.Button(menu_window, text="Cancel", command=menu_window.destroy,
                  bg="#95a5a6", fg="white", font=("Arial", 10), width=20).pack(pady=10)

    def encrypt_current_image(self):
        if not self.current_image:
            messagebox.showwarning("No Image", "Please select an image first!")
            return

        if self.current_image.endswith('.enc'):
            messagebox.showwarning("Already Encrypted", "This image is already encrypted!")
            return

        original_source_path = None
        for src_path, dest_path in self.image_source_paths.items():
            if dest_path == self.current_image or os.path.basename(dest_path) == os.path.basename(self.current_image):
                original_source_path = src_path
                break

        password = simpledialog.askstring("Encryption Password",
                                          "Enter password for encryption (min 8 characters):",
                                          show='•')
        if password and len(password) >= 8:
            confirm_password = simpledialog.askstring("Confirm Password",
                                                      "Confirm password:",
                                                      show='•')
            if confirm_password == password:
                try:
                    if original_source_path:
                        with open(original_source_path, "rb") as f:
                            image_data = f.read()

                        encrypted_data = encrypt_image_data(image_data, password)
                        if encrypted_data:
                            enc_source_path = original_source_path + ".enc"
                            with open(enc_source_path, "wb") as f:
                                f.write(encrypted_data)
                                f.flush()
                                os.fsync(f.fileno())

                            os.remove(original_source_path)
                            self.image_source_paths[enc_source_path] = enc_source_path
                            if original_source_path in self.image_source_paths:
                                del self.image_source_paths[original_source_path]

                    with open(self.current_image, "rb") as f:
                        image_data = f.read()

                    encrypted_data = encrypt_image_data(image_data, password)
                    if encrypted_data:
                        enc_path = self.current_image + ".enc"
                        with open(enc_path, "wb") as f:
                            f.write(encrypted_data)
                            f.flush()
                            os.fsync(f.fileno())

                        os.remove(self.current_image)

                        original_index = self.current_image_index
                        self.uploaded_images[original_index] = enc_path
                        self.encryption_status[enc_path] = True
                        self.current_image = enc_path
                        self.load_current_image()
                        self.save_case_state()

                        self.case_passwords[self.current_case_id] = password

                        messagebox.showinfo("Success",
                                            "Image encrypted in BOTH locations!\n\n• In tool: Cannot be viewed\n• In source folder: Cannot be opened\n• Requires password to decrypt")
                    else:
                        messagebox.showerror("Error", "Encryption failed")
                except Exception as e:
                    messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            else:
                messagebox.showerror("Error", "Passwords do not match!")
        elif password:
            messagebox.showwarning("Weak Password", "Password must be at least 8 characters")

    def decrypt_for_analysis(self):
        if not self.current_image:
            messagebox.showwarning("No Image", "Please select an image first!")
            return

        if not self.current_image.endswith('.enc'):
            messagebox.showwarning("Not Encrypted", "This image is not encrypted!")
            return

        password = simpledialog.askstring("Decryption Password",
                                          "Enter password to decrypt image for analysis:",
                                          show='•')
        if password:
            try:
                with open(self.current_image, "rb") as f:
                    encrypted_data = f.read()

                decrypted_data = decrypt_image_data(encrypted_data, password)
                if decrypted_data:
                    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.jpg')
                    temp_file.write(decrypted_data)
                    temp_file.flush()
                    os.fsync(temp_file.fileno())
                    temp_file.close()

                    self.temp_images[self.current_image] = temp_file.name
                    self.load_and_display_image(temp_file.name)
                    self.update_image_info(self.current_image)

                    messagebox.showinfo("Success",
                                        "Image decrypted for analysis!\n\n⚠️ Temporary decryption only\nOriginal remains encrypted in both locations")
                else:
                    messagebox.showerror("Error", "Wrong password or corrupted file")
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {str(e)}")

    def encrypt_entire_folder(self):
        if not self.image_source_paths:
            messagebox.showwarning("No Source Folder", "Please upload a folder first!")
            return

        response = messagebox.askyesno("Encrypt Entire Folder",
                                       "⚠️ COMPLETE ENCRYPTION WARNING\n\n"
                                       "This will encrypt ALL images in BOTH locations:\n"
                                       "1. Inside PicForensics tool\n"
                                       "2. In original source folder\n\n"
                                       "Encrypted images cannot be viewed in tool\n"
                                       "Cannot be opened in source folder\n\n"
                                       "Continue?")
        if response:
            password = simpledialog.askstring("Encryption Password",
                                              "Enter password for folder encryption (min 8 characters):",
                                              show='•')
            if password and len(password) >= 8:
                confirm_password = simpledialog.askstring("Confirm Password",
                                                          "Confirm password:",
                                                          show='•')
                if confirm_password == password:
                    encrypted_count = 0
                    failed_count = 0

                    for src_path in list(self.image_source_paths.keys()):
                        if not src_path.endswith('.enc'):
                            try:
                                with open(src_path, "rb") as f:
                                    image_data = f.read()

                                encrypted_data = encrypt_image_data(image_data, password)
                                if encrypted_data:
                                    enc_source_path = src_path + ".enc"
                                    with open(enc_source_path, "wb") as f:
                                        f.write(encrypted_data)
                                        f.flush()
                                        os.fsync(f.fileno())

                                    os.remove(src_path)
                                    self.image_source_paths[enc_source_path] = enc_source_path
                                    del self.image_source_paths[src_path]
                                    encrypted_count += 1
                                else:
                                    failed_count += 1
                            except:
                                failed_count += 1

                    for i, file_path in enumerate(self.uploaded_images[:]):
                        if not file_path.endswith('.enc'):
                            try:
                                with open(file_path, "rb") as f:
                                    image_data = f.read()

                                encrypted_data = encrypt_image_data(image_data, password)
                                if encrypted_data:
                                    enc_path = file_path + ".enc"
                                    with open(enc_path, "wb") as f:
                                        f.write(encrypted_data)
                                        f.flush()
                                        os.fsync(f.fileno())

                                    os.remove(file_path)
                                    self.uploaded_images[i] = enc_path
                                    self.encryption_status[enc_path] = True
                                    encrypted_count += 1
                                else:
                                    failed_count += 1
                            except:
                                failed_count += 1

                    if encrypted_count > 0:
                        self.current_image_index = 0 if self.uploaded_images else -1
                        if self.uploaded_images:
                            self.load_current_image()
                        self.save_case_state()

                        self.case_passwords[self.current_case_id] = password

                        result_msg = f"{encrypted_count} images encrypted in BOTH locations!\n\n"
                        result_msg += "🔒 INSIDE TOOL:\n• Images cannot be viewed\n• Show as encrypted (.enc)\n• Require password\n\n"
                        result_msg += "🔒 IN SOURCE FOLDER:\n• Files cannot be opened\n• Show as .enc files\n• Require password"

                        if failed_count > 0:
                            result_msg += f"\n\n{failed_count} images failed to encrypt"

                        messagebox.showinfo("Complete Encryption", result_msg)
                    else:
                        messagebox.showinfo("No Images", "No images were encrypted")
                else:
                    messagebox.showerror("Error", "Passwords do not match!")
            elif password:
                messagebox.showwarning("Weak Password", "Password must be at least 8 characters")

    def permanently_decrypt(self):
        if not self.current_image:
            messagebox.showwarning("No Image", "Please select an image first!")
            return

        if not self.current_image.endswith('.enc'):
            messagebox.showwarning("Not Encrypted", "This image is not encrypted!")
            return

        original_source_path = None
        for src_path in self.image_source_paths:
            if src_path.endswith('.enc') and os.path.basename(src_path) == os.path.basename(self.current_image):
                original_source_path = src_path[:-4]
                break

        password = simpledialog.askstring("Permanent Decryption",
                                          "Enter password to permanently decrypt image:",
                                          show='•')
        if password:
            try:
                source_decrypted = False
                if original_source_path:
                    enc_source_path = original_source_path + ".enc"
                    if os.path.exists(enc_source_path):
                        with open(enc_source_path, "rb") as f:
                            encrypted_data = f.read()
                        decrypted_data = decrypt_image_data(encrypted_data, password)
                        if decrypted_data:
                            with open(original_source_path, "wb") as f:
                                f.write(decrypted_data)
                                f.flush()
                                os.fsync(f.fileno())
                            os.remove(enc_source_path)
                            self.image_source_paths[original_source_path] = original_source_path
                            if enc_source_path in self.image_source_paths:
                                del self.image_source_paths[enc_source_path]
                            source_decrypted = True

                with open(self.current_image, "rb") as f:
                    encrypted_data = f.read()

                decrypted_data = decrypt_image_data(encrypted_data, password)
                if decrypted_data:
                    dec_path = self.current_image[:-4]
                    with open(dec_path, "wb") as f:
                        f.write(decrypted_data)
                        f.flush()
                        os.fsync(f.fileno())

                    os.remove(self.current_image)

                    original_index = self.current_image_index
                    self.uploaded_images[original_index] = dec_path
                    self.encryption_status[dec_path] = False
                    self.current_image = dec_path

                    self.load_current_image()
                    self.save_case_state()

                    if source_decrypted:
                        messagebox.showinfo("Success",
                                            "Image permanently decrypted in BOTH locations!\n\n• In tool: Now visible and viewable\n• In source folder: Restored to original\n• No longer encrypted")
                    else:
                        messagebox.showinfo("Success",
                                            "Image permanently decrypted in tool!\n\n• In tool: Now visible and viewable\n• Source location not found or already decrypted")
                else:
                    messagebox.showerror("Error", "Wrong password or corrupted file")
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {str(e)}")

    def decrypt_all_images(self):
        if not self.uploaded_images:
            messagebox.showwarning("No Images", "No images in case to decrypt!")
            return

        encrypted_count = sum(1 for img in self.uploaded_images if img.endswith('.enc'))
        if encrypted_count == 0:
            messagebox.showinfo("Already Decrypted", "All images are already decrypted!")
            return

        response = messagebox.askyesno("Decrypt All Images",
                                       f"⚠️ COMPLETE DECRYPTION\n\n"
                                       f"This will permanently decrypt ALL {encrypted_count} encrypted images:\n\n"
                                       f"1. Inside PicForensics tool\n"
                                       f"2. In original source folders\n\n"
                                       f"Images will become visible and accessible in both locations.\n\n"
                                       f"Continue?")
        if not response:
            return

        password = simpledialog.askstring("Decryption Password",
                                          f"Enter password to decrypt all {encrypted_count} images:",
                                          show='•')
        if password:
            success_count = 0
            failed_count = 0

            for i, file_path in enumerate(self.uploaded_images[:]):
                if file_path.endswith('.enc'):
                    try:
                        with open(file_path, "rb") as f:
                            encrypted_data = f.read()

                        decrypted_data = decrypt_image_data(encrypted_data, password)
                        if decrypted_data:
                            dec_path = file_path[:-4]
                            with open(dec_path, "wb") as f:
                                f.write(decrypted_data)
                                f.flush()
                                os.fsync(f.fileno())

                            os.remove(file_path)
                            self.uploaded_images[i] = dec_path
                            self.encryption_status[dec_path] = False
                            success_count += 1
                        else:
                            failed_count += 1
                    except:
                        failed_count += 1

            for src_path in list(self.image_source_paths.keys()):
                if src_path.endswith('.enc'):
                    try:
                        with open(src_path, "rb") as f:
                            encrypted_data = f.read()

                        decrypted_data = decrypt_image_data(encrypted_data, password)
                        if decrypted_data:
                            original_source_path = src_path[:-4]
                            with open(original_source_path, "wb") as f:
                                f.write(decrypted_data)
                                f.flush()
                                os.fsync(f.fileno())

                            os.remove(src_path)
                            self.image_source_paths[original_source_path] = original_source_path
                            del self.image_source_paths[src_path]
                    except:
                        pass

            if success_count > 0:
                self.current_image_index = 0 if self.uploaded_images else -1
                if self.uploaded_images:
                    self.load_current_image()
                self.save_case_state()

                result_msg = f"{success_count} images decrypted in BOTH locations!\n\n"
                result_msg += "✅ INSIDE TOOL:\n• Images now visible\n• Can be viewed and analyzed\n\n"
                result_msg += "✅ IN SOURCE FOLDER:\n• Files restored to original\n• Can be opened normally"

                if failed_count > 0:
                    result_msg += f"\n\n{failed_count} images failed to decrypt"

                messagebox.showinfo("Complete Decryption", result_msg)
            else:
                messagebox.showerror("Error", "Failed to decrypt any images\nWrong password or corrupted files")

    def delete_case(self):
        if not self.current_case_folder:
            messagebox.showwarning("No Case", "No case is currently open!")
            return

        response = messagebox.askyesno("Delete Case",
                                       f"⚠️ PERMANENT CASE DELETION\n\n"
                                       f"This will COMPLETELY delete case:\n"
                                       f"• Case ID: {self.current_case_id}\n"
                                       f"• Case Name: {self.current_case_name}\n"
                                       f"• All images in case folder\n"
                                       f"• Case folder: {self.current_case_folder}\n\n"
                                       f"This action cannot be undone!\n\n"
                                       f"Continue?")
        if not response:
            return

        try:
            if self.current_case_id in self.cases:
                del self.cases[self.current_case_id]
                self.save_cases()

            shutil.rmtree(self.current_case_folder)

            self.current_case_folder = None
            self.current_case_id = None
            self.current_case_name = None
            self.uploaded_images = []
            self.current_image_index = -1
            self.image_source_paths = {}
            self.encryption_status = {}
            self.cleanup_temp_files()

            if self.image_label:
                self.image_label.destroy()
                self.image_label = None

            self.image_placeholder.config(text="No Case Open\nClick 'Open/Create Case' to start")
            self.image_placeholder.pack(expand=True)

            for key in self.info_labels:
                self.info_labels[key].config(text="No image loaded")

            self.hide_action_buttons()
            self.update_navigation_buttons()

            messagebox.showinfo("Case Deleted", "Case deleted successfully!")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete case: {str(e)}")

    def save_case_state(self):
        if self.current_case_id:
            self.cases[self.current_case_id]["images"] = [os.path.basename(img) for img in self.uploaded_images]
            self.save_cases()

    def meta_data_analysis(self):
        self.analysis_var.set(f"Analysis Results ▼")
        if not self.current_image:
            messagebox.showwarning("No Image", "Please load an image first!")
            return

        try:
            if self.current_image.endswith('.enc'):
                if self.current_image not in self.temp_images:
                    messagebox.showwarning("Encrypted Image", "Please decrypt the image for analysis first!")
                    return
                image_to_analyze = self.temp_images[self.current_image]
            else:
                image_to_analyze = self.current_image

            result = self.metadata_extractor.extract_comprehensive_metadata(image_to_analyze)

            if "error" in result:
                messagebox.showerror("Error", result["error"])
                return

            meta_info = "Comprehensive Metadata Analysis\n\n"
            meta_info += "=" * 50 + "\n\n"

            if "file_information" in result:
                meta_info += "📄 FILE INFORMATION\n"
                meta_info += "-" * 30 + "\n"
                for key, value in result["file_information"].items():
                    meta_info += f"{key.replace('_', ' ').title()}: {value}\n"
                meta_info += "\n"

            if "camera_information" in result:
                meta_info += "📷 CAMERA INFORMATION\n"
                meta_info += "-" * 30 + "\n"
                for key, value in result["camera_information"].items():
                    meta_info += f"{key.replace('_', ' ').title()}: {value}\n"
                meta_info += "\n"

            if "shooting_parameters" in result:
                meta_info += "⚙️ SHOOTING PARAMETERS\n"
                meta_info += "-" * 30 + "\n"
                for key, value in result["shooting_parameters"].items():
                    meta_info += f"{key.replace('_', ' ').title()}: {value}\n"
                meta_info += "\n"

            if "gps_data" in result:
                meta_info += "📍 GPS DATA\n"
                meta_info += "-" * 30 + "\n"
                for key, value in result["gps_data"].items():
                    meta_info += f"{key.replace('_', ' ').title()}: {value}\n"
                meta_info += "\n"

            if "forensic_analysis" in result:
                meta_info += "🔍 FORENSIC ANALYSIS\n"
                meta_info += "-" * 30 + "\n"
                fa = result["forensic_analysis"]
                meta_info += f"Consistency Score: {fa.get('consistency_score', 0)}/1.0\n"
                if fa.get('editing_software_detected'):
                    meta_info += f"Editing Software Detected: {', '.join(fa['editing_software_detected'])}\n"

            if self.current_image.endswith('.enc'):
                meta_info += "\n⚠️ NOTE: Analysis performed on temporary decrypted copy\n"
                meta_info += "Original file remains encrypted (.enc) in both locations\n"

            self.show_analysis_results("Meta Data Analysis", meta_info)
        except Exception as e:
            messagebox.showerror("Error", f"Meta data analysis failed: {str(e)}")

    def timeline_analysis(self):
        self.analysis_var.set(f"Analysis Results ▼")
        if not self.current_image:
            messagebox.showwarning("No Image", "Please load an image first!")
            return

        try:
            if self.current_image.endswith('.enc'):
                if self.current_image not in self.temp_images:
                    messagebox.showwarning("Encrypted Image", "Please decrypt the image for analysis first!")
                    return
                image_to_analyze = self.temp_images[self.current_image]
            else:
                image_to_analyze = self.current_image

            result = self.timeline_analyzer.analyze_image(image_to_analyze)
            timeline_info = "Timeline Analysis\n\n"
            for key, value in result.date_time_results.items():
                if "DATE" in key.upper() or "TIME" in key.upper():
                    timeline_info += f"{key}: {value}\n"

            if self.current_image.endswith('.enc'):
                timeline_info += "\n⚠️ NOTE: Analysis performed on temporary decrypted copy\n"
                timeline_info += "Original file remains encrypted (.enc) in both locations\n"

            self.show_analysis_results("Timeline Analysis", timeline_info)
        except Exception as e:
            messagebox.showerror("Error", f"Timeline analysis failed: {str(e)}")

    def ai_detection_analysis(self):
        self.analysis_var.set(f"Analysis Results ▼")
        if not self.current_image:
            messagebox.showwarning("No Image", "Please load an image first!")
            return

        try:
            if self.current_image.endswith('.enc'):
                if self.current_image not in self.temp_images:
                    messagebox.showwarning("Encrypted Image", "Please decrypt the image for analysis first!")
                    return
                image_to_analyze = self.temp_images[self.current_image]
            else:
                image_to_analyze = self.current_image

            correlation_results = self.ai_detector.analyze_noise_correlation(image_to_analyze)

            if correlation_results is None:
                messagebox.showerror("Error", "Failed to analyze image for AI detection")
                return

            # Display results in the tool's interface
            self.ai_detector.visualize_results(correlation_results, self.root)

        except Exception as e:
            messagebox.showerror("Error", f"AI detection analysis failed: {str(e)}")

    def ela_analysis(self):
        self.tools_var.set(f"Analysis Tools ▼")
        if not self.current_image:
            messagebox.showwarning("No Image", "Please load an image first!")
            return

        try:
            if self.current_image.endswith('.enc'):
                if self.current_image not in self.temp_images:
                    messagebox.showwarning("Encrypted Image", "Please decrypt the image for analysis first!")
                    return
                image_to_analyze = self.temp_images[self.current_image]
            else:
                image_to_analyze = self.current_image

            ela_image = compute_ela(image_to_analyze)
            if ela_image:
                self.display_analysis_image(ela_image, "ELA Analysis")
            else:
                messagebox.showerror("Error", "ELA analysis failed to generate image")
        except Exception as e:
            messagebox.showerror("Error", f"ELA analysis failed: {str(e)}")

    def noise_analysis(self):
        self.tools_var.set(f"Analysis Tools ▼")
        if not self.current_image:
            messagebox.showwarning("No Image", "Please load an image first!")
            return

        try:
            if self.current_image.endswith('.enc'):
                if self.current_image not in self.temp_images:
                    messagebox.showwarning("Encrypted Image", "Please decrypt the image for analysis first!")
                    return
                image_to_analyze = self.temp_images[self.current_image]
            else:
                image_to_analyze = self.current_image

            img = Image.open(image_to_analyze).convert("RGB")
            noise_array = extract_noise_stat(img)
            noise_normalized = (noise_array - noise_array.min()) / (noise_array.max() - noise_array.min() + 1e-8)
            noise_uint8 = (noise_normalized * 255).astype(np.uint8)
            noise_image = Image.fromarray(noise_uint8)
            self.display_analysis_image(noise_image, "Noise Analysis")
        except Exception as e:
            messagebox.showerror("Error", f"Noise analysis failed: {str(e)}")

    def histogram_analysis(self):
        self.tools_var.set(f"Analysis Tools ▼")
        if not self.current_image:
            messagebox.showwarning("No Image", "Please load an image first!")
            return

        try:
            if self.current_image.endswith('.enc'):
                if self.current_image not in self.temp_images:
                    messagebox.showwarning("Encrypted Image", "Please decrypt the image for analysis first!")
                    return
                image_to_analyze = self.temp_images[self.current_image]
            else:
                image_to_analyze = self.current_image

            import matplotlib.pyplot as plt
            image = Image.open(image_to_analyze).convert("RGB")
            plt.figure(figsize=(6, 4))
            colors = ('red', 'green', 'blue')
            for i, color in enumerate(colors):
                histogram = image.getchannel(i).histogram()
                plt.plot(histogram, color=color, alpha=0.7)
            plt.title('RGB Histogram')
            plt.xlabel('Pixel Value')
            plt.ylabel('Frequency')
            plt.legend(['Red', 'Green', 'Blue'])
            plt.tight_layout()
            buf = io.BytesIO()
            plt.savefig(buf, format='png', dpi=100)
            buf.seek(0)
            hist_image = Image.open(buf)
            self.display_analysis_image(hist_image, "Histogram Analysis")
            plt.close()
        except Exception as e:
            messagebox.showerror("Error", f"Histogram analysis failed: {str(e)}")

    def show_analysis_results(self, title, results):
        results_window = tk.Toplevel(self.root)
        results_window.title(title)
        results_window.geometry("700x800")
        results_window.configure(bg="white")

        frame = tk.Frame(results_window, bg="white")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        scrollbar = tk.Scrollbar(frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        text_widget = tk.Text(frame, wrap=tk.WORD, font=("Courier New", 9),
                              yscrollcommand=scrollbar.set, bg="white", fg="black")
        text_widget.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=text_widget.yview)

        text_widget.insert(tk.END, results)
        text_widget.config(state=tk.DISABLED)

        close_btn = tk.Button(results_window, text="Close", command=results_window.destroy,
                              bg="#2196f3", fg="white", font=("Arial", 10))
        close_btn.pack(pady=10)

    def display_analysis_image(self, pil_image, title):
        analysis_window = tk.Toplevel(self.root)
        analysis_window.title(title)
        analysis_window.geometry("600x500")
        analysis_window.configure(bg="white")

        image_frame = tk.Frame(analysis_window, bg="white")
        image_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        display_image = pil_image.copy()
        display_image.thumbnail((550, 400), Image.Resampling.LANCZOS)
        photo = ImageTk.PhotoImage(display_image)

        image_label = tk.Label(image_frame, image=photo, bg='white')
        image_label.image = photo
        image_label.pack(expand=True)

        close_btn = tk.Button(analysis_window, text="Close", command=analysis_window.destroy,
                              bg="#2196f3", fg="white", font=("Arial", 10))
        close_btn.pack(pady=10)


def main():
    root = tk.Tk()
    app = PicForensicsApp(root)
    root.protocol("WM_DELETE_WINDOW", lambda: [app.cleanup_temp_files(), root.quit()])
    root.mainloop()


if __name__ == "__main__":
    main()
