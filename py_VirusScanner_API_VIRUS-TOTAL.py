import hashlib
import os
import tkinter as tk
import threading
import requests
import base64
import zipfile
import base64
import time

from queue import Queue, Empty
from tkinter import filedialog, ttk, messagebox, PhotoImage


# VirusTotal API Key
VIRUSTOTAL_API_KEY = ("INPUT_API_VIRUS-TOTAL")
RATE_LIMIT_DELAY = 16  # Default delay untuk VirusTotal = 15 detik

class MalwareDetectorGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Virus Scanner Kelompok 8")
        self.master.geometry("550x450")

        self.api_key = VIRUSTOTAL_API_KEY
        if not self.api_key:
            messagebox.showerror("Error", "VirusTotal API key is not configured.")
            self.master.destroy()
            return

         # Membuat ikon menggunakan PhotoImage
        icon_image = PhotoImage(width=16, height=16)  # Membuat ikon 16x16 pixel
        for i in range(16):
            icon_image.put("#00ff00", (i, i))  # Membuat garis diagonal hijau
            icon_image.put("#ff0000", (15 - i, i))  # Membuat garis diagonal merah

        self.master.iconphoto(True, icon_image)  # Menetapkan ikon ke jendela utama

        self.queue = Queue()
        self.stop_event = threading.Event()
        self.quarantined_files = {}

        self.setup_gui()
        self.master.after(100, self.process_queue)

    def setup_gui(self):
        """Setup the GUI components."""
        # Set dark mode for the main window
        self.master.configure(bg="#2b2b2b")  # Background color for the main window

        # Apply dark mode to other elements
        style = ttk.Style()
        style.theme_use("clam")  # Use a ttk theme that supports customization

        # Configure styles
        style.configure("TFrame", background="#2b2b2b")
        style.configure("TLabel", background="#2b2b2b", foreground="#ffffff")
        style.configure("TButton", background="#3c3f41", foreground="#ffffff")
        style.configure("Treeview", background="#3c3f41", foreground="#ffffff", fieldbackground="#3c3f41")
        style.configure("Treeview.Heading", background="#2b2b2b", foreground="#ffffff")

        # Configure progress bar (customize colors)
        style.configure("Horizontal.TProgressbar", 
                        background="#00ff00",  # Bright green for progress bar
                        troughcolor="#1f1f1f",  # Darker gray for the background
                        thickness=20)  # Adjust thickness if needed

        # Original setup for GUI elements
        dir_frame = ttk.Frame(self.master)
        dir_frame.pack(pady=10, padx=10, fill=tk.X)

        ttk.Label(dir_frame, text="Direktori:").pack(side=tk.LEFT, padx=5)
        self.dir_entry = ttk.Entry(dir_frame, width=60)
        self.dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(dir_frame, text="Pilih File", command=self.browse_directory).pack(side=tk.LEFT, padx=5)

        button_frame = ttk.Frame(self.master)
        button_frame.pack(pady=10)

        self.scan_button = ttk.Button(button_frame, text="Mulai Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.quarantine_button = ttk.Button(button_frame, text="Tampilkan File yang Di Karantina", command=self.view_quarantine)
        self.quarantine_button.pack(side=tk.LEFT, padx=5)

        results_frame = ttk.Frame(self.master)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        columns = ("File", "Status", "VirusTotal Results")
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show="headings")
        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, anchor="w", width=300)
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.results_tree.configure(yscrollcommand=scrollbar.set)

        self.results_tree.bind("<Button-1>", self.on_result_click)

        self.progress = ttk.Progressbar(self.master, orient=tk.HORIZONTAL, mode='determinate', style="Horizontal.TProgressbar")
        self.progress.pack(fill=tk.X, padx=10, pady=10)

        self.status_label = ttk.Label(self.master, text="Status: Ready")
        self.status_label.pack(pady=10)



    def browse_directory(self):
        """Open directory selection dialog."""
        directory = filedialog.askdirectory()
        if directory:
            self.dir_entry.delete(0, tk.END)
            self.dir_entry.insert(0, directory)

    def start_scan(self):
        """Start scanning files in a directory."""
        directory = self.dir_entry.get()
        if not os.path.isdir(directory):
            messagebox.showerror("Error", "Masukkan Direktori yang akan di scan terlebih dahulu.")
            return

        self.results_tree.delete(*self.results_tree.get_children())
        self.progress["value"] = 0
        self.status_label.config(text="Status: Scanning...")

        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        self.stop_event.clear()
        threading.Thread(target=self.scan_directory, args=(directory,)).start()

    def stop_scan(self):
        """Stop the ongoing scan."""
        if messagebox.askyesno("Stop Scan", "Yakin menghentikan proses scanning?"):
            self.stop_event.set()

    def scan_directory(self, directory):
        """Scan the selected directory for files."""
        try:
            file_paths = [os.path.join(root, file) for root, _, files in os.walk(directory) for file in files]
            total_files = len(file_paths)
            if total_files == 0:
                self.queue.put(("status", "Tidak ada File yang di temukan."))
                return

            self.queue.put(("set_progress_max", total_files))

            for index, file_path in enumerate(file_paths, 1):
                if self.stop_event.is_set():
                    self.queue.put(("status", "Scan dihentikan."))
                    return

                try:
                    file_hash = self.calculate_file_hash(file_path)
                    vt_result = self.check_virustotal(file_hash)
                    status = "Clean" if vt_result.get("malicious", 0) == 0 else "Malicious"
                    vt_info = f"{vt_result.get('malicious', 0)} / {vt_result.get('total', 0)}"
                    self.queue.put(("update_results", file_path, status, vt_info))
                except Exception as e:
                    self.queue.put(("update_results", file_path, "Error", str(e)))

                self.queue.put(("update_progress", index))
                time.sleep(RATE_LIMIT_DELAY)

            self.queue.put(("status", "Scan complete."))
        except Exception as e:
            self.queue.put(("status", f"Error: {e}"))

    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def check_virustotal(self, file_hash):
        """Query VirusTotal API for file hash."""
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": self.api_key}

        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {"total": stats.get("total", 0), "malicious": stats.get("malicious", 0)}
        elif response.status_code == 404:
            return {"error": "Hash not found in VirusTotal"}
        elif response.status_code == 429:
            raise Exception("Rate limit exceeded.")
        else:
            raise Exception(f"API error: {response.status_code}")

    def quarantine_file(self, file_path):
        """Compress a file into a zip archive and remove the original."""
        quarantine_dir = os.path.dirname(file_path)
    
        try:
            zip_path = os.path.join(quarantine_dir, os.path.basename(file_path) + ".zip")
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                zipf.write(file_path, arcname=os.path.basename(file_path))
        
            os.remove(file_path)
            self.quarantined_files[file_path] = zip_path
            messagebox.showinfo("Success", f"File Berhasil Di ubah ke ZIP: {file_path} -> {zip_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Gagal Mengubah ke ZIP: {e}")


    def restore_file(self, quarantine_path):
        """Restore a quarantined file by decoding it using Base64."""
        try:
            original_path = [k for k, v in self.quarantined_files.items() if v == quarantine_path]
            if not original_path:
                messagebox.showerror("Error", "Original path not found.")
                return

            original_path = original_path[0]
            with open(quarantine_path, "rb") as quarantined_file:
                decoded_data = base64.b64decode(quarantined_file.read())

            with open(original_path, "wb") as restored_file:
                restored_file.write(decoded_data)

            os.remove(quarantine_path)
            del self.quarantined_files[original_path]
            messagebox.showinfo("Success", f"File restored: {original_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to restore file: {e}")

    def on_result_click(self, event):
        """Handle left-click on result rows to show file options."""
        # Identifikasi item Treeview berdasarkan koordinat klik
        item_id = self.results_tree.identify_row(event.y)
        print("Clicked on item ID:", item_id)  # Debugging
        
        if not item_id:
            print("No item identified!")
            return

        # Ambil detail baris yang diklik
        file_path = self.results_tree.item(item_id, "values")[0]
        status = self.results_tree.item(item_id, "values")[1]
        print(f"File Path: {file_path}, Status: {status}")  # Debugging

        # Tampilkan menu sesuai status file
        menu = tk.Menu(self.master, tearoff=0)
        if status == "Malicious":
            menu.add_command(label="Delete permanen", command=lambda: self.delete_file(file_path))
            menu.add_command(label="Ubah ke ZIP", command=lambda: self.quarantine_file(file_path))
        elif status == "Clean":
            messagebox.showinfo("Info", "This file is clean. No actions available.")
        menu.post(event.x_root, event.y_root)



    def delete_file(self, file_path):
        """Delete a file permanently."""
        try:
            os.remove(file_path)
            messagebox.showinfo("Success", f"File deleted permanently: {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete file: {e}")


    def process_queue(self):
        """Process queued updates to the GUI."""
        try:
            while True:
                msg = self.queue.get_nowait()
                if msg[0] == "update_results":
                    file_path, status, vt_info = msg[1], msg[2], msg[3]
                    item_id = self.results_tree.insert("", tk.END, values=(file_path, status, vt_info))

                    # Warna baris sesuai status
                    if status == "Clean":
                        self.results_tree.tag_configure(item_id, background="lightgreen")
                    elif status == "Malicious":
                        self.results_tree.tag_configure(item_id, background="orange")
                elif msg[0] == "update_progress":
                    self.progress["value"] = msg[1]
                elif msg[0] == "set_progress_max":
                    self.progress["maximum"] = msg[1]
                elif msg[0] == "status":
                    self.status_label.config(text=f"Status: {msg[1]}")
                    if msg[1] in ["Scan complete.", "Scan stopped by user."]:
                        self.scan_button.config(state=tk.NORMAL)
                        self.stop_button.config(state=tk.DISABLED)
        except Empty:
            pass
        finally:
            self.master.after(100, self.process_queue)

    def view_quarantine(self):
        """Open a window to view quarantined files."""
        quarantine_window = tk.Toplevel(self.master)
        quarantine_window.title("File yang di Karantina")
        quarantine_window.geometry("600x400")

        columns = ("Original Path", "Quarantine Path")
        tree = ttk.Treeview(quarantine_window, columns=columns, show="headings")
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=280)
        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        for original, quarantine in self.quarantined_files.items():
            tree.insert("", tk.END, values=(original, quarantine))

        def on_quarantine_click(event):
            item_id = tree.identify_row(event.y)
            if not item_id:
                return

            original_path = tree.item(item_id, "values")[0]
            quarantine_path = tree.item(item_id, "values")[1]

            menu = tk.Menu(quarantine_window, tearoff=0)
            menu.add_command(label="Delete Permanen", command=lambda: self.delete_file(quarantine_path))
            menu.add_command(label="Restore", command=lambda: self.restore_file(quarantine_path))
            menu.post(event.x_root, event.y_root)

        tree.bind("<Button-1>", on_quarantine_click)



if __name__ == "__main__":
    root = tk.Tk()
    app = MalwareDetectorGUI(root)
    root.mainloop()