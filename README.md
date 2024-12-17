Virus Scanner Kelompok 8
Virus Scanner ini adalah aplikasi GUI sederhana berbasis Python yang menggunakan VirusTotal API untuk mendeteksi file yang mencurigakan atau berbahaya di direktori Anda. Program ini dirancang untuk mempermudah proses scanning file, menampilkan hasilnya, serta menyediakan opsi untuk menghapus atau mengkarantina file berbahaya.

Fitur Utama
Antarmuka GUI Modern: Menggunakan Tkinter dengan tema dark mode.
Integrasi VirusTotal API: Melakukan query untuk mengecek status file berdasarkan hash SHA-256.
Progress Bar: Menampilkan kemajuan proses scanning secara real-time.
Manajemen Karantina: Mengkarantina file yang berbahaya dengan mengubahnya menjadi format ZIP.
Restore File Karantina: Memulihkan file yang telah dikarantina.
Support Multi-Threading: Menghindari aplikasi hang saat proses scanning.
Prasyarat
Sebelum menjalankan program ini, pastikan Anda telah menginstal Python 3.6 atau yang lebih baru, serta menginstal dependensi berikut:

requests
tkinter
Gunakan perintah berikut untuk menginstal dependensi:

bash
Salin kode
pip install requests
Cara Menggunakan
Clone repository ini:

bash
Salin kode
git clone https://github.com/username/repo-name.git
cd repo-name
Buka file py_VirusScanner_API_VIRUS-TOTAL.py dan masukkan API key VirusTotal Anda di variabel VIRUSTOTAL_API_KEY:

python
Salin kode
VIRUSTOTAL_API_KEY = "INPUT_API_VIRUS-TOTAL"
Jalankan program:

bash
Salin kode
python py_VirusScanner_API_VIRUS-TOTAL.py
Pilih direktori yang ingin di-scan, lalu klik Mulai Scan untuk memulai proses scanning.

Struktur Program
MalwareDetectorGUI: Kelas utama untuk menangani antarmuka dan logika aplikasi.
Fungsi Utama:
browse_directory(): Memilih direktori untuk scanning.
start_scan(): Memulai proses scanning.
quarantine_file(): Mengkarantina file berbahaya.
restore_file(): Memulihkan file yang dikarantina.
check_virustotal(): Melakukan query ke VirusTotal API untuk memeriksa file.
Catatan
Aplikasi ini membutuhkan koneksi internet untuk berkomunikasi dengan VirusTotal API.
Ada rate limit 4 permintaan per menit untuk API gratis. Program ini telah diatur dengan delay untuk menghindari pembatasan ini.
