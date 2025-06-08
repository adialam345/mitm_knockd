# MITM Port Knocking Sequence Sniffer

<div align="center">
<pre>
███╗   ███╗██╗████████╗███╗   ███╗    ██╗  ██╗███╗   ██╗ ██████╗  ██████╗██╗  ██╗██╗███╗   ██╗ ██████╗ 
████╗ ████║██║╚══██╔══╝████╗ ████║    ██║ ██╔╝████╗  ██║██╔═══██╗██╔════╝██║ ██╔╝██║████╗  ██║██╔════╝ 
██╔████╔██║██║   ██║   ██╔████╔██║    █████╔╝ ██╔██╗ ██║██║   ██║██║     █████╔╝ ██║██╔██╗ ██║██║  ███╗
██║╚██╔╝██║██║   ██║   ██║╚██╔╝██║    ██╔═██╗ ██║╚██╗██║██║   ██║██║     ██╔═██╗ ██║██║╚██╗██║██║   ██║
██║ ╚═╝ ██║██║   ██║   ██║ ╚═╝ ██║    ██║  ██╗██║ ╚████║╚██████╔╝╚██████╗██║  ██╗██║██║ ╚████║╚██████╔╝
╚═╝     ╚═╝╚═╝   ╚═╝   ╚═╝     ╚═╝    ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 
</pre>
<b>[+] MITM Port Knocking Sequence Sniffer v1.0 [+]</b><br>
<b>[+] Dibuat oleh: MRXNEXSUS [+]</b><br>
<b>[+] Github: github.com/mrxnexsus [+]</b>
</div>

## 📝 Deskripsi

**MITM Port Knocking Sequence Sniffer** adalah sebuah alat keamanan siber yang dirancang untuk melakukan serangan *Man-in-the-Middle* (MITM) menggunakan teknik *ARP Spoofing*. Tujuan utamanya adalah untuk menyadap lalu lintas jaringan antara dua target (misalnya, klien dan server) untuk menemukan urutan *port knocking* yang digunakan untuk membuka port tersembunyi di server.

Alat ini sangat berguna untuk pengujian penetrasi dan analisis keamanan jaringan guna memahami bagaimana mekanisme *port knocking* diimplementasikan dan apakah urutannya dapat dideteksi oleh pihak ketiga.

## ✨ Fitur Utama

-   **Deteksi Urutan Port Knocking**: Secara otomatis menangkap dan menampilkan urutan port TCP yang coba dihubungi oleh target ke server.
-   **ARP Spoofing**: Melakukan serangan *ARP Spoofing* untuk memposisikan diri di tengah-tengah komunikasi antara target dan gateway.
-   **Mode Interaktif**: Memandu pengguna melalui input yang diperlukan seperti IP target, IP server, IP gateway, dan antarmuka jaringan.
-   **Dukungan Multi-Platform**: Berjalan di **Windows** dan **Linux**. Skrip secara otomatis menyesuaikan perintah untuk mengaktifkan/menonaktifkan *IP forwarding*.
-   **Penanganan Otomatis**: Mengaktifkan *IP forwarding* saat serangan dimulai dan menonaktifkannya kembali saat selesai.
-   **Pemulihan Jaringan**: Mengembalikan tabel ARP target dan gateway ke kondisi normal setelah serangan dihentikan untuk memastikan konektivitas jaringan tidak terganggu.
-   **Validasi Input**: Memeriksa format alamat IP yang dimasukkan pengguna untuk mengurangi kesalahan.

## ⚠️ Peringatan (Disclaimer)

Alat ini dibuat **hanya untuk tujuan pendidikan dan pengujian keamanan etis**. Penggunaan alat ini untuk aktivitas ilegal atau tanpa izin dari pemilik jaringan adalah **sepenuhnya tanggung jawab pengguna**. Penulis tidak bertanggung jawab atas penyalahgunaan atau kerusakan yang disebabkan oleh program ini. Selalu patuhi hukum dan etika dalam melakukan pengujian keamanan.

## ⚙️ Cara Kerja

1.  **Input Pengguna**: Skrip akan meminta informasi penting seperti IP target, IP server tujuan, IP gateway, dan antarmuka jaringan yang akan digunakan.
2.  **Aktivasi IP Forwarding**: Skrip akan mengaktifkan *IP forwarding* pada mesin penyerang. Ini memungkinkan paket data dari target dapat diteruskan ke tujuan sebenarnya (gateway/server) sehingga koneksi tidak terputus.
3.  **ARP Spoofing**: Skrip memulai *thread* terpisah untuk terus-menerus mengirim paket ARP palsu ke:
    -   **Target**: Mengatakan bahwa alamat MAC dari **Gateway** adalah alamat MAC **penyerang**.
    -   **Gateway**: Mengatakan bahwa alamat MAC dari **Target** adalah alamat MAC **penyerang**.
    Akibatnya, semua lalu lintas antara target dan gateway akan melewati mesin penyerang.
4.  **Packet Sniffing**: Skrip menggunakan `scapy` untuk mengendus (sniff) semua lalu lintas yang melewati antarmuka jaringan penyerang.
5.  **Deteksi Knocking**: Setiap paket TCP yang berasal dari `TARGET_IP` dan ditujukan ke `SERVER_IP` akan dianalisis. Port tujuan dari setiap paket tersebut akan dicatat secara berurutan.
6.  **Tampilan Hasil**: Urutan port yang terdeteksi akan ditampilkan secara *real-time* dan juga sebagai ringkasan di akhir.
7.  **Pembersihan (Cleanup)**: Ketika pengguna menghentikan skrip (dengan `CTRL+C`), skrip akan secara otomatis mengirim paket ARP yang benar untuk memulihkan tabel ARP korban dan menonaktifkan kembali *IP forwarding*.

## 🔧 Kebutuhan Sistem

-   **Python 3.x**
-   **Scapy**: Library manipulasi paket yang kuat.
-   **Hak Akses Administrator/Root**: Diperlukan untuk melakukan *ARP spoofing* dan memodifikasi pengaturan jaringan.

## 🛠️ Instalasi

1.  **Clone repository atau unduh skrip.**

2.  **Install library `scapy` menggunakan pip:**
    ```bash
    pip install scapy
    ```

## 🚀 Cara Penggunaan

1.  **Buka terminal atau command prompt dengan hak akses Administrator (di Windows) atau sebagai user root (di Linux).**

2.  **Jalankan skrip menggunakan Python:**
    ```bash
    python nmitm.py
    ```

3.  **Ikuti prompt interaktif untuk memasukkan data yang diperlukan:**
    -   **Enter target IP (knocking from)**: Masukkan alamat IP dari mesin klien yang akan melakukan *port knocking*.
    -   **Enter server IP (knocking to)**: Masukkan alamat IP dari server yang menjadi tujuan *port knocking*.
    -   **Enter gateway IP (usually ends with .1)**: Masukkan alamat IP dari router/gateway jaringan.
    -   **Select interface number**: Pilih nomor antarmuka jaringan yang terhubung ke jaringan target.

4.  **Konfirmasi konfigurasi yang Anda masukkan.** Jika sudah benar, ketik `y` dan tekan Enter.

5.  **Biarkan skrip berjalan.** Skrip akan memulai serangan MITM dan mulai memonitor lalu lintas. Setiap kali ada *knock* (upaya koneksi TCP) dari target ke server, portnya akan dicatat dan ditampilkan.

    **Contoh output saat mendeteksi *knock*:**
    ```
    [!!!] New knock detected!
    [!!!] Port: 3000
    [!!!] From: 192.168.1.10:54321
    [!!!] To: 192.168.1.100:3000
    [!!!] TCP Flags: S
    [!!!] Current knock sequence: [1000, 2000, 3000]
    ```

6.  **Hentikan serangan** dengan menekan `CTRL+C`. Skrip akan melakukan proses pembersihan (mengembalikan tabel ARP dan menonaktifkan *IP forwarding*).

7.  **Lihat hasil akhir.** Setelah dihentikan, skrip akan menampilkan ringkasan urutan *port knocking* yang berhasil dideteksi.

    **Contoh hasil akhir:**
    ```
    [+] Results:
    ========================================
    [+] Port knock sequence detected!
    [+] Sequence (in order): 1000, 2000, 3000, 4000
    [+] Total unique ports knocked: 4
    ========================================
    ```
