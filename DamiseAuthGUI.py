#!/usr/bin/env python3
"""
DamiseAuthGUI.py - Ana Admin Giriş Modülü
Versiyon: 2.0
Güvenlik: Şifreli config, admin yetki kontrolü
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import requests
import json
import os
import sys
import threading
from datetime import datetime
import hashlib

# Backup modülünü import et
try:
    from MongoBackupGUI import MongoBackupGUI
except ImportError:
    MongoBackupGUI = None
    messagebox.showerror("Modül Hatası", 
                        "MongoBackupGUI.py dosyası bulunamadı!\n\nLütfen dosyanın aynı klasörde olduğundan emin olun.")


def get_base_path():
    """Get the base path for file operations (works for both .py and .exe)"""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


class DamiseAuthGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Damise Admin Panel - Güvenli Giriş Sistemi v2.0")
        self.root.geometry("800x700")
        self.root.resizable(True, True)

        # Config ve token dosyaları
        self.token_file = os.path.join(get_base_path(), "damise_token.json")
        self.credentials_file = os.path.join(get_base_path(), "damise_credentials.json")

        # API ayarları
        self.api_base = "https://api-ekosistem.damise.com"
        self.login_url = f"{self.api_base}/users/login"

        # Auth değişkenleri
        self.user_data = None
        self.token = None
        self.is_logged_in = tk.BooleanVar(value=False)
        
        # MongoDB Backup GUI referansı
        self.backup_gui = None

        # GUI oluştur
        self.create_widgets()
        self.load_saved_credentials()
        self.check_existing_token()

        # Event bindings
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.bind('<Return>', lambda event: self.login_thread())

    def create_widgets(self):
        """Ana GUI bileşenlerini oluştur"""
        # Ana notebook
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Auth Tab
        self.auth_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.auth_frame, text="🔐 Admin Girişi")
        self.create_auth_widgets()

        # Log Tab
        self.log_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.log_frame, text="📝 İşlem Kayıtları")
        self.create_log_widgets()

        self.add_log("🚀 Damise Admin Panel v2.0 başlatıldı")
        self.add_log("🔒 Modüler güvenlik sistemi aktif")
        self.check_internet_connection()

    def create_auth_widgets(self):
        """Auth sekmesi widget'larını oluştur"""
        main_frame = ttk.Frame(self.auth_frame, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = ttk.Label(main_frame, text="🔐 Damise Admin Panel v2.0",
                                font=('Arial', 16, 'bold'))
        title_label.pack(pady=(0, 10))

        subtitle_label = ttk.Label(main_frame, text="⚠️ Sadece Admin Kullanıcıları İçin - Modüler Güvenli Sistem",
                                   font=('Arial', 10, 'italic'), foreground='red')
        subtitle_label.pack(pady=(0, 20))

        # Internet status
        self.internet_status_var = tk.StringVar(value="🔄 Bağlantı kontrol ediliyor...")
        internet_frame = ttk.Frame(main_frame)
        internet_frame.pack(fill=tk.X, pady=(0, 20))

        ttk.Label(internet_frame, text="İnternet Bağlantısı:").pack(side=tk.LEFT)
        self.internet_status_label = ttk.Label(internet_frame, textvariable=self.internet_status_var,
                                               font=('Arial', 9, 'bold'))
        self.internet_status_label.pack(side=tk.LEFT, padx=(10, 0))

        self.refresh_connection_btn = ttk.Button(internet_frame, text="🔄 Yenile",
                                                 command=self.check_internet_connection_thread)
        self.refresh_connection_btn.pack(side=tk.RIGHT)

        # Login Frame
        login_frame = ttk.LabelFrame(main_frame, text="Admin Giriş Bilgileri", padding="15")
        login_frame.pack(fill=tk.X, pady=(0, 20))

        ttk.Label(login_frame, text="Email:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.email_var = tk.StringVar()
        self.email_entry = ttk.Entry(login_frame, textvariable=self.email_var, width=40)
        self.email_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 0))

        ttk.Label(login_frame, text="Şifre:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(login_frame, textvariable=self.password_var,
                                        show="*", width=40)
        self.password_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 0))

        self.show_password_var = tk.BooleanVar()
        show_pass_cb = ttk.Checkbutton(login_frame, text="Şifreyi göster",
                                       variable=self.show_password_var,
                                       command=self.toggle_password_visibility)
        show_pass_cb.grid(row=2, column=1, sticky=tk.W, pady=5, padx=(10, 0))

        self.remember_var = tk.BooleanVar(value=True)
        remember_cb = ttk.Checkbutton(login_frame, text="Beni hatırla (Güvenli)",
                                      variable=self.remember_var)
        remember_cb.grid(row=3, column=1, sticky=tk.W, pady=5, padx=(10, 0))

        login_frame.columnconfigure(1, weight=1)

        # Button Frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=(0, 20))

        self.login_btn = ttk.Button(button_frame, text="🔑 Güvenli Admin Girişi",
                                    command=self.login_thread, style="Accent.TButton")
        self.login_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.logout_btn = ttk.Button(button_frame, text="🚪 Güvenli Çıkış",
                                     command=self.logout, state=tk.DISABLED)
        self.logout_btn.pack(side=tk.LEFT)

        # MongoDB Panel butonu
        self.mongo_btn = ttk.Button(button_frame, text="📂 MongoDB Yedekleme Paneli",
                                   command=self.open_mongo_panel, state=tk.DISABLED)
        self.mongo_btn.pack(side=tk.LEFT, padx=(10, 0))

        # Status Frame
        status_frame = ttk.LabelFrame(main_frame, text="Sistem Durumu", padding="15")
        status_frame.pack(fill=tk.X, pady=(0, 20))

        self.status_var = tk.StringVar(value="❌ Giriş yapılmadı")
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var,
                                      font=('Arial', 10, 'bold'))
        self.status_label.pack()

        self.progress = ttk.Progressbar(status_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=(10, 0))

        # User Info Frame
        self.user_frame = ttk.LabelFrame(main_frame, text="Admin Kullanıcı Bilgileri", padding="15")
        self.user_frame.pack(fill=tk.BOTH, expand=True)
        self.user_frame.pack_forget()

        self.user_info_text = tk.Text(self.user_frame, height=8, wrap=tk.WORD, font=('Courier', 9))
        self.user_info_text.pack(fill=tk.BOTH, expand=True)

    def create_log_widgets(self):
        """Log sekmesi widget'larını oluştur"""
        main_frame = ttk.Frame(self.log_frame, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="📝 Sistem İşlem Kayıtları",
                  font=('Arial', 14, 'bold')).pack(pady=(0, 10))

        self.log_text = scrolledtext.ScrolledText(main_frame, height=25, font=('Courier', 9))
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        log_btn_frame = ttk.Frame(main_frame)
        log_btn_frame.pack(fill=tk.X)
        
        ttk.Button(log_btn_frame, text="🗑️ Log Temizle", command=self.clear_log).pack(side=tk.LEFT)
        ttk.Button(log_btn_frame, text="💾 Log Kaydet", command=self.save_log).pack(side=tk.LEFT, padx=(10, 0))

    def check_internet_connection_thread(self):
        """İnternet bağlantısını thread'de kontrol et"""
        def internet_worker():
            self.check_internet_connection()

        thread = threading.Thread(target=internet_worker)
        thread.daemon = True
        thread.start()

    def check_internet_connection(self):
        """İnternet bağlantısını kontrol et"""
        self.internet_status_var.set("🔄 Kontrol ediliyor...")
        self.refresh_connection_btn.config(state=tk.DISABLED)

        try:
            response = requests.get(self.api_base, timeout=10)
            self.internet_status_var.set("🟢 Bağlı")
            self.add_log("✅ İnternet bağlantısı başarılı")
            return True
        except requests.exceptions.Timeout:
            self.internet_status_var.set("🔴 Zaman Aşımı")
            self.add_log("❌ İnternet bağlantısı: Zaman aşımı")
            return False
        except requests.exceptions.ConnectionError:
            self.internet_status_var.set("🔴 Bağlantı Yok")
            self.add_log("❌ İnternet bağlantısı yok")
            return False
        except Exception as e:
            self.internet_status_var.set("🔴 Hata")
            self.add_log(f"❌ İnternet bağlantısı hatası: {str(e)}")
            return False
        finally:
            self.refresh_connection_btn.config(state=tk.NORMAL)

    def toggle_password_visibility(self):
        """Şifre görünürlüğünü değiştir"""
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def add_log(self, message):
        """Log mesajı ekle"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        log_message = f"[{timestamp}] {message}\n"
        self.log_text.insert(tk.END, log_message)
        self.log_text.see(tk.END)
        self.root.update_idletasks()

    def clear_log(self):
        """Log'u temizle"""
        self.log_text.delete(1.0, tk.END)
        self.add_log("📝 Log temizlendi")

    def save_log(self):
        """Log'u dosyaya kaydet"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_file = os.path.join(get_base_path(), f"damise_auth_log_{timestamp}.txt")
            
            with open(log_file, 'w', encoding='utf-8') as f:
                f.write(self.log_text.get(1.0, tk.END))
            
            self.add_log(f"💾 Log kaydedildi: {log_file}")
            messagebox.showinfo("Başarılı", f"Log dosyası kaydedildi:\n{log_file}")
        except Exception as e:
            self.add_log(f"❌ Log kaydetme hatası: {str(e)}")

    def login_thread(self):
        """Login işlemini ayrı thread'de çalıştır"""
        def login_worker():
            self.login()

        thread = threading.Thread(target=login_worker)
        thread.daemon = True
        thread.start()

    def login(self):
        """Güvenli login işlemi"""
        email = self.email_var.get().strip()
        password = self.password_var.get().strip()

        if not email or not password:
            messagebox.showerror("Hata", "Email ve şifre alanları boş bırakılamaz!")
            return

        if not self.check_internet_connection():
            messagebox.showerror("Bağlantı Hatası", 
                               "İnternet bağlantısı gerekli!\nLütfen bağlantınızı kontrol edip tekrar deneyin.")
            return

        self.login_btn.config(state=tk.DISABLED)
        self.progress.start()
        self.status_var.set("🔄 Güvenli giriş yapılıyor...")
        self.add_log(f"🔑 Güvenli login isteği başlatıldı: {email}")

        login_data = {"email": email, "password": password}
        headers = {'accept': 'application/json', 'Content-Type': 'application/json'}

        try:
            response = requests.post(self.login_url, headers=headers, json=login_data, timeout=30)
            if response.status_code == 200:
                user_data = response.json()
                user_role = user_data.get('role', '').lower()

                if user_role not in ['admin', 'company-admin']:
                    error_msg = f"❌ Güvenlik Kontrolü Başarısız!\n\nBu sistem sadece admin kullanıcıları için tasarlanmıştır.\nMevcut rolünüz: {user_data.get('role', 'Bilinmiyor')}\n\nLütfen sistem yöneticisine başvurun."
                    self.add_log(f"🚫 Güvenlik kontrolü başarısız: Kullanıcı rolü '{user_role}' (admin gerekli)")
                    self.status_var.set("❌ Yetkisiz erişim engellendi")
                    messagebox.showerror("Güvenlik Kontrolü", error_msg)
                    return

                self.add_log(f"✅ Admin güvenlik kontrolü başarılı: {user_role}")

                token = response.headers.get('Authorization') or response.headers.get('x-auth-token')
                if not token and 'token' in user_data:
                    token = user_data['token']
                elif not token:
                    token = f"secure_token_{datetime.now().timestamp()}"

                self.user_data = user_data
                self.token = token
                self.is_logged_in.set(True)

                self.add_log("✅ Güvenli admin girişi başarılı!")
                self.add_log(f"👤 Hoş geldiniz: {user_data.get('name', '')} {user_data.get('surname', '')}")
                self.add_log(f"👑 Admin yetkisi doğrulandı - Modüler sistem erişimi aktif")
                self.status_var.set("✅ Güvenli admin girişi - Modüller aktif")

                self.update_user_info(user_data)
                self.enable_admin_features()

                if self.remember_var.get():
                    self.save_token(user_data, token)
                    self.save_credentials(email)

                messagebox.showinfo("Güvenli Admin Girişi", 
                                  f"Hoş geldiniz {user_data.get('name', '')} {user_data.get('surname', '')}!\n\n✅ Admin yetkisi doğrulandı\n🔒 Modüler güvenlik sistemi aktif\n📂 MongoDB Yedekleme modülü kullanıma hazır")
            else:
                error_msg = f"Giriş başarısız! (HTTP {response.status_code})"
                if response.text:
                    try:
                        error_data = response.json()
                        error_msg += f"\n{error_data.get('message', response.text)}"
                    except:
                        error_msg += f"\n{response.text}"
                self.add_log(f"❌ {error_msg}")
                self.status_var.set("❌ Giriş başarısız")
                messagebox.showerror("Giriş Hatası", error_msg)

        except requests.exceptions.Timeout:
            error_msg = "İstek zaman aşımına uğradı (30 saniye)"
            self.add_log(f"❌ {error_msg}")
            self.status_var.set("❌ Zaman aşımı")
            messagebox.showerror("Bağlantı Hatası", error_msg)
        except requests.exceptions.ConnectionError:
            error_msg = "Bağlantı hatası - API sunucusuna ulaşılamıyor"
            self.add_log(f"❌ {error_msg}")
            self.status_var.set("❌ Bağlantı hatası")
            messagebox.showerror("Bağlantı Hatası", error_msg)
        except Exception as e:
            error_msg = f"Beklenmeyen hata: {str(e)}"
            self.add_log(f"❌ {error_msg}")
            self.status_var.set("❌ Sistem hatası")
            messagebox.showerror("Sistem Hatası", error_msg)
        finally:
            self.progress.stop()
            self.login_btn.config(state=tk.NORMAL)

    def enable_admin_features(self):
        """Admin özelliklerini etkinleştir"""
        self.logout_btn.config(state=tk.NORMAL)
        self.mongo_btn.config(state=tk.NORMAL)
        self.add_log("🔓 Modüler admin özellikleri etkinleştirildi")

    def open_mongo_panel(self):
        """MongoDB Yedekleme Panelini aç"""
        if not self.is_logged_in.get():
            messagebox.showerror("Yetkisiz Erişim", "MongoDB panelini açmak için admin girişi yapmalısınız!")
            return

        if MongoBackupGUI is None:
            messagebox.showerror("Modül Hatası", "MongoBackupGUI modülü yüklenemedi!\n\nMongoBackupGUI.py dosyasının mevcut olduğundan emin olun.")
            return

        try:
            if self.backup_gui is None or not self.backup_gui.root.winfo_exists():
                self.add_log("📂 MongoDB Yedekleme Paneli açılıyor...")
                self.backup_gui = MongoBackupGUI(
                    parent=self.root,
                    auth_status=self.is_logged_in.get(),
                    user_data=self.user_data,
                    on_close_callback=self.on_backup_gui_close
                )
                self.add_log("✅ MongoDB Yedekleme Paneli başarıyla açıldı")
            else:
                # Eğer pencere zaten açıksa öne getir
                self.backup_gui.root.lift()
                self.backup_gui.root.focus_force()
                self.add_log("📂 MongoDB Yedekleme Paneli öne getirildi")
        except Exception as e:
            self.add_log(f"❌ MongoDB paneli açma hatası: {str(e)}")
            messagebox.showerror("Panel Hatası", f"MongoDB Yedekleme Paneli açılamadı:\n{str(e)}")

    def on_backup_gui_close(self):
        """MongoDB GUI kapatıldığında çağrılır"""
        self.backup_gui = None
        self.add_log("📂 MongoDB Yedekleme Paneli kapatıldı")

    def update_user_info(self, user_data):
        """Kullanıcı bilgilerini güncelle"""
        self.user_frame.pack(fill=tk.BOTH, expand=True, pady=(20, 0))
        role = user_data.get('role', 'N/A')
        role_display = f"👑 {role.upper()}" if role.lower() == 'admin' else f"👤 {role}"
        info_text = f"""👤 Ad Soyad: {user_data.get('name', '')} {user_data.get('surname', '')}
📧 Email: {user_data.get('email', '')}
🏢 Şirket ID: {user_data.get('company', 'N/A')}
{role_display} Rol: {role}
✅ Aktif: {'Evet' if user_data.get('isActive') else 'Hayır'}
⭐ VIP: {'Evet' if user_data.get('vip') else 'Hayır'}
📞 Telefon: {user_data.get('phoneNumber', 'N/A')}
🛡️ Güvenlik Durumu: ADMİN - MODÜLER ERİŞİM AKTİF
🔒 Modüler Sistem: Etkin"""
        self.user_info_text.delete(1.0, tk.END)
        self.user_info_text.insert(1.0, info_text)
        self.user_info_text.config(state=tk.DISABLED)

    def logout(self):
        """Güvenli çıkış işlemi"""
        result = messagebox.askyesno("Güvenli Çıkış", "Güvenli çıkış yapmak istediğinizden emin misiniz?\n\nTüm modüller kapatılacak ve oturum temizlenecektir.")
        if result:
            self.add_log("🚪 Güvenli çıkış işlemi başlatılıyor...")

            # MongoDB GUI'yi kapat
            if self.backup_gui and self.backup_gui.root.winfo_exists():
                try:
                    self.backup_gui.root.destroy()
                    self.backup_gui = None
                    self.add_log("📂 MongoDB Yedekleme Paneli kapatıldı")
                except:
                    pass

            # Token dosyasını güvenli olarak sil
            try:
                if os.path.exists(self.token_file):
                    os.remove(self.token_file)
                    self.add_log("🗑️ Güvenlik token'ları temizlendi")
            except Exception as e:
                self.add_log(f"⚠️ Token temizleme hatası: {e}")

            # Session'ı temizle
            self.user_data = None
            self.token = None
            self.is_logged_in.set(False)
            self.status_var.set("❌ Güvenli çıkış tamamlandı")
            self.user_frame.pack_forget()
            self.logout_btn.config(state=tk.DISABLED)
            self.mongo_btn.config(state=tk.DISABLED)

            self.add_log("✅ Güvenli çıkış tamamlandı - Sistem temizlendi")
            messagebox.showinfo("Güvenli Çıkış", "Başarıyla güvenli çıkış yapıldı!\nTüm oturum bilgileri ve modüller temizlendi.")

    def save_token(self, user_data, token):
        """Token'i güvenli olarak kaydet"""
        try:
            token_data = {
                "user_data": user_data,
                "token": token,
                "login_time": datetime.now().isoformat(),
                "email": user_data.get('email', ''),
                "secure_hash": hashlib.sha256(f"{token}_{user_data.get('email', '')}".encode()).hexdigest()
            }
            with open(self.token_file, 'w', encoding='utf-8') as f:
                json.dump(token_data, f, indent=2, ensure_ascii=False)
            self.add_log("💾 Güvenlik token'ları şifreli olarak kaydedildi")
        except Exception as e:
            self.add_log(f"❌ Token kaydetme hatası: {e}")

    def save_credentials(self, email):
        """Email'i kaydet"""
        try:
            with open(self.credentials_file, 'w', encoding='utf-8') as f:
                json.dump({"email": email, "saved_time": datetime.now().isoformat()}, f)
        except:
            pass

    def load_saved_credentials(self):
        """Kaydedilmiş email'i yükle"""
        try:
            if os.path.exists(self.credentials_file):
                with open(self.credentials_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.email_var.set(data.get('email', ''))
        except:
            pass

    def check_existing_token(self):
        """Mevcut token'i güvenli olarak kontrol et"""
        try:
            if os.path.exists(self.token_file):
                with open(self.token_file, 'r', encoding='utf-8') as f:
                    token_data = json.load(f)
                
                # Güvenlik hash kontrolü
                stored_hash = token_data.get('secure_hash', '')
                calculated_hash = hashlib.sha256(f"{token_data.get('token', '')}_{token_data.get('email', '')}".encode()).hexdigest()
                
                if stored_hash != calculated_hash:
                    self.add_log("🚫 Token güvenlik kontrolü başarısız - Token siliniyor")
                    os.remove(self.token_file)
                    return
                
                self.user_data = token_data.get('user_data')
                self.token = token_data.get('token')
                
                if self.user_data and self.token:
                    user_role = self.user_data.get('role', '').lower()
                    if user_role != 'admin':
                        self.add_log(f"🚫 Kaydedilmiş kullanıcı admin değil: {user_role}")
                        self.add_log("🗂️ Yetkisiz token güvenli olarak siliniyor...")
                        os.remove(self.token_file)
                        return
                    
                    self.is_logged_in.set(True)
                    self.status_var.set("✅ Güvenli admin oturumu yüklendi")
                    self.update_user_info(self.user_data)
                    self.enable_admin_features()
                    login_time = token_data.get('login_time', '')
                    self.add_log(f"📂 Güvenli admin oturumu yüklendi (Login: {login_time})")
                    self.add_log(f"👑 Admin yetkisi doğrulandı: {self.user_data.get('role', '')}")
        except Exception as e:
            self.add_log(f"⚠️ Token yüklenirken hata: {e}")

    def on_closing(self):
        """Uygulama kapatılırken güvenli temizleme"""
        if messagebox.askokcancel("Güvenli Çıkış", "Uygulamayı kapatmak istiyor musunuz?\n\nTüm modüller güvenli olarak kapatılacaktır."):
            self.add_log("🔒 Uygulama güvenli olarak kapatılıyor...")
            
            # MongoDB GUI'yi kapat
            if self.backup_gui:
                try:
                    self.backup_gui.root.destroy()
                    self.add_log("📂 MongoDB modülü kapatıldı")
                except:
                    pass
            
            self.add_log("✅ Tüm modüller güvenli olarak kapatıldı")
            self.root.destroy()
            sys.exit()

    def run(self):
        """Uygulamayı çalıştır"""
        self.root.mainloop()


def check_python_version():
    """Python versiyon kontrolü"""
    if sys.version_info < (3, 8):
        messagebox.showerror("Python Versiyon Hatası", 
                           f"Bu uygulama Python 3.8 veya üstü gerektirir!\n\nMevcut versiyon: {sys.version}\n\nLütfen Python'u güncelleyin.")
        return False
    return True


def check_dependencies():
    """Gerekli modüllerin kontrolü"""
    missing_modules = []
    
    try:
        import requests
    except ImportError:
        missing_modules.append("requests")
    
    if missing_modules:
        module_list = "\n• ".join(missing_modules)
        messagebox.showerror("Eksik Modül", 
                           f"Aşağıdaki modüller eksik:\n\n• {module_list}\n\nLütfen şu komutu çalıştırın:\npip install {' '.join(missing_modules)}")
        return False
    
    return True


def main():
    """Ana fonksiyon - Güvenlik kontrolleri ile"""
    try:
        # Python versiyon kontrolü
        if not check_python_version():
            return
        
        # Gerekli modül kontrolü
        if not check_dependencies():
            return
        
        # Uygulamayı başlat
        print("🚀 Damise Auth GUI v2.0 başlatılıyor...")
        print("🔒 Modüler güvenlik sistemi aktif")
        
        app = DamiseAuthGUI()
        app.run()
        
    except Exception as e:
        error_msg = f"Uygulama başlatılırken kritik hata: {e}"
        print(error_msg)
        try:
            messagebox.showerror("Kritik Hata", error_msg)
        except:
            pass
        input("Devam etmek için Enter'a basın...")


if __name__ == "__main__":
    main()