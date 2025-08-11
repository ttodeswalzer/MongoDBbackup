#!/usr/bin/env python3
"""
MongoBackupGUI.py - MongoDB Yedekleme Modülü
Versiyon: 2.0
Güvenlik: Şifreli config, tarih bazlı yedekleme, modüler yapı
"""

import json
import os
import sys
import threading
from datetime import datetime
from tkinter import filedialog, messagebox, ttk
import tkinter as tk
from sshtunnel import SSHTunnelForwarder
import base64
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# .env dosyasını yükle
load_dotenv()

try:
    import pymongo
    from bson import ObjectId
    from bson.binary import Binary
except ImportError:
    pymongo = None
    ObjectId = None
    Binary = None


def get_base_path():
    """Get the base path for file operations (works for both .py and .exe)"""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


class ConfigManager:
    """Güvenli config yönetimi - şifreli depolama"""
    
    def __init__(self, config_file):
        self.config_file = config_file
        self.key_file = config_file.replace('.json', '.key')
        self.cipher = None
        self._init_encryption()
    
    def _init_encryption(self):
        """Şifreleme anahtarını başlat"""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            # Key dosyasını gizle (Windows)
            if sys.platform == 'win32':
                try:
                    import subprocess
                    subprocess.run(['attrib', '+H', self.key_file], shell=True)
                except:
                    pass
        
        self.cipher = Fernet(key)
    
    def save_config(self, config):
        """Config'i şifreli olarak kaydet"""
        try:
            # Hassas bilgileri şifrele
            encrypted_config = config.copy()
            if 'ssh_password' in encrypted_config and encrypted_config['ssh_password']:
                encrypted_config['ssh_password'] = self.cipher.encrypt(
                    encrypted_config['ssh_password'].encode()
                ).decode()
                encrypted_config['_ssh_encrypted'] = True
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(encrypted_config, f, indent=2)
            return True
        except Exception as e:
            print(f"Config kaydetme hatası: {e}")
            return False
    
    def load_config(self):
        """Config'i şifreli olarak yükle"""
        # Çevre değişkenlerinden varsayılan değerleri al
        backup_dir_name = os.getenv('BACKUP_DIR_NAME', 'damise_backups')
        ssh_host = os.getenv('SSH_LOCAL_BIND_ADDRESS', 'localhost')
        ssh_port = int(os.getenv('SSH_DEFAULT_PORT', '22'))
        mongo_host = os.getenv('MONGODB_DEFAULT_HOST', 'localhost')
        mongo_port = int(os.getenv('MONGODB_DEFAULT_PORT', '27017'))
        
        default_config = {
            "ssh_host": ssh_host,
            "ssh_port": ssh_port,
            "ssh_username": "",
            "ssh_password": "",
            "mongo_host": mongo_host,
            "mongo_port": mongo_port,
            "saved_databases": [],
            "backup_dir": os.path.join(os.path.expanduser("~"), backup_dir_name),
            "_ssh_encrypted": False
        }
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                # Şifreli şifreyi çöz
                if config.get('_ssh_encrypted') and config.get('ssh_password'):
                    try:
                        decrypted_pass = self.cipher.decrypt(
                            config['ssh_password'].encode()
                        ).decode()
                        config['ssh_password'] = decrypted_pass
                    except Exception:
                        config['ssh_password'] = ""
                        config['_ssh_encrypted'] = False
                
                # Eski format uyumluluğu
                if isinstance(config.get("saved_databases"), str):
                    config["saved_databases"] = [config["saved_databases"]]
                
                default_config.update(config)
                return default_config
            else:
                self.save_config(default_config)
                return default_config
        except Exception as e:
            print(f"Config yükleme hatası: {e}")
            return default_config


class SSHPresetManager:
    """SSH bağlantı önayarlarını yöneten sınıf"""
    
    def __init__(self, config_manager, logger=None):
        self.config_manager = config_manager
        self.logger = logger
        self.presets_key = "ssh_presets"
    
    def log(self, message):
        if self.logger:
            self.logger(message)
    
    def save_preset(self, name, ssh_host, ssh_port, ssh_username, mongo_host, mongo_port):
        """SSH preset kaydet (şifre hariç)"""
        try:
            config = self.config_manager.load_config()
            if self.presets_key not in config:
                config[self.presets_key] = {}
            
            preset_data = {
                "ssh_host": ssh_host,
                "ssh_port": ssh_port, 
                "ssh_username": ssh_username,
                "mongo_host": mongo_host,
                "mongo_port": mongo_port,
                "created_date": datetime.now().isoformat()
            }
            
            config[self.presets_key][name] = preset_data
            
            if self.config_manager.save_config(config):
                self.log(f"💾 SSH preset '{name}' kaydedildi")
                return True
            else:
                self.log(f"❌ SSH preset '{name}' kaydedilemedi")
                return False
        except Exception as e:
            self.log(f"❌ Preset kaydetme hatası: {str(e)}")
            return False
    
    def load_presets(self):
        """Tüm presetleri yükle"""
        try:
            config = self.config_manager.load_config()
            return config.get(self.presets_key, {})
        except Exception as e:
            self.log(f"❌ Preset yükleme hatası: {str(e)}")
            return {}
    
    def get_preset(self, name):
        """Belirli bir preset'i getir"""
        presets = self.load_presets()
        return presets.get(name, None)
    
    def delete_preset(self, name):
        """Preset sil"""
        try:
            config = self.config_manager.load_config()
            if self.presets_key in config and name in config[self.presets_key]:
                del config[self.presets_key][name]
                if self.config_manager.save_config(config):
                    self.log(f"🗑️ SSH preset '{name}' silindi")
                    return True
            return False
        except Exception as e:
            self.log(f"❌ Preset silme hatası: {str(e)}")
            return False


class BackupManager:
    """Yedekleme işlemlerini yöneten sınıf - Tarih bazlı dosya yapısı"""

    def __init__(self, mongo_uri, backup_dir, logger=None):
        self.mongo_uri = mongo_uri
        self.backup_dir = backup_dir
        self.logger = logger

    def log(self, message):
        """Log mesajı gönder"""
        if self.logger:
            self.logger(message)

    def _json_serializable(self, obj):
        """Özel türleri JSON serileştirilebilir hale getirir"""
        if isinstance(obj, ObjectId):
            return str(obj)
        elif isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, Binary):
            return base64.b64encode(obj).decode('utf-8')
        elif isinstance(obj, bytes):
            return base64.b64encode(obj).decode('utf-8')
        raise TypeError(f"Type {type(obj)} is not JSON serializable")

    def _create_date_folder(self):
        """Bugünün tarihinde klasör oluştur"""
        today = datetime.now().strftime("%d.%m.%Y")
        date_folder = os.path.join(self.backup_dir, today)
        os.makedirs(date_folder, exist_ok=True)
        return date_folder

    def backup_collection(self, db_name, collection_name, output_file):
        """Tek bir koleksiyonu yedekle"""
        try:
            client = pymongo.MongoClient(self.mongo_uri, serverSelectionTimeoutMS=10000)
            db = client[db_name]
            collection = db[collection_name]

            self.log(f"⏳ {db_name}.{collection_name} koleksiyonu yedekleniyor...")

            with open(output_file, 'w', encoding='utf-8') as f:
                first = True
                f.write('[')
                for doc in collection.find(batch_size=1000):
                    if not first:
                        f.write(',')
                    json.dump(doc, f, default=self._json_serializable, ensure_ascii=False)
                    first = False
                f.write(']')

            self.log(f"✅ {db_name}.{collection_name} koleksiyonu yedeklendi")
            client.close()
            return True

        except Exception as e:
            self.log(f"❌ {db_name}.{collection_name} yedeklenirken hata: {str(e)}")
            return False

    def backup_database(self, db_name):
        """Tüm veritabanını tarih klasörüne yedekle"""
        try:
            client = pymongo.MongoClient(self.mongo_uri, serverSelectionTimeoutMS=10000)
            db = client[db_name]

            # Tarih klasörü oluştur
            date_folder = self._create_date_folder()
            timestamp = datetime.now().strftime("%H%M%S")
            
            collections = db.list_collection_names()
            success_count = 0

            if len(collections) == 1:
                # Tek koleksiyon varsa doğrudan veritabanı adıyla kaydet
                collection_name = collections[0]
                output_file = os.path.join(date_folder, f"{db_name}.json")
                if self.backup_collection(db_name, collection_name, output_file):
                    success_count += 1
                    self.log(f"✅ {db_name} veritabanı tek dosya olarak yedeklendi: {output_file}")
            else:
                # Birden fazla koleksiyon varsa klasör oluştur
                db_folder = os.path.join(date_folder, f"{db_name}_{timestamp}")
                os.makedirs(db_folder, exist_ok=True)
                
                for collection_name in collections:
                    output_file = os.path.join(db_folder, f"{collection_name}.json")
                    if self.backup_collection(db_name, collection_name, output_file):
                        success_count += 1
                
                self.log(f"✅ {db_name} veritabanı klasör olarak yedeklendi: {db_folder}")

            client.close()
            self.log(f"📊 {success_count}/{len(collections)} koleksiyon başarıyla yedeklendi")

            return date_folder, success_count == len(collections)

        except Exception as e:
            self.log(f"❌ {db_name} veritabanı yedeklenirken hata: {str(e)}")
            return None, False

    def backup_selected_collections(self, db_name, collections):
        """Seçili koleksiyonları tarih klasörüne yedekle"""
        try:
            date_folder = self._create_date_folder()
            timestamp = datetime.now().strftime("%H%M%S")
            
            success_count = 0

            if len(collections) == 1:
                # Tek koleksiyon
                collection_name = collections[0]
                output_file = os.path.join(date_folder, f"{db_name}_{collection_name}.json")
                if self.backup_collection(db_name, collection_name, output_file):
                    success_count += 1
            else:
                # Birden fazla koleksiyon
                output_dir = os.path.join(date_folder, f"{db_name}_selected_{timestamp}")
                os.makedirs(output_dir, exist_ok=True)
                
                for collection_name in collections:
                    output_file = os.path.join(output_dir, f"{collection_name}.json")
                    if self.backup_collection(db_name, collection_name, output_file):
                        success_count += 1

            self.log(f"✅ {db_name} seçili yedekleme tamamlandı: {date_folder}")
            self.log(f"📊 {success_count}/{len(collections)} koleksiyon başarıyla yedeklendi")

            return date_folder, success_count == len(collections)

        except Exception as e:
            self.log(f"❌ {db_name} seçili koleksiyonları yedeklenirken hata: {str(e)}")
            return None, False


class ConnectionManager:
    """Bağlantı yönetimini sağlayan sınıf"""

    def __init__(self, logger=None):
        self.ssh_tunnel = None
        self.mongo_uri = None
        self.is_connected = False
        self.available_dbs = []
        self.logger = logger

    def log(self, message):
        """Log mesajı gönder"""
        if self.logger:
            self.logger(message)

    def connect_ssh(self, ssh_host, ssh_port, username, password, mongo_host, mongo_port):
        """SSH bağlantısı kur"""
        try:
            # Çevre değişkenlerinden local bind address'i al
            local_bind_host = os.getenv('SSH_LOCAL_BIND_ADDRESS', 'localhost')
            
            self.log(f"SSH bağlantısı kuruluyor: {username}@{ssh_host}:{ssh_port}")

            self.ssh_tunnel = SSHTunnelForwarder(
                (ssh_host, ssh_port),
                ssh_username=username,
                ssh_password=password,
                remote_bind_address=(mongo_host, mongo_port),
                local_bind_address=(local_bind_host, 0)
            )
            self.ssh_tunnel.start()

            self.log(f"SSH tüneli başarıyla açıldı ({local_bind_host}:{self.ssh_tunnel.local_bind_port})")
            return True, f"{local_bind_host}:{self.ssh_tunnel.local_bind_port}"

        except Exception as e:
            self.log(f"SSH bağlantı hatası: {str(e)}")
            return False, str(e)

    def connect_mongo(self):
        """MongoDB bağlantısını test et ve veritabanlarını listele"""
        if not self.ssh_tunnel:
            return False, "SSH bağlantısı bulunamadı"

        try:
            # Çevre değişkenlerinden değerleri al
            local_bind_host = os.getenv('SSH_LOCAL_BIND_ADDRESS', 'localhost')
            connection_timeout = int(os.getenv('MONGODB_CONNECTION_TIMEOUT', '5000'))
            
            self.mongo_uri = f"mongodb://{local_bind_host}:{self.ssh_tunnel.local_bind_port}/"
            client = pymongo.MongoClient(self.mongo_uri, serverSelectionTimeoutMS=connection_timeout)
            client.admin.command('ping')

            self.available_dbs = client.list_database_names()
            self.is_connected = True

            self.log(f"✅ Tüm veritabanları: {', '.join(self.available_dbs)}")
            self.log(f"📊 Toplam {len(self.available_dbs)} veritabanı bulundu")
            client.close()

            return True, self.available_dbs

        except Exception as e:
            self.log(f"❌ MongoDB bağlantı hatası: {str(e)}")
            return False, str(e)

    def get_collections(self, db_name):
        """Veritabanındaki koleksiyonları al"""
        if not self.is_connected:
            return []

        try:
            # Çevre değişkeninden timeout değerini al
            connection_timeout = int(os.getenv('MONGODB_CONNECTION_TIMEOUT', '10000'))
            
            client = pymongo.MongoClient(self.mongo_uri, serverSelectionTimeoutMS=connection_timeout)
            db = client[db_name]
            collections = db.list_collection_names()
            client.close()
            return collections
        except Exception as e:
            self.log(f"❌ Koleksiyonlar alınırken hata: {str(e)}")
            return []

    def disconnect(self):
        """Tüm bağlantıları kes"""
        try:
            if self.ssh_tunnel:
                self.ssh_tunnel.stop()
                self.log("SSH bağlantısı kapatıldı")

            self.is_connected = False
            self.available_dbs = []
            self.mongo_uri = None

        except Exception as e:
            self.log(f"Bağlantı kapatma hatası: {str(e)}")


class DatabaseSaveManager:
    """Veritabanı kaydetme ve yükleme işlemleri"""
    
    def __init__(self, config_manager, logger=None):
        self.config_manager = config_manager
        self.logger = logger
    
    def log(self, message):
        if self.logger:
            self.logger(message)
    
    def save_databases(self, databases, ssh_info):
        """Seçili veritabanlarını config'e kaydet"""
        try:
            config = self.config_manager.load_config()
            config['saved_databases'] = databases
            config.update(ssh_info)  # SSH bilgilerini de kaydet
            
            if self.config_manager.save_config(config):
                self.log(f"💾 {len(databases)} veritabanı güvenli olarak kaydedildi: {', '.join(databases)}")
                return True
            else:
                self.log("❌ Veritabanları kaydedilemedi")
                return False
        except Exception as e:
            self.log(f"❌ Kaydetme hatası: {str(e)}")
            return False
    
    def load_saved_databases(self):
        """Kaydedilmiş veritabanlarını yükle"""
        try:
            config = self.config_manager.load_config()
            return config.get('saved_databases', [])
        except Exception as e:
            self.log(f"❌ Yükleme hatası: {str(e)}")
            return []


class MongoBackupGUI:
    def __init__(self, parent=None, auth_status=False, user_data=None, on_close_callback=None):
        if parent is None:
            raise RuntimeError("Bu modül bağımsız olarak çalıştırılamaz. DamiseAuthGUI tarafından çağrılmalıdır.")
        if not auth_status:
            messagebox.showerror("Yetkisiz Erişim", "MongoDB Yedekleme Aracı'nı açmak için admin girişi yapmalısınız!")
            raise RuntimeError("Admin yetkisi olmadan MongoBackupGUI başlatılamaz.")

        # Çevre değişkenlerinden değerleri al
        backup_app_title = os.getenv('BACKUP_APP_TITLE', 'Damise MongoDB Yedekleme Aracı')
        app_version = os.getenv('APP_VERSION', '2.0')
        backup_window_width = int(os.getenv('BACKUP_WINDOW_WIDTH', '1000'))
        backup_window_height = int(os.getenv('BACKUP_WINDOW_HEIGHT', '900'))
        
        self.root = tk.Toplevel(parent)
        self.root.title(f"{backup_app_title} v{app_version} - Güvenli Tarih Bazlı Sistem")
        self.root.geometry(f"{backup_window_width}x{backup_window_height}")
        self.root.resizable(True, True)
        self.on_close_callback = on_close_callback
        self.user_data = user_data

        # Config yöneticisi
        config_file_name = os.getenv('CONFIG_FILE_NAME', 'damise_config.json')
        config_file = os.path.join(get_base_path(), config_file_name)
        self.config_manager = ConfigManager(config_file)
        self.config = self.config_manager.load_config()

        # Gerekli modül kontrolü
        if pymongo is None:
            messagebox.showerror("Eksik Modül", 
                               "pymongo modülü bulunamadı!\n\nLütfen şu komutu çalıştırın:\npip install pymongo sshtunnel cryptography python-dotenv\n\nPython 3.8+ gereklidir.")
            self.root.destroy()
            return

        # Managers
        self.connection_manager = ConnectionManager(logger=self.log)
        self.backup_manager = None
        self.db_save_manager = DatabaseSaveManager(self.config_manager, logger=self.log)
        self.ssh_preset_manager = SSHPresetManager(self.config_manager, logger=self.log)

        # GUI bileşenlerini oluştur
        self.create_widgets()

        # Pencere kapatma olayı
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.log("🚀 MongoDB Yedekleme Aracı v2.0 başlatıldı")
        self.log(f"👤 Kullanıcı: {user_data.get('name', '')} {user_data.get('surname', '')}")
        self.log("🔒 Güvenli şifreli sistem aktif")

    def create_widgets(self):
        """GUI bileşenlerini oluşturur"""
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header
        self.create_header(main_frame)

        # Connection Frame
        self.create_connection_frame(main_frame)

        # Database Selection Frame
        self.create_database_frame(main_frame)

        # Backup Frame
        self.create_backup_frame(main_frame)

        # Log Frame
        self.create_log_frame(main_frame)

    def create_header(self, parent):
        """Header bölümünü oluştur"""
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill=tk.X, pady=(0, 20))

        title_label = ttk.Label(header_frame, text="📂 MongoDB Güvenli Yedekleme Sistemi v2.0",
                               font=('Arial', 16, 'bold'))
        title_label.pack(side=tk.LEFT)

        # Kullanıcı bilgisi
        if self.user_data:
            user_label = ttk.Label(header_frame, 
                                  text=f"👤 {self.user_data.get('name', '')} {self.user_data.get('surname', '')}",
                                  font=('Arial', 10), foreground="green")
            user_label.pack(side=tk.RIGHT)

    def create_connection_frame(self, parent):
        """Bağlantı ayarları frame'ini oluştur"""
        conn_frame = ttk.LabelFrame(parent, text="🔒 Güvenli Bağlantı Ayarları", padding="15")
        conn_frame.pack(fill=tk.X, pady=(0, 15))

        # Preset yönetimi frame
        preset_frame = ttk.Frame(conn_frame)
        preset_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(preset_frame, text="📋 Bağlantı Önayarları:", font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        
        preset_control_frame = ttk.Frame(preset_frame)
        preset_control_frame.pack(fill=tk.X, pady=(5, 0))
        
        # Preset dropdown
        ttk.Label(preset_control_frame, text="Kayıtlı Bağlantılar:").pack(side=tk.LEFT)
        
        self.preset_var = tk.StringVar()
        self.preset_combo = ttk.Combobox(preset_control_frame, textvariable=self.preset_var, 
                                        state="readonly", width=20)
        self.preset_combo.pack(side=tk.LEFT, padx=(10, 10))
        self.preset_combo.bind('<<ComboboxSelected>>', self.load_selected_preset)
        
        ttk.Button(preset_control_frame, text="📥 Yükle", 
                  command=self.load_selected_preset).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(preset_control_frame, text="🗑️ Sil", 
                  command=self.delete_selected_preset).pack(side=tk.LEFT)
        
        # Yeni preset kaydetme
        save_preset_frame = ttk.Frame(preset_frame)
        save_preset_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Label(save_preset_frame, text="Yeni Kayıt:").pack(side=tk.LEFT)
        
        self.preset_name_var = tk.StringVar()
        preset_entry = ttk.Entry(save_preset_frame, textvariable=self.preset_name_var, width=20)
        preset_entry.pack(side=tk.LEFT, padx=(10, 10))
        
        ttk.Button(save_preset_frame, text="💾 Kaydet", 
                  command=self.save_current_preset).pack(side=tk.LEFT)

        # Ayırıcı çizgi
        ttk.Separator(conn_frame, orient='horizontal').pack(fill=tk.X, pady=(15, 15))

        # SSH ayarları
        ssh_frame = ttk.Frame(conn_frame)
        ssh_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(ssh_frame, text="SSH Sunucusu:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.ssh_host_var = tk.StringVar()  # BOŞ BAŞLAR
        ttk.Entry(ssh_frame, textvariable=self.ssh_host_var, width=25).grid(row=0, column=1, sticky=tk.W, padx=5)

        ttk.Label(ssh_frame, text="Port:").grid(row=0, column=2, sticky=tk.W, padx=(15, 5))
        self.ssh_port_var = tk.StringVar(value="22")  # SADECE VARSAYILAN PORT
        ttk.Entry(ssh_frame, textvariable=self.ssh_port_var, width=8).grid(row=0, column=3, sticky=tk.W, padx=5)

        ttk.Label(ssh_frame, text="Kullanıcı:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.ssh_user_var = tk.StringVar()  # BOŞ BAŞLAR
        ttk.Entry(ssh_frame, textvariable=self.ssh_user_var, width=25).grid(row=1, column=1, sticky=tk.W, padx=5)

        ttk.Label(ssh_frame, text="🔑 Şifre:").grid(row=1, column=2, sticky=tk.W, padx=(15, 5))
        self.ssh_pass_var = tk.StringVar()  # ŞİFRE HER ZAMAN BOŞ BAŞLAR
        password_entry = ttk.Entry(ssh_frame, textvariable=self.ssh_pass_var, show="*", width=15)
        password_entry.grid(row=1, column=3, sticky=tk.W, padx=5)
        
        # Şifre için özel not
        ttk.Label(ssh_frame, text="⚠️ Güvenlik: Şifre her seferinde girilmeli", 
                 foreground="red", font=('Arial', 8)).grid(row=2, column=2, columnspan=2, sticky=tk.W, padx=(15, 0))

        # MongoDB ayarları
        mongo_frame = ttk.Frame(conn_frame)
        mongo_frame.pack(fill=tk.X, pady=(10, 10))

        # Çevre değişkenlerinden varsayılan değerleri al
        mongo_host = os.getenv('MONGODB_DEFAULT_HOST', 'localhost')
        mongo_port = os.getenv('MONGODB_DEFAULT_PORT', '27017')

        ttk.Label(mongo_frame, text="MongoDB Host:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.mongo_host_var = tk.StringVar(value=mongo_host)  # SADECE VARSAYILAN
        ttk.Entry(mongo_frame, textvariable=self.mongo_host_var, width=25).grid(row=0, column=1, sticky=tk.W, padx=5)

        ttk.Label(mongo_frame, text="Port:").grid(row=0, column=2, sticky=tk.W, padx=(15, 5))
        self.mongo_port_var = tk.StringVar(value=mongo_port)  # SADECE VARSAYILAN
        ttk.Entry(mongo_frame, textvariable=self.mongo_port_var, width=8).grid(row=0, column=3, sticky=tk.W, padx=5)

        # Bağlantı butonları ve durum
        btn_frame = ttk.Frame(conn_frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))

        ttk.Button(btn_frame, text="🔌 SSH Bağlan", command=self.connect_ssh_thread).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_frame, text="🔗 MongoDB Bağlan", command=self.connect_mongo_thread).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_frame, text="✂️ Bağlantıyı Kes", command=self.disconnect).pack(side=tk.LEFT)

        self.status_var = tk.StringVar(value="🔴 Güvenli bağlantı bekleniyor...")
        ttk.Label(btn_frame, textvariable=self.status_var, foreground="blue").pack(side=tk.RIGHT)
        
        # Widget'lar oluşturulduktan SONRA presetleri yükle
        self.root.after(100, self.refresh_preset_list)

    def create_database_frame(self, parent):
        """Veritabanı seçimi frame'ini oluştur"""
        db_frame = ttk.LabelFrame(parent, text="📊 Veritabanı Yönetimi", padding="15")
        db_frame.pack(fill=tk.X, pady=(0, 15))

        # Top frame with save button
        db_top_frame = ttk.Frame(db_frame)
        db_top_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(db_top_frame, text="Mevcut Veritabanları:").pack(side=tk.LEFT)
        
        # Kaydet butonu
        self.save_db_btn = ttk.Button(db_top_frame, text="💾 Seçilileri Kaydet", 
                                      command=self.save_selected_databases, state=tk.DISABLED)
        self.save_db_btn.pack(side=tk.RIGHT)

        # Listbox frame
        listbox_frame = ttk.Frame(db_frame)
        listbox_frame.pack(fill=tk.X, pady=(0, 10))

        self.db_listbox = tk.Listbox(listbox_frame, selectmode=tk.MULTIPLE, height=6)
        self.db_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar_db = ttk.Scrollbar(listbox_frame, command=self.db_listbox.yview)
        scrollbar_db.pack(side=tk.RIGHT, fill=tk.Y)
        self.db_listbox.config(yscrollcommand=scrollbar_db.set)

        self.db_listbox.insert(tk.END, "MongoDB'ye güvenli bağlantı kurun...")

        # Kaydedilen veritabanları göster
        saved_frame = ttk.Frame(db_frame)
        saved_frame.pack(fill=tk.X)
        
        ttk.Label(saved_frame, text="💾 Kaydedilen Veritabanları:", font=('Arial', 9, 'bold')).pack(anchor=tk.W)
        
        self.saved_db_var = tk.StringVar()
        saved_databases = self.db_save_manager.load_saved_databases()
        if saved_databases:
            self.saved_db_var.set(f"📁 {', '.join(saved_databases)} (Şifreli)")
        else:
            self.saved_db_var.set("📁 Henüz kaydedilmiş veritabanı yok")
        
        ttk.Label(saved_frame, textvariable=self.saved_db_var, foreground="green", 
                 font=('Arial', 9)).pack(anchor=tk.W, pady=(5, 0))

    def create_backup_frame(self, parent):
        """Yedekleme frame'ini oluştur"""
        backup_frame = ttk.LabelFrame(parent, text="📂 Tarih Bazlı Yedekleme İşlemleri", padding="15")
        backup_frame.pack(fill=tk.X, pady=(0, 15))

        # Yedekleme dizini
        dir_frame = ttk.Frame(backup_frame)
        dir_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(dir_frame, text="Ana Yedekleme Dizini:").pack(anchor=tk.W)

        dir_input_frame = ttk.Frame(dir_frame)
        dir_input_frame.pack(fill=tk.X, pady=(5, 0))

        self.backup_dir_var = tk.StringVar(value=self.config["backup_dir"])
        ttk.Entry(dir_input_frame, textvariable=self.backup_dir_var, state="readonly").pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        ttk.Button(dir_input_frame, text="📁 Değiştir", command=self.select_backup_dir).pack(side=tk.RIGHT)

        # Tarih bilgisi
        today = datetime.now().strftime("%d.%m.%Y")
        info_frame = ttk.Frame(dir_frame)
        info_frame.pack(fill=tk.X, pady=(5, 0))
        
        ttk.Label(info_frame, text=f"📅 Bugünkü yedeklemeler: {self.backup_dir_var.get()}/{today}/", 
                 foreground="blue", font=('Arial', 9)).pack(anchor=tk.W)

        # Yedekleme butonları
        btn_frame = ttk.Frame(backup_frame)
        btn_frame.pack(fill=tk.X, pady=(15, 0))

        ttk.Button(btn_frame, text="🗄️ Tam Yedekleme", command=self.full_backup_thread, 
                  style="Accent.TButton").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_frame, text="📂 Seçili Koleksiyonlar", command=self.selective_backup_thread).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_frame, text="📁 Yedek Klasörünü Aç", command=self.open_backup_folder).pack(side=tk.RIGHT)

    def create_log_frame(self, parent):
        """Log frame'ini oluştur"""
        log_frame = ttk.LabelFrame(parent, text="📝 İşlem Kayıtları", padding="15")
        log_frame.pack(fill=tk.BOTH, expand=True)

        self.log_text = tk.Text(log_frame, height=15, wrap=tk.WORD, font=('Courier', 9))
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar_log = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        scrollbar_log.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=scrollbar_log.set)

        # Log butonları
        log_btn_frame = ttk.Frame(log_frame)
        log_btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(log_btn_frame, text="🗑️ Temizle", command=self.clear_log).pack(side=tk.LEFT)
        ttk.Button(log_btn_frame, text="💾 Kaydet", command=self.save_log).pack(side=tk.LEFT, padx=(10, 0))

    def log(self, message):
        """Log mesajı ekler"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()

    def clear_log(self):
        """Log'u temizle"""
        self.log_text.delete(1.0, tk.END)
        self.log("📝 Log temizlendi")

    def save_log(self):
        """Log'u dosyaya kaydet"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_file = os.path.join(get_base_path(), f"mongo_backup_log_{timestamp}.txt")
            
            with open(log_file, 'w', encoding='utf-8') as f:
                f.write(self.log_text.get(1.0, tk.END))
            
            self.log(f"💾 Log kaydedildi: {log_file}")
            messagebox.showinfo("Başarılı", f"Log dosyası kaydedildi:\n{log_file}")
        except Exception as e:
            self.log(f"❌ Log kaydetme hatası: {str(e)}")

    def refresh_preset_list(self):
        """Preset listesini yenile"""
        try:
            presets = self.ssh_preset_manager.load_presets()
            preset_names = list(presets.keys())
            
            # Widget mevcut mu kontrol et
            if hasattr(self, 'preset_combo') and self.preset_combo.winfo_exists():
                self.preset_combo['values'] = preset_names
                if preset_names:
                    self.log(f"📋 {len(preset_names)} kayıtlı bağlantı yüklendi: {', '.join(preset_names)}")
                else:
                    self.log("📋 Henüz kayıtlı bağlantı bulunamadı")
        except Exception as e:
            self.log(f"⚠️ Preset listesi yüklenirken hata: {str(e)}")

    def save_current_preset(self):
        """Mevcut ayarları preset olarak kaydet"""
        try:
            preset_name = self.preset_name_var.get().strip()
            if not preset_name:
                messagebox.showwarning("Uyarı", "Lütfen bağlantı için bir isim girin!")
                return
            
            # Mevcut değerleri kontrol et
            if not all([self.ssh_host_var.get(), self.ssh_user_var.get()]):
                messagebox.showwarning("Uyarı", "SSH Host ve Kullanıcı alanları dolu olmalı!")
                return
            
            # Port değerlerini kontrol et
            try:
                ssh_port = int(self.ssh_port_var.get())
                mongo_port = int(self.mongo_port_var.get())
            except ValueError:
                messagebox.showwarning("Uyarı", "Port değerleri sayı olmalı!")
                return
            
            # Aynı isimde preset var mı kontrol et
            existing_presets = self.ssh_preset_manager.load_presets()
            if preset_name in existing_presets:
                result = messagebox.askyesno("Onay", 
                    f"'{preset_name}' adında kayıt zaten var.\n\nÜzerine yazılsın mı?")
                if not result:
                    return
            
            # Preset kaydet (şifre hariç)
            success = self.ssh_preset_manager.save_preset(
                preset_name,
                self.ssh_host_var.get(),
                ssh_port,
                self.ssh_user_var.get(),
                self.mongo_host_var.get(),
                mongo_port
            )
            
            if success:
                self.preset_name_var.set("")  # İsim alanını temizle
                self.refresh_preset_list()  # Listeyi yenile
                self.preset_var.set(preset_name)  # Yeni kaydedileni seç
                messagebox.showinfo("Başarılı", 
                    f"✅ '{preset_name}' bağlantı ayarları kaydedildi!\n\n🔑 Güvenlik: Şifre kaydedilmedi, her seferinde girilmeli.")
            else:
                messagebox.showerror("Hata", "Bağlantı ayarları kaydedilemedi!")
                
        except Exception as e:
            self.log(f"❌ Preset kaydetme hatası: {str(e)}")
            messagebox.showerror("Hata", f"Preset kaydedilemedi: {str(e)}")

    def load_selected_preset(self, event=None):
        """Seçili preset'i yükle"""
        preset_name = self.preset_var.get()
        if not preset_name:
            return
        
        preset_data = self.ssh_preset_manager.get_preset(preset_name)
        if not preset_data:
            messagebox.showerror("Hata", f"'{preset_name}' preset'i bulunamadı!")
            return
        
        # Alanları doldur (şifre hariç)
        mongo_host = os.getenv('MONGODB_DEFAULT_HOST', 'localhost')
        mongo_port = int(os.getenv('MONGODB_DEFAULT_PORT', '27017'))
        
        self.ssh_host_var.set(preset_data.get("ssh_host", ""))
        self.ssh_port_var.set(str(preset_data.get("ssh_port", 22)))
        self.ssh_user_var.set(preset_data.get("ssh_username", ""))
        self.mongo_host_var.set(preset_data.get("mongo_host", mongo_host))
        self.mongo_port_var.set(str(preset_data.get("mongo_port", mongo_port)))
        
        # Şifre alanını temizle (güvenlik)
        self.ssh_pass_var.set("")
        
        created_date = preset_data.get("created_date", "")
        if created_date:
            try:
                date_obj = datetime.fromisoformat(created_date)
                date_str = date_obj.strftime("%d.%m.%Y %H:%M")
            except:
                date_str = "Bilinmiyor"
        else:
            date_str = "Bilinmiyor"
        
        self.log(f"📥 '{preset_name}' bağlantı ayarları yüklendi (Kayıt: {date_str})")
        self.log("🔑 Güvenlik: Lütfen SSH şifresini girin")

    def delete_selected_preset(self):
        """Seçili preset'i sil"""
        preset_name = self.preset_var.get()
        if not preset_name:
            messagebox.showwarning("Uyarı", "Lütfen silinecek bağlantıyı seçin!")
            return
        
        result = messagebox.askyesno("Onay", 
            f"'{preset_name}' bağlantı ayarları silinecek.\n\nEmin misiniz?")
        
        if result:
            if self.ssh_preset_manager.delete_preset(preset_name):
                self.preset_var.set("")  # Seçimi temizle
                self.refresh_preset_list()  # Listeyi yenile
                messagebox.showinfo("Başarılı", f"✅ '{preset_name}' bağlantı ayarları silindi!")
            else:
                messagebox.showerror("Hata", "Bağlantı ayarları silinemedi!")

    def select_backup_dir(self):
        """Yedekleme dizinini seç"""
        dir_path = filedialog.askdirectory(title="Ana Yedekleme Dizini Seç")
        if dir_path:
            self.config["backup_dir"] = dir_path
            self.backup_dir_var.set(dir_path)
            self.config_manager.save_config(self.config)
            self.log(f"📁 Ana yedekleme dizini güncellendi: {dir_path}")
            
            # Tarih bilgisini güncelle
            today = datetime.now().strftime("%d.%m.%Y")
            messagebox.showinfo("Dizin Güncellendi", f"Yedekleme dizini güncellendi.\n\nBugünkü yedeklemeler şu klasöre kaydedilecek:\n{dir_path}/{today}/")

    def open_backup_folder(self):
        """Yedek klasörünü aç"""
        try:
            backup_dir = self.backup_dir_var.get()
            if os.path.exists(backup_dir):
                if sys.platform == 'win32':
                    os.startfile(backup_dir)
                elif sys.platform == 'darwin':
                    os.system(f'open "{backup_dir}"')
                else:
                    os.system(f'xdg-open "{backup_dir}"')
                self.log(f"📁 Yedek klasörü açıldı: {backup_dir}")
            else:
                messagebox.showerror("Hata", f"Yedek klasörü bulunamadı:\n{backup_dir}")
        except Exception as e:
            self.log(f"❌ Klasör açma hatası: {str(e)}")

    def save_selected_databases(self):
        """Seçili veritabanlarını şifreli olarak kaydet"""
        selected_dbs = self.get_selected_databases()
        if not selected_dbs:
            messagebox.showwarning("Uyarı", "Lütfen kaydetmek istediğiniz veritabanlarını seçin!")
            return
        
        # SSH bilgilerini de kaydet
        ssh_info = {
            "ssh_host": self.ssh_host_var.get(),
            "ssh_port": int(self.ssh_port_var.get()),
            "ssh_username": self.ssh_user_var.get(),
            "ssh_password": self.ssh_pass_var.get(),
            "mongo_host": self.mongo_host_var.get(),
            "mongo_port": int(self.mongo_port_var.get())
        }
        
        if self.db_save_manager.save_databases(selected_dbs, ssh_info):
            self.saved_db_var.set(f"📁 {', '.join(selected_dbs)} (Şifreli)")
            messagebox.showinfo("Güvenli Kaydetme", f"✅ {len(selected_dbs)} veritabanı güvenli olarak kaydedildi!\n\nKaydedilen veritabanları:\n• " + "\n• ".join(selected_dbs) + "\n\n🔒 SSH bilgileri şifreli olarak saklandı.\n💾 Bir sonraki açılışta otomatik yüklenecek.")
        else:
            messagebox.showerror("Hata", "Veritabanları kaydedilemedi!")

    def connect_ssh_thread(self):
        """SSH bağlantısını thread'de çalıştır"""
        def ssh_worker():
            self.connect_ssh()

        thread = threading.Thread(target=ssh_worker)
        thread.daemon = True
        thread.start()

    def connect_ssh(self):
        """SSH bağlantısı kur"""
        if not all([self.ssh_host_var.get(), self.ssh_user_var.get(), self.ssh_pass_var.get()]):
            messagebox.showerror("Hata", "SSH bilgileri eksik!")
            return

        self.status_var.set("🔄 Güvenli SSH bağlantısı kuruluyor...")

        success, result = self.connection_manager.connect_ssh(
            self.ssh_host_var.get(),
            int(self.ssh_port_var.get()),
            self.ssh_user_var.get(),
            self.ssh_pass_var.get(),
            self.mongo_host_var.get(),
            int(self.mongo_port_var.get())
        )

        if success:
            self.status_var.set("🟡 SSH bağlı - MongoDB bekleniyor")
        else:
            self.status_var.set("🔴 SSH bağlantı hatası")
            messagebox.showerror("SSH Hatası", f"Güvenli bağlantı kurulamadı:\n{result}")

    def connect_mongo_thread(self):
        """MongoDB bağlantısını thread'de çalıştır"""
        def mongo_worker():
            self.connect_mongo()

        thread = threading.Thread(target=mongo_worker)
        thread.daemon = True
        thread.start()

    def connect_mongo(self):
        """MongoDB bağlantısını test et"""
        if not self.connection_manager.ssh_tunnel:
            messagebox.showerror("Hata", "Önce SSH bağlantısı kurmalısınız!")
            return

        self.status_var.set("🔄 MongoDB güvenli bağlantısı test ediliyor...")

        success, result = self.connection_manager.connect_mongo()

        if success:
            self.status_var.set("🟢 Güvenli bağlantı başarılı")
            self.update_database_list(result)
            self.backup_manager = BackupManager(
                self.connection_manager.mongo_uri,
                self.backup_dir_var.get(),
                logger=self.log
            )
            self.save_db_btn.config(state=tk.NORMAL)
        else:
            self.status_var.set("🔴 MongoDB bağlantı hatası")
            messagebox.showerror("Hata", f"MongoDB güvenli bağlantı hatası:\n{result}")

    def update_database_list(self, databases):
        """Veritabanı listesini güncelle"""
        self.db_listbox.delete(0, tk.END)
        for db in databases:
            self.db_listbox.insert(tk.END, db)

        # Kaydedilmiş veritabanlarını otomatik seç
        saved_databases = self.db_save_manager.load_saved_databases()
        for db in saved_databases:
            if db in databases:
                idx = databases.index(db)
                self.db_listbox.selection_set(idx)
        
        if saved_databases:
            self.log(f"📋 Kaydedilmiş veritabanları otomatik seçildi: {', '.join(saved_databases)}")

    def disconnect(self):
        """Tüm bağlantıları kes"""
        self.connection_manager.disconnect()
        self.db_listbox.delete(0, tk.END)
        self.db_listbox.insert(tk.END, "MongoDB'ye güvenli bağlantı kurun...")
        self.status_var.set("🔴 Güvenli bağlantılar kapatıldı")
        self.backup_manager = None
        self.save_db_btn.config(state=tk.DISABLED)

    def get_selected_databases(self):
        """Seçili veritabanlarını döndür"""
        selected_indices = self.db_listbox.curselection()
        selected_dbs = [self.db_listbox.get(i) for i in selected_indices]
        return selected_dbs

    def full_backup_thread(self):
        """Tam yedeklemeyi thread'de çalıştır"""
        def backup_worker():
            self.full_backup()

        thread = threading.Thread(target=backup_worker)
        thread.daemon = True
        thread.start()

    def full_backup(self):
        """Tam veritabanı yedeklemesi - Tarih bazlı"""
        if not self.connection_manager.is_connected or not self.backup_manager:
            messagebox.showerror("Hata", "Önce MongoDB'ye güvenli bağlantı kurmalısınız!")
            return

        selected_dbs = self.get_selected_databases()
        if not selected_dbs:
            messagebox.showerror("Hata", "Lütfen yedeklenecek en az bir veritabanı seçin!")
            return

        # SSH bilgilerini config'e kaydet
        ssh_info = {
            "ssh_host": self.ssh_host_var.get(),
            "ssh_port": int(self.ssh_port_var.get()),
            "ssh_username": self.ssh_user_var.get(),
            "ssh_password": self.ssh_pass_var.get(),
            "mongo_host": self.mongo_host_var.get(),
            "mongo_port": int(self.mongo_port_var.get())
        }
        self.config.update(ssh_info)
        self.config_manager.save_config(self.config)

        backup_dir = self.backup_dir_var.get()
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)

        self.backup_manager.backup_dir = backup_dir

        success_count = 0
        today = datetime.now().strftime("%d.%m.%Y")
        
        self.log(f"🚀 Tam yedekleme başlatıldı - Hedef: {backup_dir}/{today}/")
        
        for db_name in selected_dbs:
            # Çevre değişkeninden local bind host'u al
            local_bind_host = os.getenv('SSH_LOCAL_BIND_ADDRESS', 'localhost')
            self.backup_manager.mongo_uri = f"mongodb://{local_bind_host}:{self.connection_manager.ssh_tunnel.local_bind_port}/{db_name}"
            output_dir, success = self.backup_manager.backup_database(db_name)
            if success:
                success_count += 1

        if success_count == len(selected_dbs):
            messagebox.showinfo("Yedekleme Başarılı", 
                              f"✅ Tüm veritabanları başarıyla yedeklendi!\n\n📁 Konum: {backup_dir}/{today}/\n📊 {success_count}/{len(selected_dbs)} veritabanı\n🔒 Güvenli tarih bazlı sistem\n\nYedeklenen veritabanları:\n• " + "\n• ".join(selected_dbs))
        else:
            messagebox.showwarning("Kısmi Yedekleme", 
                                 f"⚠️ Kısmi yedekleme tamamlandı!\n\n📁 Konum: {backup_dir}/{today}/\n📊 {success_count}/{len(selected_dbs)} veritabanı başarılı\n\nLütfen log kayıtlarını kontrol edin.")

    def selective_backup_thread(self):
        """Seçili koleksiyon yedeklemesini thread'de başlat"""
        def backup_worker():
            self.selective_backup()

        thread = threading.Thread(target=backup_worker)
        thread.daemon = True
        thread.start()

    def selective_backup(self):
        """Seçili koleksiyonları yedekle"""
        if not self.connection_manager.is_connected:
            messagebox.showerror("Hata", "Önce MongoDB'ye güvenli bağlantı kurmalısınız!")
            return

        selected_dbs = self.get_selected_databases()
        if not selected_dbs:
            messagebox.showerror("Hata", "Lütfen en az bir veritabanı seçin!")
            return

        for db_name in selected_dbs:
            collections = self.connection_manager.get_collections(db_name)
            if not collections:
                self.log(f"❌ {db_name} veritabanında koleksiyon bulunamadı")
                continue

            self.show_collection_selector(db_name, collections)

    def show_collection_selector(self, db_name, collections):
        """Koleksiyon seçici penceresi göster"""
        select_win = tk.Toplevel(self.root)
        select_win.title(f"📂 {db_name} - Koleksiyon Seçimi")
        select_win.geometry("520x650")
        select_win.resizable(True, True)

        # Ana frame
        main_frame = ttk.Frame(select_win, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Başlık
        title_label = ttk.Label(main_frame, text=f"📂 {db_name} Veritabanı",
                                font=('Arial', 14, 'bold'))
        title_label.pack(pady=(0, 10))

        info_label = ttk.Label(main_frame, text="Yedeklenecek koleksiyonları seçin:", 
                              font=('Arial', 10))
        info_label.pack(pady=(0, 10))

        # Tarih bilgisi
        today = datetime.now().strftime("%d.%m.%Y")
        date_label = ttk.Label(main_frame, text=f"📅 Hedef klasör: damise_backups/{today}/", 
                              foreground="blue", font=('Arial', 9))
        date_label.pack(pady=(0, 15))

        # Listbox frame
        listbox_frame = ttk.Frame(main_frame)
        listbox_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))

        listbox = tk.Listbox(listbox_frame, selectmode=tk.MULTIPLE)
        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(listbox_frame, command=listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        listbox.config(yscrollcommand=scrollbar.set)

        # Koleksiyonları listele
        for col in collections:
            listbox.insert(tk.END, col)

        # Seçim butonları
        selection_frame = ttk.Frame(main_frame)
        selection_frame.pack(fill=tk.X, pady=(0, 15))

        def select_all():
            listbox.select_set(0, tk.END)

        def deselect_all():
            listbox.selection_clear(0, tk.END)

        ttk.Button(selection_frame, text="✅ Tümünü Seç", command=select_all).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(selection_frame, text="❌ Seçimi Temizle", command=deselect_all).pack(side=tk.LEFT)

        # Info frame
        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill=tk.X, pady=(0, 15))

        count_label = ttk.Label(info_frame, text=f"📊 Toplam {len(collections)} koleksiyon mevcut")
        count_label.pack()

        # Ana butonlar
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)

        def backup_selected():
            selected_cols = [listbox.get(i) for i in listbox.curselection()]
            if not selected_cols:
                messagebox.showerror("Hata", "En az bir koleksiyon seçmelisiniz!")
                return

            backup_dir = self.backup_dir_var.get()
            if not backup_dir or not os.path.exists(backup_dir):
                messagebox.showerror("Hata", "Geçerli bir yedekleme dizini belirtmelisiniz!")
                return

            select_win.destroy()
            self.backup_selected_collections(db_name, selected_cols)

        def cancel_backup():
            select_win.destroy()

        ttk.Button(button_frame, text="💾 Yedeklemeyi Başlat", command=backup_selected, 
                  style="Accent.TButton").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="❌ İptal", command=cancel_backup).pack(side=tk.LEFT)

        # Pencereyi ortalama ve modal yap
        select_win.transient(self.root)
        select_win.grab_set()
        select_win.geometry("+%d+%d" % (
            self.root.winfo_rootx() + 100,
            self.root.winfo_rooty() + 100
        ))

    def backup_selected_collections(self, db_name, collections):
        """Seçili koleksiyonları yedekle"""
        if not self.backup_manager:
            return

        # Çevre değişkeninden local bind host'u al
        local_bind_host = os.getenv('SSH_LOCAL_BIND_ADDRESS', 'localhost')
        self.backup_manager.mongo_uri = f"mongodb://{local_bind_host}:{self.connection_manager.ssh_tunnel.local_bind_port}/{db_name}"
        self.backup_manager.backup_dir = self.backup_dir_var.get()

        today = datetime.now().strftime("%d.%m.%Y")
        self.log(f"🚀 Seçili koleksiyon yedeklemesi başlatıldı - {db_name}")
        self.log(f"📂 Hedef: {self.backup_dir_var.get()}/{today}/")

        output_dir, success = self.backup_manager.backup_selected_collections(db_name, collections)

        if success:
            messagebox.showinfo("Yedekleme Başarılı", 
                              f"✅ Seçili koleksiyonlar başarıyla yedeklendi!\n\n📁 Konum: {output_dir}\n📊 {len(collections)} koleksiyon\n🔒 Güvenli tarih bazlı sistem\n\nYedeklenen koleksiyonlar:\n• " + "\n• ".join(collections))
        else:
            messagebox.showwarning("Kısmi Yedekleme", 
                                 f"⚠️ Bazı koleksiyonlar yedeklenemedi!\n\n📁 Konum: {output_dir}\n\nLütfen log kayıtlarını kontrol edin.")

    def on_closing(self):
        """Pencere kapatılırken güvenli temizleme"""
        if messagebox.askokcancel("Modül Kapatma", "MongoDB Yedekleme modülünü kapatmak istiyor musunuz?\n\nTüm bağlantılar güvenli olarak kesilecektir."):
            self.log("🔒 MongoDB modülü güvenli olarak kapatılıyor...")
            
            # Bağlantıları kapat
            self.connection_manager.disconnect()
            self.log("✅ Tüm bağlantılar güvenli olarak kesildi")

            # Callback'i çağır
            if self.on_close_callback:
                self.on_close_callback()

            self.root.destroy()


if __name__ == "__main__":
    messagebox.showerror("Modül Hatası", 
                        "Bu modül bağımsız olarak çalıştırılamaz!\n\nLütfen DamiseAuthGUI.py dosyasını çalıştırın ve admin girişi yaparak MongoDB panelini açın.")
    sys.exit(1)