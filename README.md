# Damise MongoDB Yedekleme Sistemi

MongoDB veritabanlarının güvenli bir şekilde SSH tüneli üzerinden yedeklenmesi için geliştirilmiş profesyonel masaüstü uygulaması.

## Proje Açıklaması

Bu proje, MongoDB veritabanlarının güvenli bir şekilde yedeklenmesi için geliştirilmiş çift katmanlı bir güvenlik sistemidir. Admin kimlik doğrulama modülü (DamiseAuthGUI) ve MongoDB yedekleme modülü (MongoBackupGUI) olmak üzere iki ana bileşenden oluşmaktadır.

### Temel Özellikler

- **Güvenli Admin Kimlik Doğrulama**: API tabanlı kullanıcı yetkilendirme sistemi
- **SSH Tünel Desteği**: Güvenli uzak sunucu bağlantıları
- **Şifreli Yapılandırma**: Hassas bilgilerin güvenli depolanması
- **Tarih Bazlı Yedekleme**: Otomatik klasör organizasyonu
- **Koleksiyon Seçimi**: Esnek veritabanı ve koleksiyon yedekleme seçenekleri
- **SSH Preset Yönetimi**: Sık kullanılan bağlantıların kaydedilmesi
- **Detaylı Loglama**: Tüm işlemlerin kayıt altına alınması

## Sistem Gereksinimleri

### Yazılım Gereksinimleri

- **Python**: 3.8 veya üzeri
- **İşletim Sistemi**: Windows, macOS, Linux
- **GUI**: tkinter (Python ile birlikte gelir)

### Gerekli Python Paketleri

```
requests>=2.28.0
sshtunnel>=0.4.0
cryptography>=3.4.8
pymongo>=4.0.0
python-dotenv>=0.19.0
```

## Kurulum

### 1. Python Bağımlılıklarının Kurulumu

```bash
pip install -r requirements.txt
```

veya

```bash
pip install requests sshtunnel cryptography pymongo python-dotenv
```

### 2. Proje Dosyalarının İndirilmesi

```bash
git clone https://github.com/ttodeswalzer/MongoDBbackup.git
cd MongoDBbackup
```

### 3. Çevre Değişkenlerinin Yapılandırılması

Proje çevre değişkenleri kullanarak yapılandırılır. Önce örnek dosyayı kopyalayın:

```bash
cp .env.example .env
```

`.env` dosyasını düzenleyerek kendi değerlerinizi girin:

```bash
# API Yapılandırması
API_BASE_URL=https://your-api-domain.com
LOGIN_ENDPOINT=/users/login

# MongoDB Bağlantı Ayarları
MONGODB_DEFAULT_HOST=localhost
MONGODB_DEFAULT_PORT=27017

# SSH Tünel Ayarları
SSH_LOCAL_BIND_ADDRESS=your-ssh-ip
SSH_DEFAULT_PORT=22

# Uygulama Ayarları
APP_TITLE=Your App Title
APP_VERSION=2.0
```

## Kullanım

### 1. Uygulamanın Başlatılması

```bash
python DamiseAuthGUI.py
```

### 2. Admin Kimlik Doğrulama

- API sistemi üzerinden admin kimlik bilgilerinizi girin
- "Beni hatırla" seçeneği ile güvenli oturum yönetimi
- İnternet bağlantısı durumu otomatik olarak kontrol edilir

### 3. MongoDB Yedekleme Aracına Erişim

Başarılı admin girişi sonrasında MongoDB yedekleme aracı otomatik olarak açılır.

### 4. SSH Bağlantı Kurulumu

- **SSH Sunucu Bilgileri**: Host, port, kullanıcı adı ve şifre
- **MongoDB Bilgileri**: Sunucu adresi ve port bilgisi
- **Preset Yönetimi**: Sık kullanılan bağlantıları kaydetme ve yükleme

### 5. Yedekleme İşlemleri

- **Veritabanı Listesi**: Bağlantı sonrası otomatik veritabanı keşfi
- **Koleksiyon Seçimi**: İsteğe bağlı koleksiyon bazlı yedekleme
- **Tarih Bazlı Organizasyon**: Yedekler otomatik olarak tarih klasörlerine organize edilir

## Dosya Yapısı

```
MongoDBbackup/
├── DamiseAuthGUI.py          # Ana kimlik doğrulama modülü
├── MongoBackupGUI.py         # MongoDB yedekleme modülü
├── requirements.txt          # Python bağımlılıkları
├── .env.example             # Çevre değişkenleri örnek dosyası
├── .gitignore               # Git yok sayma kuralları
└── README.md                # Bu dokümantasyon dosyası
```

### Yapılandırma Dosyaları

```
├── .env                     # Çevre değişkenleri (kullanıcı tarafından oluşturulan)
├── damise_config.json       # Şifreli yapılandırma dosyası
├── damise_config.key        # Şifreleme anahtarı
├── damise_credentials.json  # Kaydedilmiş kimlik bilgileri
├── damise_token.json        # API oturum token'ı
└── damise_backups/          # Yedek dosyalarının depolandığı klasör
    └── dd.mm.yyyy/          # Tarih bazlı alt klasörler
```

## Güvenlik Özellikleri

### Veri Şifreleme

- **Yapılandırma Dosyaları**: Fernet simetrik şifreleme
- **SSH Şifreleri**: Güvenli depolama ve otomatik çözme
- **Token Yönetimi**: Otomatik token yenileme ve güvenli saklama

### Kimlik Doğrulama

- **API Tabanlı Yetkilendirme**: Damise ekosistem API entegrasyonu
- **Admin Seviye Kontrol**: Sadece yetkili kullanıcılar erişebilir
- **Oturum Yönetimi**: Güvenli oturum açma/kapatma

### Bağlantı Güvenliği

- **SSH Tünelleme**: Tüm MongoDB bağlantıları SSH üzerinden
- **Bağlantı Timeout**: Otomatik bağlantı zaman aşımı koruması
- **Hata Yönetimi**: Güvenli hata mesajları ve loglama

## Yedekleme Sistemi

### Dosya Formatı

- **JSON Format**: Tüm veriler JSON formatında yedeklenir
- **BSON Uyumluluğu**: MongoDB BSON tiplerinin korunması
- **UTF-8 Kodlama**: Türkçe karakter desteği

### Organizasyon Yapısı

```
damise_backups/
├── 15.01.2025/              # Günlük klasör
│   ├── database1.json       # Tek koleksiyonlu veritabanı
│   └── database2_143052/    # Çoklu koleksiyonlu veritabanı
│       ├── collection1.json
│       └── collection2.json
└── 16.01.2025/              # Diğer günler
```

### Yedekleme Türleri

1. **Tam Veritabanı Yedekleme**: Tüm koleksiyonları içerir
2. **Seçili Koleksiyon Yedekleme**: Belirli koleksiyonları yedekler
3. **Tek Koleksiyon Yedekleme**: Tekil koleksiyon dosyası

## Çevre Değişkenleri

Uygulama `.env` dosyası kullanarak yapılandırılır. Kullanılabilir tüm çevre değişkenleri:

### API Yapılandırması

### MongoDB Ayarları
- `MONGODB_DEFAULT_HOST`: Varsayılan MongoDB host (varsayılan: localhost)
- `MONGODB_DEFAULT_PORT`: Varsayılan MongoDB port (varsayılan: 27017)
- `MONGODB_CONNECTION_TIMEOUT`: Bağlantı timeout (ms) (varsayılan: 10000)

### SSH Tünel Ayarları
- `
- `SSH_DEFAULT_PORT`: Varsayılan SSH port (varsayılan: 22)
- `SSH_LOCAL_BIND_ADDRESS`: Local bind adresi (varsayılan: localhost)
- `SSH_CONNECTION_TIMEOUT`: SSH timeout (s) (varsayılan: 30)

### Dosya Yolları
- `CONFIG_FILE_NAME`: Config dosya adı (varsayılan: damise_config.json)
- `CREDENTIALS_FILE_NAME`: Kimlik bilgileri dosya adı (varsayılan: damise_credentials.json)
- `TOKEN_FILE_NAME`: Token dosya adı (varsayılan: damise_token.json)
- `BACKUP_DIR_NAME`: Yedek klasör adı (varsayılan: damise_backups)

### Uygulama Ayarları
- `APP_TITLE`: Ana uygulama başlığı
- `APP_VERSION`: Uygulama versiyonu (varsayılan: 2.0)
- `BACKUP_APP_TITLE`: Yedekleme aracı başlığı
- `WINDOW_DEFAULT_WIDTH`: Varsayılan pencere genişliği (varsayılan: 800)
- `WINDOW_DEFAULT_HEIGHT`: Varsayılan pencere yüksekliği (varsayılan: 700)
- `BACKUP_WINDOW_WIDTH`: Yedekleme pencere genişliği (varsayılan: 1000)
- `BACKUP_WINDOW_HEIGHT`: Yedekleme pencere yüksekliği (varsayılan: 900)

### Log Dosyaları

Uygulama detaylı log dosyaları oluşturur:
- `damise_auth_log_YYYYMMDD_HHMMSS.txt`
- `mongo_backup_log_YYYYMMDD_HHMMSS.txt`

## Geliştirici Bilgileri

### Mimari Yapı

```
DamiseAuthGUI (Ana Modül)
├── Kimlik Doğrulama
├── Token Yönetimi
├── Yapılandırma Yönetimi
└── MongoBackupGUI (Alt Modül)
    ├── SSH Bağlantı Yönetimi
    ├── MongoDB İşlemleri
    ├── Yedekleme Sistemi
    └── Preset Yönetimi
```

### Sınıf Yapısı

- **DamiseAuthGUI**: Ana kimlik doğrulama sınıfı
- **MongoBackupGUI**: MongoDB yedekleme ana sınıfı
- **ConfigManager**: Güvenli yapılandırma yönetimi
- **SSHPresetManager**: SSH bağlantı önayarları
- **BackupManager**: Yedekleme işlemleri
- **ConnectionManager**: Bağlantı yönetimi
- **DatabaseSaveManager**: Veritabanı kaydetme/yükleme

### API Entegrasyonu

Damise ekosistem API'si kullanılarak kimlik doğrulama yapılır:
- Base URL: `.env` dosyasında `API_BASE_URL` ile yapılandırılır
- Endpoint: `.env` dosyasında `LOGIN_ENDPOINT` ile yapılandırılır
- Yetkilendirme: Bearer Token

