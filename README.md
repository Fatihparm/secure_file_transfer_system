# Secure File Transfer System

Bu proje, dosyaları ağ üzerinden güvenli bir şekilde transfer etmek için geliştirilmiş bir Python tabanlı sistemdir. Amacı, dosyaları şifreleyerek korumak ve ağ performansını izlemektir. Hem bireysel hem de eğitim amaçlı kullanılabilir!

## Ne Yapar?

* Dosyaları RSA ve AES şifreleme ile güvenli bir şekilde gönderir ve alır.
* Kullanıcı kimlik doğrulamasını destekler, böylece yalnızca yetkili kişiler erişebilir.
* Ağın hızını (bant genişliği) ve gecikmesini (RTT) ölçer.
* Man-in-the-Middle (MITM) saldırılarını simüle ederek güvenliği test eder.
* Paket kaybı gibi ağ sorunlarını taklit ederek sistemin dayanıklılığını kontrol eder.

## Özellikler

* Güçlü şifreleme ile veri gizliliği.
* Performans izleme araçları (RTT, bant genişliği).
* MITM simülasyonu ile güvenlik testi.
* Paket kaybı simülasyonu.

## Gereksinimler

Projenin çalışması için aşağıdaki bağımlılıkları yüklemen gerekiyor:

* Python 3.7 veya üstü
* `cryptography` (şifreleme için)
* `scapy` (ağ paketleri için)

Windows kullanıyorsan, Scapy için Npcap kurulu olmalı.

Bağımlılıkları yüklemek için:

```bash
pip install -r requirements.txt
```

`requirements.txt` dosyasını projeye eklemeyi unutma:

```
cryptography
scapy
```

## Nasıl Çalıştırılır?

### 1. Projeyi İndir veya Klonla

GitHub'dan projeyi bilgisayarına indir:

```bash
git clone https://github.com/Fatihparm/secure_file_transfer_system.git
cd secure_file_transfer_system
```

### 2. Sunucuyu Başlat

Bir terminalde sunucuyu çalıştır:

```bash
python secure_file_transfer.py server
```

Ekranında "Sunucu dinliyor" mesajını görmelisin.

### 3. İstemciyi Çalıştır

Ayrı bir terminalde istemciyi çalıştır ve transfer etmek istediğin dosyanın yolunu belirt:

```bash
python secure_file_transfer.py client test1.txt
```

(Önce `test1.txt` gibi bir test dosyası oluşturabilirsin: `echo "Test" > test1.txt`)

### 4. MITM Testi (Opsiyonel)

MITM simülasyonunu denemek için:

```bash
python secure_file_transfer.py mitm
```

## Notlar

* Sunucu çalışmadan istemciyi çalıştırma, aksi halde bağlantı hatası alırsın.
* Windows'ta terminali yönetici olarak çalıştırman gerekebilir.
* Daha fazla bilgi için Final Report dosyasını oku.

## Katkıda Bulunma

Sorularını veya önerilerini paylaşmak istersen, GitHub Issues bölümüne yazabilirsin!
