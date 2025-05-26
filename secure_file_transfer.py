import scapy.all as scapy
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import os
import socket
import struct
import time
import random

# RSA anahtar çifti oluşturma
def generate_rsa_keys():
    print("RSA anahtar çifti oluşturuluyor...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# AES şifreleme için anahtar oluşturma
def generate_key():
    print("AES anahtar oluşturuluyor...")
    return Fernet.generate_key()

# Dosyayı şifreleme
def encrypt_file(file_path, key):
    print(f"Dosya şifreleniyor: {file_path}")
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        data = file.read()
    encrypted_data = fernet.encrypt(data)
    print(f"Şifreli veri boyutu: {len(encrypted_data)} bayt")
    return encrypted_data

# Dosyayı çözme
def decrypt_file(encrypted_data, key, output_path):
    print(f"Şifreli veri çözülüyor, çıktı: {output_path}")
    fernet = Fernet(key)
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
        with open(output_path, 'wb') as file:
            file.write(decrypted_data)
        print(f"Dosya başarıyla çözüldü: {output_path}")
    except Exception as e:
        print(f"Şifre çözme hatası: {e}")
        raise

# SHA-256 ile dosya bütünlüğünü kontrol etme
def calculate_hash(file_path):
    print(f"Hash hesaplanıyor: {file_path}")
    sha256 = hashes.Hash(hashes.SHA256())
    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256.update(chunk)
    return sha256.finalize()

# Dosyayı parçalara ayırma
def fragment_file(file_data, chunk_size=1024):
    fragments = [file_data[i:i + chunk_size] for i in range(0, len(file_data), chunk_size)]
    print(f"Dosya {len(fragments)} parçaya ayrıldı")
    return fragments

# RTT ölçümü
def measure_rtt(dst_ip, count=5):
    print(f"RTT ölçülüyor: {dst_ip}")
    rtt_list = []
    for _ in range(count):
        start_time = time.time()
        pkt = scapy.IP(dst=dst_ip)/scapy.ICMP()
        ans = scapy.sr1(pkt, timeout=2, verbose=False)
        if ans:
            rtt = (time.time() - start_time) * 1000  # ms cinsinden
            rtt_list.append(rtt)
    avg_rtt = sum(rtt_list) / len(rtt_list) if rtt_list else 0
    print(f"Ortalama RTT: {avg_rtt:.2f} ms")
    return avg_rtt

# IP paketi gönderme (paket kaybı simülasyonu ile)
def send_packet(data, src_ip, dst_ip, seq_num, frag_offset=0, ttl=64, id=1, packet_loss_prob=0.0):
    print(f"IP paketi gönderiliyor: seq={seq_num}, offset={frag_offset}")
    if random.random() < packet_loss_prob:
        print(f"Paket düşürüldü (simülasyon): seq={seq_num}")
        return False
    ip_packet = scapy.IP(src=src_ip, dst=dst_ip, ttl=ttl, id=id)
    ip_packet.flags = 'MF' if frag_offset > 0 else 0
    ip_packet.frag = frag_offset // 8
    payload = struct.pack('!I', seq_num) + data
    try:
        scapy.send(ip_packet / scapy.Raw(load=payload), verbose=False)
        print(f"Paket gönderildi: seq={seq_num}")
        return True
    except Exception as e:
        print(f"Paket gönderme hatası: {e}")
        return False

# Kimlik doğrulama
def authenticate_client(conn):
    try:
        credentials = conn.recv(1024).decode()
        username, password = credentials.split(':')
        valid_credentials = {'user1': 'password123', 'user2': 'securepass456'}
        if valid_credentials.get(username) == password:
            conn.send(b'AUTH_OK')
            print(f"Kimlik doğrulama başarılı: {username}")
            return True
        else:
            conn.send(b'AUTH_FAIL')
            print(f"Kimlik doğrulama başarısız: {username}")
            return False
    except Exception as e:
        print(f"Kimlik doğrulama hatası: {e}")
        conn.send(b'AUTH_FAIL')
        return False

# MITM simülasyonu
def mitm_test(host='127.0.0.1', port=12345):
    print("MITM testi başlatılıyor...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
        print(f"Sunucuya bağlanıldı (MITM): {host}:{port}")
    except Exception as e:
        print(f"MITM bağlantı hatası: {e}")
        return
    
    # Yanlış kimlik bilgileriyle doğrulama denemesi
    try:
        s.send("hacker:wrongpass".encode())
        auth_response = s.recv(1024)
        if auth_response == b'AUTH_OK':
            print("MITM: Kimlik doğrulama beklenmedik şekilde başarılı!")
        else:
            print("MITM: Kimlik doğrulama başarısız (beklenen davranış)")
    except Exception as e:
        print(f"MITM kimlik doğrulama hatası: {e}")
    
    # Sahte RSA anahtarı alma denemesi
    try:
        fake_public_key_pem = s.recv(4096)
        print("MITM: Sahte RSA anahtarı alındı")
        # Sahte bir AES anahtarı gönder
        fake_key = Fernet.generate_key()
        fake_public_key = serialization.load_pem_public_key(fake_public_key_pem)
        encrypted_fake_key = fake_public_key.encrypt(
            fake_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        s.send(encrypted_fake_key)
        print("MITM: Sahte AES anahtarı gönderildi")
    except Exception as e:
        print(f"MITM sahte anahtar hatası: {e}")
    
    s.close()
    print("MITM testi tamamlandı")

# Sunucu tarafı
def server(host='127.0.0.1', port=12345):
    private_key, public_key = generate_rsa_keys()
    key = generate_key()
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(1)
    print(f"Sunucu dinliyor: {host}:{port}")
    
    conn, addr = s.accept()
    print(f"İstemci bağlandı: {addr}")
    
    # Kimlik doğrulama
    if not authenticate_client(conn):
        conn.close()
        s.close()
        print("Kimlik doğrulama başarısız, bağlantı kapatılıyor")
        return
    
    # RSA genel anahtarını istemciye gönder
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    conn.send(public_key_pem)
    print(f"RSA genel anahtarı gönderildi, boyutu: {len(public_key_pem)} bayt")
    
    # Şifreli AES anahtarını al
    try:
        encrypted_key = conn.recv(4096)
        print(f"Şifreli AES anahtarı alındı, boyutu: {len(encrypted_key)} bayt")
        key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("AES anahtarı alındı ve çözüldü")
    except Exception as e:
        print(f"AES anahtar çözme hatası: {e}")
        conn.close()
        s.close()
        return
    
    # Parçaları al ve birleştir
    fragments = {}
    total_fragments = None
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                print("Veri alımı tamamlandı")
                break
            seq_num = struct.unpack('!I', data[:4])[0]
            print(f"Parça alındı: seq={seq_num}")
            if seq_num == 0:
                total_fragments = struct.unpack('!I', data[4:8])[0]
                fragments[seq_num] = data[8:]
                print(f"Toplam parça sayısı: {total_fragments}")
            else:
                fragments[seq_num] = data[4:]
            
            conn.send(struct.pack('!I', seq_num))
            print(f"Onay gönderildi: seq={seq_num}")
            
            if total_fragments and len(fragments) == total_fragments:
                print("Tüm parçalar alındı, döngüden çıkılıyor")
                break
    except Exception as e:
        print(f"Veri alma hatası: {e}")
    
    # Eksik parçaları kontrol et
    missing = [i for i in range(total_fragments or 0) if i not in fragments]
    try:
        if missing:
            print(f"Eksik parçalar: {missing}")
            conn.send(struct.pack('!I', len(missing)) + b''.join(struct.pack('!I', i) for i in missing))
        else:
            print("Tüm parçalar alındı")
            conn.send(struct.pack('!I', 0))
    except Exception as e:
        print(f"Eksik parça bildirimi hatası: {e}")
    
    # Parçaları birleştir
    received_data = b""
    for i in sorted(fragments.keys()):
        received_data += fragments[i]
    print(f"Birleştirilen veri boyutu: {len(received_data)} bayt")
    
    # Şifreli dosyayı kaydet ve çöz
    try:
        with open('received_encrypted.bin', 'wb') as f:
            f.write(received_data)
        decrypt_file(received_data, key, 'received_file.txt')
        
        # Bütünlük kontrolü
        received_hash = calculate_hash('received_file.txt')
        print(f"Alınan dosya hash: {received_hash.hex()}")
    except Exception as e:
        print(f"Dosya işleme hatası: {e}")
    
    conn.close()
    s.close()
    print("Sunucu bağlantısı kapandı")

# İstemci tarafı
def client(file_path, host='127.0.0.1', port=12345, src_ip='127.0.0.1', dst_ip='127.0.0.1'):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
        print(f"Sunucuya bağlanıldı: {host}:{port}")
    except Exception as e:
        print(f"Bağlantı hatası: {e}")
        return
    
    # RTT ölçümü
    measure_rtt(dst_ip)
    
    # Kimlik doğrulama
    try:
        username = "user1"
        password = "password123"
        s.send(f"{username}:{password}".encode())
        auth_response = s.recv(1024)
        if auth_response != b'AUTH_OK':
            print("Kimlik doğrulama başarısız, bağlantı kapatılıyor")
            s.close()
            return
        print("Kimlik doğrulama başarılı")
    except Exception as e:
        print(f"Kimlik doğrulama hatası: {e}")
        s.close()
        return
    
    # RSA genel anahtarını al
    try:
        public_key_pem = s.recv(4096)
        public_key = serialization.load_pem_public_key(public_key_pem)
        print("RSA genel anahtarı alındı")
    except Exception as e:
        print(f"RSA anahtar alma hatası: {e}")
        s.close()
        return
    
    # AES anahtarı oluştur ve RSA ile şifrele
    key = generate_key()
    try:
        encrypted_key = public_key.encrypt(
            key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        s.send(encrypted_key)
        print("Şifreli AES anahtarı gönderildi")
    except Exception as e:
        print(f"AES anahtar şifreleme hatası: {e}")
        s.close()
        return
    
    # Dosyayı şifrele
    encrypted_data = encrypt_file(file_path, key)
    
    # Dosya hash'ini hesapla
    original_hash = calculate_hash(file_path)
    print(f"Orijinal dosya hash: {original_hash.hex()}")
    
    # Dosyayı parçalara ayır
    fragments = fragment_file(encrypted_data, chunk_size=1024)
    
    # Parçaları gönder ve bant genişliği ölç
    start_time = time.time()
    sent_packets = 0
    total_sent_bytes = 0
    for i, fragment in enumerate(fragments):
        data = struct.pack('!I', i)
        if i == 0:
            data += struct.pack('!I', len(fragments))
            data += fragment
        else:
            data += fragment
        try:
            s.sendall(data)
            print(f"Parça gönderildi: seq={i}")
            ack = s.recv(4)
            ack_seq = struct.unpack('!I', ack)[0]
            if ack_seq != i:
                print(f"Hata: {i}. parça için onay alınamadı!")
            else:
                print(f"Onay alındı: seq={i}")
                sent_packets += 1
                total_sent_bytes += len(fragment)
        except Exception as e:
            print(f"Parça gönderme veya onay alma hatası: {e}")
            s.close()
            return
        if send_packet(fragment, src_ip, dst_ip, seq_num=i, frag_offset=i * 1024, id=i+1, packet_loss_prob=0.0):
            sent_packets += 1
    
    # Eksik parçaları kontrol et
    try:
        missing_count = struct.unpack('!I', s.recv(4))[0]
        if missing_count > 0:
            missing_data = s.recv(4 * missing_count)
            missing = [struct.unpack('!I', missing_data[i:i+4])[0] for i in range(0, len(missing_data), 4)]
            print(f"Yeniden gönderiliyor: {missing}")
            for i in missing:
                data = struct.pack('!I', i) + fragments[i]
                s.sendall(data)
                print(f"Eksik parça gönderildi: seq={i}")
                send_packet(fragments[i], src_ip, dst_ip, seq_num=i, frag_offset=i * 1024, id=i+1)
                sent_packets += 1
                total_sent_bytes += len(fragments[i])
        else:
            print("Tüm parçalar başarıyla gönderildi")
    except Exception as e:
        print(f"Eksik parça kontrol hatası: {e}")
    
    # Bant genişliği hesapla
    transfer_time = time.time() - start_time
    if transfer_time > 0:
        bandwidth = (total_sent_bytes / 1024) / transfer_time  # KB/s
        print(f"Ortalama bant genişliği: {bandwidth:.2f} KB/s")
    
    # Paket kaybı oranı
    packet_loss_rate = 0 if len(fragments) == sent_packets else (len(fragments) - sent_packets) / len(fragments)
    print(f"Paket kaybı oranı: {packet_loss_rate:.2%}")
    
    s.close()
    print("İstemci bağlantısı kapandı")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Kullanım: python secure_file_transfer.py [server|client|mitm] [dosya_yolu]")
    elif sys.argv[1] == "server":
        server()
    elif sys.argv[1] == "client":
        client(sys.argv[2])
    elif sys.argv[1] == "mitm":
        mitm_test()