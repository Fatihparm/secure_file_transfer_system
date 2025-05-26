import scapy.all as scapy
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
import os
import socket
import struct
import time

# AES şifreleme için anahtar oluşturma
def generate_key():
    print("Anahtar oluşturuluyor...")
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

# IP paketi gönderme
def send_packet(data, src_ip, dst_ip, seq_num, frag_offset=0, ttl=64, id=1):
    print(f"IP paketi gönderiliyor: seq={seq_num}, offset={frag_offset}")
    ip_packet = scapy.IP(src=src_ip, dst=dst_ip, ttl=ttl, id=id)
    ip_packet.flags = 'MF' if frag_offset > 0 else 0
    ip_packet.frag = frag_offset // 8
    payload = struct.pack('!I', seq_num) + data
    try:
        scapy.send(ip_packet / scapy.Raw(load=payload), verbose=False)
        print(f"Paket gönderildi: seq={seq_num}")
    except Exception as e:
        print(f"Paket gönderme hatası: {e}")

# Sunucu tarafı
def server(host='127.0.0.1', port=12345):
    key = generate_key()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(1)
    print(f"Sunucu dinliyor: {host}:{port}")
    
    conn, addr = s.accept()
    print(f"İstemci bağlandı: {addr}")
    conn.send(key)  # Anahtarı istemciye gönder
    
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
            if seq_num == 0:  # İlk parça, toplam parça sayısını içerir
                total_fragments = struct.unpack('!I', data[4:8])[0]
                fragments[seq_num] = data[8:]
                print(f"Toplam parça sayısı: {total_fragments}")
            else:
                fragments[seq_num] = data[4:]
            
            # Onay (ACK) gönder
            conn.send(struct.pack('!I', seq_num))
            print(f"Onay gönderildi: seq={seq_num}")
            
            # Tüm parçalar alındıysa döngüden çık
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
            conn.send(struct.pack('!I', 0))  # Eksik parça yok
    except Exception as e:
        print(f"Eksik parça bildirimi hatası: {e}")
    
    # Parçaları sıralı birleştir
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
    # Soket bağlantısı
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
        print(f"Sunucuya bağlanıldı: {host}:{port}")
    except Exception as e:
        print(f"Bağlantı hatası: {e}")
        return
    
    # Sunucudan anahtarı al
    try:
        key = s.recv(1024)
        print(f"Anahtar alındı, boyutu: {len(key)} bayt")
    except Exception as e:
        print(f"Anahtar alma hatası: {e}")
        s.close()
        return
    
    # Dosyayı şifrele
    encrypted_data = encrypt_file(file_path, key)
    
    # Dosya hash'ini hesapla
    original_hash = calculate_hash(file_path)
    print(f"Orijinal dosya hash: {original_hash.hex()}")
    
    # Dosyayı parçalara ayır
    fragments = fragment_file(encrypted_data, chunk_size=1024)
    
    # Parçaları gönder
    for i, fragment in enumerate(fragments):
        data = struct.pack('!I', i)
        if i == 0:  # İlk parça, toplam parça sayısını içerir
            data += struct.pack('!I', len(fragments))
            data += fragment
        else:
            data += fragment
        try:
            s.sendall(data)
            print(f"Parça gönderildi: seq={i}")
            # Onay bekle
            ack = s.recv(4)
            ack_seq = struct.unpack('!I', ack)[0]
            if ack_seq != i:
                print(f"Hata: {i}. parça için onay alınamadı!")
            else:
                print(f"Onay alındı: seq={i}")
        except Exception as e:
            print(f"Parça gönderme veya onay alma hatası: {e}")
            s.close()
            return
        # Scapy ile IP paketi gönder
        send_packet(fragment, src_ip, dst_ip, seq_num=i, frag_offset=i * 1024, id=i+1)
    
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
        else:
            print("Tüm parçalar başarıyla gönderildi")
    except Exception as e:
        print(f"Eksik parça kontrol hatası: {e}")
    
    s.close()
    print("İstemci bağlantısı kapandı")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Kullanım: python secure_file_transfer.py [server|client] [dosya_yolu]")
    elif sys.argv[1] == "server":
        server()
    elif sys.argv[1] == "client":
        client(sys.argv[2])