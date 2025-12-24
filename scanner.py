import subprocess
import platform
import ipaddress
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor
import time

# Host tarama işlemi için maksimum iş parçacığı (thread) sayısı
MAX_THREADS = 254 

def ping_host(ip_adresi):
    """
    Belirtilen IP adresine ping atar ve erişilebilirliği kontrol eder.
    """
    # İşletim sistemine göre ping komutu ayarı
    if platform.system() == "Windows":
        # -n 1 (1 paket), -w 500 (500 ms timeout)
        komut = ["ping", "-n", "1", "-w", "500", str(ip_adresi)]
    else:
        # -c 1 (1 paket), -W 1 (1 saniye timeout)
        komut = ["ping", "-c", "1", "-W", "1", str(ip_adresi)]
        
    try:
        result = subprocess.run(
            komut, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True,
            timeout=1  
        )
        
        if result.returncode == 0:
            # Çıktıda başarı kriterlerini kontrol et
            if "TTL=" in result.stdout or "1 received" in result.stdout or "0% packet loss" in result.stdout:
                return (ip_adresi, True)
        
        return (ip_adresi, False)
        
    except subprocess.TimeoutExpired:
        return (ip_adresi, False)
    except Exception:
        return (ip_adresi, False)


def scan_network(network_range):
    """Verilen network aralığındaki hostları paralel olarak tarar."""
    
    start_time = time.time()
    
    try:
        ag = ipaddress.ip_network(network_range, strict=False)
        all_hosts = [str(host) for host in ag.hosts()]
    except ValueError as e:
        print(f"❌ Hata: Hatalı IP aralığı formatı girdin. {e}")
        print("Örnek format: 192.168.1.0/24")
        sys.exit(1)
        
    hosts_to_scan = [ip for ip in all_hosts if ip != str(ag.network_address) and ip != str(ag.broadcast_address)]
    
    print(f"\n=======================================================")
    print(f"✅ Network Tarayıcı Başlatılıyor...")
    print(f"📡 Hedeflenen Ağ: {network_range} ({len(hosts_to_scan)} olası host)")
    print(f"⚡ Paralel İşlem Sayısı: {MAX_THREADS}")
    print(f"=======================================================\n")
    
    aktif_hostlar = []
    pasif_host_sayisi = 0

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        results = executor.map(ping_host, hosts_to_scan)

        for ip, is_up in results:
            if is_up:
                print(f"🟢 {ip:<15} -> Aktif (UP)")
                aktif_hostlar.append(ip)
            else:
                pasif_host_sayisi += 1

    end_time = time.time()
    elapsed_time = end_time - start_time

    print("\n------------------- Tarama Özeti ----------------------")
    print(f"⏰ Toplam Süre: {elapsed_time:.2f} saniye")
    print(f"✅ Aktif Host Sayısı: {len(aktif_hostlar)}")
    print(f"❌ Pasif Host Sayısı: {pasif_host_sayisi}")
    print("-------------------------------------------------------")
    
    if aktif_hostlar:
        print("\n💰 *BULUNAN AKTİF HOSTLAR:*")
        for ip in aktif_hostlar:
            print(f"    - {ip}")


def main():
    parser = argparse.ArgumentParser(
        description="Paralel Ping Tarayıcı",
        epilog="Kullanım Örneği: python tarayici.py 192.168.1.0/24"
    )
    
    parser.add_argument(
        "network_range",
        type=str,
        help="Taranacak Network aralığı (örn: 192.168.1.0/24)"
    )
    
    args = parser.parse_args()
    scan_network(args.network_range)

# HATA BURADAYDI: __name__ ve "__main__" olmalı
if __name__ == "__main__":
    main()
