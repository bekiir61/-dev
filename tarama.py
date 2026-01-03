import subprocess
import platform
import ipaddress
import argparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

MAX_THREADS = 100


def is_host_alive(ip):
    """Tek bir IP adresine ping atar"""
    if platform.system() == "Windows":
        cmd = ["ping", "-n", "1", "-w", "500", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return ip, result.returncode == 0
    except Exception:
        return ip, False


def scan_network(network):
    """Verilen network aralığını paralel olarak tarar"""
    try:
        net = ipaddress.ip_network(network, strict=False)
        hosts = [str(h) for h in net.hosts()]
    except ValueError:
        print("❌ Hatalı network formatı! Örnek: 192.168.1.0/24")
        return

    print("\n================= PING TARAMASI =================")
    print(f"📡 Ağ: {network}")
    print(f"🖥️  Toplam Host: {len(hosts)}")
    print(f"⚡ Thread Sayısı: {MAX_THREADS}")
    print("=================================================\n")

    start = time.time()
    aktif = []

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(is_host_alive, ip) for ip in hosts]

        for future in as_completed(futures):
            ip, alive = future.result()
            if alive:
                print(f"🟢 {ip:<15} AKTİF")
                aktif.append(ip)

    end = time.time()

    print("\n------------------ ÖZET ------------------")
    print(f"⏱️  Süre: {end - start:.2f} saniye")
    print(f"✅ Aktif Host: {len(aktif)}")
    print(f"❌ Pasif Host: {len(hosts) - len(aktif)}")
    print("------------------------------------------")

    if aktif:
        print("\n📌 AKTİF HOSTLAR:")
        for ip in aktif:
            print(f"  - {ip}")


def main():
    parser = argparse.ArgumentParser(
        description="Basit Paralel Ping Network Tarayıcı"
    )
    parser.add_argument(
        "network",
        help="Taranacak ağ (örn: 192.168.1.0/24)"
    )

    args = parser.parse_args()
    scan_network(args.network)


if __name__ == "__main__":
    main()
