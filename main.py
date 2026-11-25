import socket
import time
import requests
import nmap
from collections import Counter

# ================= CONFIGURAÇÕES =================
ESP_IP = "192.168.1.123"  # <-- Coloque aqui o IP do seu ESP8266
BASE_URL = f"http://{ESP_IP}"
# =================================================

def obter_subrede_local():
    """Descobre automaticamente a sub-rede local (ex: 192.168.1.0/24)"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_local = s.getsockname()
        s.close()
        prefixo = ".".join(ip_local.split(".")[:3])
        return f"{prefixo}.0/24"
    except Exception:
        return "192.168.1.0/24"

# --- PROGRAMA 1: ANÁLISE VIA ESP8266 ---
def menu_esp8266():
    print(f"\n[Conectando ao ESP8266 em {ESP_IP}...]")
    
    print("\n--- 1. Estabilidade e Sinal (5 amostras) ---")
    rssis, latencias, falhas = [], [], 0

    for i in range(5):
        try:
            inicio = time.time()
            res = requests.get(f"{BASE_URL}/status", timeout=3)
            latencia_ms = (time.time() - inicio) * 1000
            dados = res.json()
            
            rssis.append(dados["rssi"])
            latencias.append(latencia_ms)
            freq_mhz = 2407 + (dados["canal"] * 5)
            
            print(f"[{i+1}/5] Sinal: {dados['rssi']} dBm | Canal: {dados['canal']} ({freq_mhz} MHz) | Latência: {latencia_ms:.1f} ms")
        except Exception:
            falhas += 1
            print(f"[{i+1}/5] Falha na comunicação com o ESP8266")
        time.sleep(1)

    if rssis:
        print(f"\nResumo: Sinal Médio = {sum(rssis)/len(rssis):.1f} dBm | "
              f"Latência Média = {sum(latencias)/len(latencias):.1f} ms | "
              f"Perda = {(falhas/5)*100:.0f}%")
    else:
        print("\nNão foi possível conectar ao ESP8266. Verifique o IP na opção 3.")
        return

    print("\n--- 2. Espectro Wi-Fi 2.4 GHz (Redes Vizinhas) ---")
    try:
        res = requests.get(f"{BASE_URL}/scan", timeout=10)
        redes = res.json()
        redes.sort(key=lambda x: x["rssi"], reverse=True)

        canais = Counter()
        for r in redes:
            canais[r["canal"]] += 1
            nome = r["ssid"] if r["ssid"] else "<Rede Oculta>"
            freq = 2407 + (r["canal"] * 5)
            print(f"Canal {r['canal']:2d} ({freq} MHz) | {r['rssi']:4d} dBm | {nome}")

        print("\nOcupação por Canal:")
        for canal, qtd in sorted(canais.items()):
            print(f"Canal {canal:2d}: {'█' * qtd} ({qtd} redes)")
    except Exception as e:
        print(f"Erro ao escanear redes vizinhas: {e}")

# --- PROGRAMA 2: ANÁLISE DETALHADA COM NMAP ---
def menu_nmap():
    try:
        nm = nmap.PortScanner()
    except nmap.PortScannerError:
        print("\n[ERRO] Nmap não encontrado no sistema! Instale o Nmap oficial e reinicie o VS Code.")
        return

    sub_rede = obter_subrede_local()
    print(f"\n--- Varredura Nmap na rede {sub_rede} ---")
    print("Descobrindo equipamentos ativos (Ping Scan -sn)...")
    
    # -sn: Descobre hosts ativos rapidamente sem escanear todas as portas ainda
    nm.scan(hosts=sub_rede, arguments='-sn')
    hosts_ativos = nm.all_hosts()

    if not hosts_ativos:
        print("Nenhum dispositivo encontrado.")
        return

    print(f"\n{'IP':<16} | {'Hostname':<25} | {'MAC / Fabricante'}")
    print("-" * 75)
    
    for host in sorted(hosts_ativos, key=lambda ip: tuple(map(int, ip.split('.')))):
        hostname = nm[host].hostname() or "Desconhecido"
        mac = nm[host]['addresses'].get('mac', 'Local/N/A')
        fabricante = nm[host]['vendor'].get(mac, '')
        info_mac = f"{mac} ({fabricante})" if fabricante else mac
        print(f"{host:<16} | {hostname:<25} | {info_mac}")

    # Pergunta se deseja detalhar algum equipamento específico
    alvo = input("\nDigite o IP de um equipamento acima para análise profunda (ou Enter para voltar): ").strip()
    if alvo in hosts_ativos:
        print(f"\nAnalisando portas, serviços e versões em {alvo} (aguarde)...")
        # -sV: Detecta versões dos serviços | -F: Fast scan (100 portas mais comuns)
        nm.scan(hosts=alvo, arguments='-sV -F')
        
        for proto in nm[alvo].all_protocols():
            print(f"\nProtocolo: {proto.upper()}")
            portas = sorted(nm[alvo][proto].keys())
            for porta in portas:
                info = nm[alvo][proto][porta]
                servico = info.get('name', '')
                produto = info.get('product', '')
                versao = info.get('version', '')
                print(f"  Porta {porta:<5} | Estado: {info['state']:<8} | Serviço: {servico} {produto} {versao}".strip())
        
        if not nm[alvo].all_protocols():
            print("Nenhuma porta aberta encontrada nas 100 portas principais (firewall ativo ou dispositivo fechado).")

# --- MENU PRINCIPAL ---
def main():
    global ESP_IP, BASE_URL
    while True:
        print("\n" + "="*48)
        print("     PAINEL DE ANÁLISE DE REDE (ESP8266 + NMAP)")
        print("="*48)
        print(f"IP atual do ESP8266: {ESP_IP}")
        print("-" * 48)
        print("1 - Analisar Wi-Fi e Frequências (via ESP8266)")
        print("2 - Descobrir e Detalhar Equipamentos (via Nmap)")
        print("3 - Alterar IP do ESP8266")
        print("0 - Sair")
        print("="*48)

        opcao = input("Escolha uma opção: ").strip()

        if opcao == "1":
            menu_esp8266()
        elif opcao == "2":
            menu_nmap()
        elif opcao == "3":
            novo_ip = input("Digite o novo IP do ESP8266: ").strip()
            if novo_ip:
                ESP_IP = novo_ip
                BASE_URL = f"http://{ESP_IP}"
                print("IP atualizado com sucesso!")
        elif opcao == "0":
            print("Encerrando painel...")
            break
        else:
            print("Opção inválida! Tente novamente.")

if __name__ == "__main__":
    main()
