#!/usr/bin/env python3

import sys
import time
import argparse
import threading
from scapy.all import Ether, Raw, sendp, sniff, conf
import struct

# Configuração
ETHER_TYPE_SECRET = 0x1234
MAC_SEND = "00:00:00:00:00:01"
MAC_RECV = "00:00:00:00:00:02"
MAC_MON = "00:00:00:00:00:03"

IFACE_SEND = "veth0"
IFACE_RECV = "veth8"
IFACE_MON = "veth16"

# Token secreto padrão (16 bytes = 128 bits)
SECRET_TOKEN = b'\x00' * 16

class SecretPacket:
    def __init__(self, op, token=None):
        if token is None:
            token = SECRET_TOKEN
        if len(token) != 16:
            raise ValueError("Token deve ter 16 bytes")
        self.op = op
        self.token = token
    
    def to_bytes(self):
        return struct.pack('!B', self.op) + self.token
    
    def to_packet(self, dst_mac=MAC_RECV, src_mac=MAC_SEND, payload=None):
        secret_bytes = self.to_bytes()
        pkt = Ether(dst=dst_mac, src=src_mac, type=ETHER_TYPE_SECRET)
        pkt = pkt / Raw(load=secret_bytes)
        if payload:
            pkt = pkt / Raw(load=payload)
        
        if len(pkt) < 64:
            pkt = pkt / Raw(load=b'\x00' * (64 - len(pkt)))
        return pkt

def send_packet(pkt, iface=IFACE_SEND, verbose=True):
    if verbose:
        print(f"\n[SEND] Interface: {iface}")
        print(f"       Destino: {pkt[Ether].dst}")
        print(f"       Tipo: 0x{pkt[Ether].type:04x}")
        print(f"       Tamanho: {len(pkt)} bytes")
        if pkt.haslayer(Raw):
            load = pkt[Raw].load
            if pkt.haslayer(Ether) and pkt[Ether].type == ETHER_TYPE_SECRET and len(load) >= 17:
                op = load[0]
                token = load[1:17].hex()
                payload = load[17:]
                print(f"       [Header Secret Enviado] OP: {op}, Token: {token}")
                
                # Remover bytes nulos para evitar SyntaxError no f-string
                clean_payload = payload.replace(b'\x00', b'')
                if clean_payload:
                    decoded_msg = clean_payload.decode('utf-8', errors='ignore')
                    print(f"       [Payload Enviado] {decoded_msg}")
            else:
                print(f"       [Payload Bruto Enviado] {load}")
    sendp(pkt, iface=iface, verbose=0)

def monitor_packets(iface=IFACE_MON, timeout=2, target_mac=None):
    print(f"\n[MONITOR] Aguardando pacotes em {iface} por {timeout}s...")
    filter_str = ""
    if target_mac:
        filter_str = "ether dst " + target_mac
    
    packets = sniff(iface=iface, timeout=timeout, store=True, filter=filter_str)
    
    if packets:
        print(f"[MONITOR] Recebeu {len(packets)} pacote(s):")
        for i, pkt in enumerate(packets, 1):
            print(f"  Pacote {i}:")
            print(f"    Origem: {pkt[Ether].src}")
            print(f"    Destino: {pkt[Ether].dst}")
            print(f"    Tipo: 0x{pkt[Ether].type:04x}")
            if pkt.haslayer(Raw):
                load = pkt[Raw].load
                if pkt[Ether].type == ETHER_TYPE_SECRET and len(load) >= 17:
                    op = load[0]
                    token = load[1:17].hex()
                    payload = load[17:]
                    
                    print(f"    [Header Secret] OP: {op}, Token: {token}")
                    if op == 1:
                        print("    [LOG Tofino] ESTADO ALTERADO! Novo token registrado nos registradores.")
                    elif op == 2:
                        print("    [LOG Tofino] VERIFICAÇÃO! Pacote validado com o token correto.")
                    
                else:
                    print(f"    [Payload Bruto] {load}")
    else:
        print("[MONITOR] Nenhum pacote recebido")
    return packets

def run_test_with_monitor(pkt, send_iface, recv_iface, target_mac, timeout=2):
    results = []
    def run_monitor():
        pkts = monitor_packets(iface=recv_iface, timeout=timeout, target_mac=target_mac)
        results.append(pkts)
    
    t = threading.Thread(target=run_monitor)
    t.start()
    time.sleep(0.5)
    send_packet(pkt, iface=send_iface)
    t.join()
    return results[0] if results else []

def test_scenario_1():
    print("\n" + "="*60)
    print("TESTE 1: Registrar token secreto (op=1)")
    print("="*60)
    token = b'\x12\x34\x56\x78\x9a\xbc\xde\xf0' + b'\x00' * 8
    pkt = SecretPacket(op=1, token=token).to_packet(dst_mac=MAC_MON, src_mac=MAC_SEND)
    # Esperado: DROP (nenhum pacote recebido em veth16)
    pkts = run_test_with_monitor(pkt, IFACE_SEND, IFACE_MON, MAC_MON)
    if not pkts:
        print("[RESULTADO] SUCESSO: Pacote descartado como esperado")
    else:
        print("[RESULTADO] FALHA: Pacote não deveria ter sido recebido")

def test_scenario_2():
    print("\n" + "="*60)
    print("TESTE 2: Verificar com token correto (op=2)")
    print("="*60)
    token = b'\x12\x34\x56\x78\x9a\xbc\xde\xf0' + b'\x00' * 8
    pkt = SecretPacket(op=2, token=token).to_packet(dst_mac=MAC_RECV, src_mac=MAC_SEND, payload=b"MENSAGEM SECRETA AUTENTICADA")
    # Esperado: PASS (recebido em veth8)
    pkts = run_test_with_monitor(pkt, IFACE_SEND, IFACE_RECV, MAC_RECV)
    if pkts:
        print("[RESULTADO] SUCESSO: Pacote recebido com token correto")
    else:
        print("[RESULTADO] FALHA: Pacote com token correto foi descartado")

def test_scenario_3():
    print("\n" + "="*60)
    print("TESTE 3: Verificar com token errado (op=2)")
    print("="*60)
    wrong_token = b'\xff' * 16
    pkt = SecretPacket(op=2, token=wrong_token).to_packet(dst_mac=MAC_RECV, src_mac=MAC_SEND)
    # Esperado: DROP (nenhum pacote recebido em veth8)
    pkts = run_test_with_monitor(pkt, IFACE_SEND, IFACE_RECV, MAC_RECV)
    if not pkts:
        print("[RESULTADO] SUCESSO: Pacote com token errado descartado")
    else:
        print("[RESULTADO] FALHA: Pacote com token errado foi aceito")

def test_scenario_4():
    print("\n" + "="*60)
    print("TESTE 4: Pacote sem header secreto")
    print("="*60)
    pkt = Ether(dst=MAC_RECV, src=MAC_SEND, type=0x0800) / Raw(load=b"A"*50)
    # Esperado: DROP
    pkts = run_test_with_monitor(pkt, IFACE_SEND, IFACE_RECV, MAC_RECV)
    if not pkts:
        print("[RESULTADO] SUCESSO: Pacote comum descartado")
    else:
        print("[RESULTADO] FALHA: Pacote comum foi aceito")

def test_scenario_5():
    print("\n" + "="*60)
    print("TESTE 5: Operação inválida (op=99)")
    print("="*60)
    token = b'\x12\x34\x56\x78\x9a\xbc\xde\xf0' + b'\x00' * 8
    pkt = SecretPacket(op=99, token=token).to_packet(dst_mac=MAC_RECV, src_mac=MAC_SEND)
    # Esperado: DROP
    pkts = run_test_with_monitor(pkt, IFACE_SEND, IFACE_RECV, MAC_RECV)
    if not pkts:
        print("[RESULTADO] SUCESSO: Operação inválida descartada")
    else:
        print("[RESULTADO] FALHA: Operação inválida foi aceita")

def test_switching_matrix():
    print("\n" + "="*60)
    print("TESTE EXTRA: Matriz de Comutação (Interface Entry -> Exit)")
    print("="*60)
    
    # Mapeamento das interfaces e seus MACs configurados no setup.py
    interfaces = [
        {"iface": "veth0",  "mac": "00:00:00:00:00:01"},
        {"iface": "veth8",  "mac": "00:00:00:00:00:02"},
        {"iface": "veth16", "mac": "00:00:00:00:00:03"},
        {"iface": "veth24", "mac": "00:00:00:00:00:04"}
    ]
    
    token = b'\x12\x34\x56\x78\x9a\xbc\xde\xf0' + b'\x00' * 8
    
    # Primeiro, registrar o token enviando de veth0 (op=1)
    print("[*] Registrando token antes de iniciar a matriz...")
    reg_pkt = SecretPacket(op=1, token=token).to_packet(dst_mac=interfaces[2]["mac"], src_mac=interfaces[0]["mac"])
    send_packet(reg_pkt, iface=interfaces[0]["iface"], verbose=False)
    time.sleep(1)

    for entry in interfaces:
        for exit in interfaces:
            if entry["iface"] == exit["iface"]:
                continue
            
            print(f"\n[TEST] Enviando: {entry['iface']} -> Recebendo: {exit['iface']}")
            
            payload_text = f"DE:{entry['iface']} PARA:{exit['iface']}"
            pkt = SecretPacket(op=2, token=token).to_packet(
                dst_mac=exit["mac"], 
                src_mac=entry["mac"], 
                payload=payload_text.encode()
            )
            
            pkts = run_test_with_monitor(pkt, entry["iface"], exit["iface"], exit["mac"], timeout=2)
            
            if pkts:
                print(f"[RESULTADO] SUCESSO: Comutação {entry['iface']} -> {exit['iface']} OK")
            else:
                print(f"[RESULTADO] FALHA: Pacote não chegou em {exit['iface']}")
            time.sleep(0.5)

if __name__ == "__main__":
    conf.use_pcap = True
    test_scenario_1()
    time.sleep(1)
    test_scenario_2()
    time.sleep(1)
    test_scenario_3()
    time.sleep(1)
    test_scenario_4()
    time.sleep(1)
    test_scenario_5()
    
    # Novo teste de matriz
    test_switching_matrix()
    
    print("\n" + "="*60)
    print("TESTES CONCLUÍDOS")
    print("="*60)
