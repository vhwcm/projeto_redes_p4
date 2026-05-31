#!/bin/bash

set -e
LOG_FILE="/tmp/p4_setup.log"
echo "Teste do Mecanismo de Autenticação - P4 Switch"

export PROJECT_SRC=/home/dev/project
export SDE=/home/dev/open-p4studio
export SDE_INSTALL=$SDE/install

# teste para ver se o switch está rodando e retornar erro logo
if ! tmux list-sessions 2>/dev/null | grep -q "switch"; then
    echo "Switch não encontrado. Temos que rodar ./simulator/start_switch.sh secret primeiro."
    exit 1
fi

echo ""
echo "=========================================================="
echo "Executando testes..."
echo "=========================================================="

# Instalação do scapy
if ! python3 -c "import scapy" &> /dev/null; then
    echo "[*] Scapy não encontrado. Instalando bibliotecas necessárias..."
    sudo pip3 install scapy
fi

# Rodar o script de teste Python
cd /home/dev/project
sudo python3 test_secret.py "$@"

echo ""
echo "=========================================================="
echo "Testes finalizados!"
echo "=========================================================="
