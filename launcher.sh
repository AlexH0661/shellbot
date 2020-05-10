#! /bin/bash
if dpkg -l gnome-terminal > /dev/null
then
    echo "[*] Gnome-Terminal is installed"
else
    echo "[-] Installing Gnome-Terminal"
    sudo apt-get install -y gnome-terminal
fi

echo "[*] Starting and Initialising MSF Database"
sudo msfdb init
echo "[*] Starting MSF Console, and MSF RPC"
gnome-terminal -q -- bash -c "sudo msfconsole -x 'load msgrpc Pass=Password1'"
echo "[*] Waiting for MSF Console to start"
sleep 10
echo "[*] Launching ShellBot"
gnome-terminal -q -- python3 './shellbot.py'