#!/bin/bash

# Sprawdzenie czy skrypt uruchomiony jako root, jeśli nie to przeładuj przez sudo (interaktywnie)
if [[ $EUID -ne 0 ]]; then
  echo "⏳ Podnoszę uprawnienia do root przez sudo..."
  exec sudo -E "$0" "$@"
fi

# Sprawdzenie czy dialog jest zainstalowany
if ! command -v dialog &>/dev/null; then
  echo "❌ Nie znaleziono pakietu 'dialog'. Instaluje..."
  apt install dialog -y > /dev/null 2>&1
fi

# Ustaw logo jako zmienną
if [[ -f /tmp/logo.txt ]]; then
  rm -r /tmp/logo.txt
else
  echo ""
fi

cat <<'EOF' > /tmp/logo.txt
 _______   __    __                __    __                        __
|       \ |  \  |  \              |  \  |  \                      |  \
| $$$$$$$\ \$$ _| $$_     ______  | $$  | $$  ______    _______  _| $$_
| $$__/ $$|  \|   $$ \   /      \ | $$__| $$ /      \  /       \|   $$ \
| $$    $$| $$ \$$$$$$  |  $$$$$$\| $$    $$|  $$$$$$\|  $$$$$$$ \$$$$$$
| $$$$$$$\| $$  | $$ __ | $$    $$| $$$$$$$$| $$  | $$ \$$    \   | $$ __
| $$__/ $$| $$  | $$|  \| $$$$$$$$| $$  | $$| $$__/ $$ _\$$$$$$\  | $$|  \
| $$    $$| $$   \$$  $$ \$$     \| $$  | $$ \$$    $$|       $$   \$$  $$
 \$$$$$$$  \$$    \$$$$   \$$$$$$$ \$$   \$$  \$$$$$$  \$$$$$$$     \$$$$
    
🚀 CLI - UFW Manager [v1.0]
by Vahistar
EOF

# Wyświetl logo w oknie dialogu
dialog --title "CLI - UFW Manager" --textbox /tmp/logo.txt 20 80

# Funkcja rozbijająca porty i zakresy na pojedyncze porty
parse_ports() {
  local input="$1"
  local ports=()

  IFS=',' read -ra parts <<< "$input"
  for part in "${parts[@]}"; do
    if [[ "$part" =~ ^[0-9]+-[0-9]+$ ]]; then
      start=${part%-*}
      end=${part#*-}
      if (( start > end )); then
        echo "⚠️"
        continue
      fi
      for ((p=start; p<=end; p++)); do
        ports+=("$p")
      done
    elif [[ "$part" =~ ^[0-9]+$ ]]; then
      ports+=("$part")
    else
      echo "⚠️"
    fi
  done

  # Usuń duplikaty i sortuj
  echo "${ports[@]}" | tr ' ' '\n' | sort -n | uniq
}

# Funkcja ładnego wyświetlenia reguł UFW
show_ufw_rules() {
  dialog --title "Lista Dozwolonych Portów" --clear --msgbox "$(ufw status numbered | grep -E "ALLOW" | grep -v "\(v6\)" || echo 'Brak dozwolonych portów lub firewall jest wyłaczony 🖥️')" 20 80
}

# Funkcja dodawania lub usuwania portów z uwzględnieniem protokołu
process_ports() {
  local action=$1
  local ports=$2
  local proto=$3

  local ports_changed=0

  for PORT in $ports; do
    if [[ "$action" == "add" ]]; then
      if [[ "$proto" == "tcp" || "$proto" == "both" ]]; then
        if ufw status 2>/dev/null | grep -qE "^${PORT}(/tcp)?\s+ALLOW"; then
          echo "📝 Port $PORT (TCP) już jest dozwolony, pomijam."
        else
          ufw allow ${PORT}/tcp > /dev/null 2>&1
          echo "➕  Dodano port $PORT (TCP)"
          ports_changed=1
        fi
      fi

      if [[ "$proto" == "udp" || "$proto" == "both" ]]; then
        if ufw status 2>/dev/null | grep -qE "^${PORT}(/udp)?\s+ALLOW"; then
          echo "📝 Port $PORT (UDP) już jest dozwolony, pomijam."
        else
          ufw allow ${PORT}/udp > /dev/null 2>&1
          echo "➕ Dodano port $PORT (UDP)"
          ports_changed=1
        fi
      fi

    else
      if [[ "$proto" == "tcp" || "$proto" == "both" ]]; then
        if ufw status 2>/dev/null | grep -qE "^${PORT}(/tcp)?\s+ALLOW"; then
          ufw delete allow ${PORT}/tcp > /dev/null 2>&1
          echo "🗑️  Usunięto port $PORT (TCP)"
          ports_changed=1
        else
          echo "📝 Port $PORT (TCP) nie był dozwolony, pomijam."
        fi
      fi

      if [[ "$proto" == "udp" || "$proto" == "both" ]]; then
        if ufw status 2>/dev/null | grep -qE "^${PORT}(/udp)?\s+ALLOW"; then
          ufw delete allow ${PORT}/udp > /dev/null 2>&1
          echo "🗑️  Usunięto port $PORT (UDP)"
          ports_changed=1
        else
          echo "📝 Port $PORT (UDP) nie był dozwolony, pomijam."
        fi
      fi
    fi
  done

  if [[ "$ports_changed" -eq 1 ]]; then
    echo ""
    echo "♻️  Przeładowuję UFW..."
    ufw reload > /dev/null 2>&1
    echo ""
  else
    echo ""
    echo "📝 Nic nie zostało zmienione."
    echo ""
  fi
}

# --- Funkcja do UFW ---
disable_ufw() {
  echo "♻️  Wyłączam UFW..."
  ufw disable > /dev/null 2>&1
  echo "✅ UFW wyłączony."
}

enable_ufw() {
  echo "♻️  Włączam UFW i dodaję port 22 (SSH)..."
  ufw --force enable > /dev/null 2>&1
  # Dodaj port 22 tcp jeśli nie ma
  if ! ufw status | grep -q "^22/tcp\s\+ALLOW"; then
    ufw allow 22/tcp > /dev/null 2>&1
    echo "➕  Port 22 (TCP) został dodany."
  fi
  ufw reload > /dev/null 2>&1
  echo "✅ UFW włączony."
}

reset_ufw() {
  echo "♻️  Resetuję UFW do ustawień fabrycznych..."
  ufw --force reset > /dev/null 2>&1
  ufw default deny incoming > /dev/null 2>&1
  ufw default allow outgoing > /dev/null 2>&1
  ufw --force enable > /dev/null 2>&1
  ufw allow 22/tcp > /dev/null 2>&1
  ufw reload > /dev/null 2>&1
  echo "✅ Reset wykonany. Port 22 (SSH) jest otwarty."
}


# --- Funkcja do obsługi presetów ---
handle_preset() {
  local preset_name=$1
  local ports_tcp=""
  local ports_udp=""

  case "$preset_name" in
    "Bitehost Wings")
      ports_tcp="2022 8080 80 443"
      ports_udp=""
      ;;
    "Wings")
      ports_tcp="2022 8080"
      ports_udp=""
      ;;
    "Nginx")
      ports_tcp="80 443"
      ports_udp=""
      ;;
    *)
      dialog --msgbox "Nieznany preset: $preset_name" 20 80
      return
      ;;
  esac

  # Wybór akcji: dodaj, usuń, nic
  action=$(dialog --menu "Co Zrobić Z Presetem $preset_name?" 20 80 3 \
    1 "Dodaj" \
    2 "Usuń" \
    3 "Pozostaw Bez Zmian" 3>&1 1>&2 2>&3)

  case $action in
    1)
      # Dodaj porty TCP i UDP (tu UDP puste)
      output=""
      for p in $ports_tcp; do
        if ufw status | grep -q "^${p}/tcp\s\+ALLOW"; then
          output+="📝 Port $p (TCP) już jest dozwolony, pomijam.\n"
        else
          ufw allow ${p}/tcp > /dev/null 2>&1
          output+="➕  Dodano port $p (TCP)\n"
        fi
      done
      for p in $ports_udp; do
        if ufw status | grep -q "^${p}/udp\s\+ALLOW"; then
          output+="📝 Port $p (UDP) już jest dozwolony, pomijam.\n"
        else
          ufw allow ${p}/udp > /dev/null 2>&1
          output+="➕  Dodano port $p (UDP)\n"
        fi
      done
      ufw reload > /dev/null 2>&1
      dialog --title "Preset $preset_name" --msgbox "$output" 20 80
      ;;
    2)
      # Usuń porty TCP i UDP
      output=""
      for p in $ports_tcp; do
        if ufw status | grep -q "^${p}/tcp\s\+ALLOW"; then
          ufw delete allow ${p}/tcp > /dev/null 2>&1
          output+="🗑️  Usunięto port $p (TCP)\n"
        else
          output+="📝  Port $p (TCP) nie był dozwolony, pomijam.\n"
        fi
      done
      for p in $ports_udp; do
        if ufw status | grep -q "^${p}/udp\s\+ALLOW"; then
          ufw delete allow ${p}/udp > /dev/null 2>&1
          output+="🗑️  Usunięto port $p (UDP)\n"
        else
          output+="📝 Port $p (UDP) nie był dozwolony, pomijam.\n"
        fi
      done
      ufw reload > /dev/null 2>&1
      dialog --title "Preset $preset_name" --msgbox "$output" 20 80
      ;;
    3)
      dialog --msgbox "💀 Nie Dokonano Zmian W Presecie $preset_name." 20 80
      ;;
    *)
      dialog --msgbox "💀 Nieprawidłowy wybór." 20 80
      ;;
  esac
}

while true; do
  # Menu główne
  choice=$(dialog --clear \
    --title "Menu Główne" \
    --menu "Wybierz opcję:" 20 80 7 \
    1 "Dodaj porty" \
    2 "Usuń porty" \
    3 "Presety" \
    4 "Pokaż listę portów" \
    5 "Włącz UFW" \
    6 "Wyłącz UFW" \
    7 "Reset UFW do ustawień fabrycznych" \
    8 "Wyjdź" \
    3>&1 1>&2 2>&3)

  exit_status=$?
  clear

  if [[ $exit_status -ne 0 ]]; then
    echo ""
    echo "Do widzenia! 👋"
    echo ""
    exit 0
  fi

  case $choice in
    1)
      action="add"
      ;;
    2)
      action="remove"
      ;;
    4)
      show_ufw_rules
      continue
      ;;
    5)
      enable_ufw
      dialog --msgbox "♻️  UFW włączony.\n✅ Port 22 (SSH) jest otwarty." 20 80
      continue
      ;;
    6)
      disable_ufw
      dialog --msgbox "💀  UFW wyłączony." 20 80
      continue
      ;;
    7)
      reset_ufw
      dialog --msgbox "♻️  Firewall został zresetowany do ustawień fabrycznych.\n✅ Port 22 (SSH) jest otwarty." 20 80
      continue
      ;;
    3)
      preset_choice=$(dialog --menu "Wybierz preset:" 20 80 3 \
        1 "Bitehost Wings" \
        2 "Wings" \
        3 "Nginx" \
        3>&1 1>&2 2>&3)

      case $preset_choice in
        2) handle_preset "Wings" ;;
        3) handle_preset "Nginx" ;;
        1) handle_preset "Bitehost Wings" ;;
        *) dialog --msgbox "💀 Nie wybrano żadnego presetu! Wracasz do menu." 20 80 ;;
      esac
      continue
      ;;
    8)
      echo ""
      echo "Do widzenia! 👋"
      echo ""
      exit 0
      ;;
    *)
      echo "💀 Nieprawidłowy wybór."
      continue
      ;;
  esac

  # Wybór protokołu
  proto_choice=$(dialog --clear \
    --title "Protokół" \
    --menu "Wybierz protokół do przetworzenia:" 20 80 3 \
    1 "TCP" \
    2 "UDP" \
    3 "TCP/UDP" \
    3>&1 1>&2 2>&3)

  case $proto_choice in
    1) proto="tcp" ;;
    2) proto="udp" ;;
    3) proto="both" ;;
    *)
      dialog --msgbox "💀 Nie wybrano żadnego protokołu! Wracasz do menu." 20 80
      continue
      ;;
  esac

  # Pobierz porty od użytkownika za pomocą dialogu inputbox
  user_ports_raw=$(dialog --inputbox "Podaj porty lub zakresy (np. 80,443,2000-2010):" 20 80 3>&1 1>&2 2>&3)
  if [[ -z "$user_ports_raw" ]]; then
    dialog --msgbox "💀 Nie podano żadnych portów! Wracasz do menu." 20 80
    continue
  fi

  ports=$(parse_ports "$user_ports_raw")

  if [[ -z "$ports" ]]; then
    dialog --msgbox "💀 Nie podałeś żadnych poprawnych portów." 20 80
    continue
  fi

  # Przetwarzanie portów
  output=$(process_ports "$action" "$ports" "$proto" 2>&1)

  dialog --title "Logi" --msgbox "$output" 20 80
done
