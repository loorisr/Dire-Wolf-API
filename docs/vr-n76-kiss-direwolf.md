# VR-N76 KISS + Direwolf — rapport de test

Date : **2026-10-27**  
Matériel : **VR-N76**, **Baofeng BF-F8HP**, PC Linux, carte son **Intel PCH**  
Logiciels : **Direwolf 1.9**, **Direwolf API**, BlueZ 5.72, PipeWire

## Résumé

Les deux sens de transmission ont été validés :

- **VR-N76 KISS → RF → Baofeng → carte son → Direwolf → application** : OK
- **Direwolf → carte son PC → Baofeng (VOX) → RF → VR-N76 KISS** : OK

Réglage de référence : **`TXDELAY 30` (300 ms)** et **`TXTAIL 10` (100 ms)**.  
Après redémarrage du talkie (VOX froid), 300 ms n'a donné que **3/5** ; **400 ms (`TXDELAY 40`) a donné 5/5** et est recommandé pour un usage régulier.

Points importants :

- Le profil Bluetooth **Headset** doit être désactivé pour que le canal KISS soit exposé.
- Le canal RFCOMM du service **SPP Dev** est **dynamique** : il a été observé sur **1** et sur **4**.
- La carte son USB G430 se déconnecte à chaque émission RF ; le test final utilise la **sortie ligne arrière de la carte mère**.
- Le VOX du BF-F8HP exige un **câble APRS 2 fiches** correct et un préambule suffisant.

---

## 1. Chaînes testées

### 1.1 Réception VR-N76 → Direwolf

```
VR-N76 (KISS)
   │ RF 144.800 MHz
   ▼
Baofeng BF-F8HP (réception)
   │ câble audio
   ▼
Carte son USB G430
   │
   ▼
Direwolf (ADEVICE plughw:2,0)
   │ KISS TCP :8001
   ▼
Direwolf API
```

### 1.2 Émission Direwolf → VR-N76

```
Direwolf
   │ KISS TCP :8001
   ▼
Carte son PC (PCH, sortie ligne arrière)
   │ câble audio
   ▼
Baofeng BF-F8HP (VOX)
   │ RF 144.800 MHz
   ▼
VR-N76 (KISS)
   │ RFCOMM SPP
   ▼
Client KISS de test
```

---

## 2. Configuration Bluetooth du VR-N76

### 2.1 Profil Headset à désactiver

Sans ce réglage, le profil audio Bluetooth du PC monopolise la radio et le canal RFCOMM KISS est refusé.

```ini
# /etc/bluetooth/input.conf
[General]
Disable=Headset
```

Puis :

```bash
sudo systemctl restart bluetooth
```

Il faut ensuite ré-appairer la radio si nécessaire.

### 2.2 Appairage

```bash
bluetoothctl
agent on
default-agent
scan on
pair 38:D2:00:AA:BB:CC
trust 38:D2:00:AA:BB:CC
exit
```

Adresse observée : `38:D2:00:AA:BB:CC`.

### 2.3 Réglages sur la radio

- **Settings → General Settings → TNC Mode → KISS**  
  ou **KISS TNC → Enable KISS TNC** selon le firmware.
- **General Settings → Digital Mode → Enable**
- **Radio Settings → Tail Elimination → OFF**
- Fermer l'**application HT APP** du téléphone et déconnecter le téléphone de la radio.
- Rester sur l'écran KISS et garder la radio allumée.

La radio quitte le mode KISS quand la liaison RFCOMM se ferme. Il faut alors réactiver le mode KISS, ou garder le service connecté en permanence.

### 2.4 Découverte du canal SPP

Le canal du service série **SPP Dev** change selon l'état de la radio :

```bash
sdptool records 38:D2:00:AA:BB:CC
```

Exemple observé :

```text
Service Name: SPP Dev
Service Class ID List:
  "Serial Port" (0x1101)
Protocol Descriptor List:
  "L2CAP" (0x0100)
  "RFCOMM" (0x0003)
    Channel: 1          # observé aussi : Channel: 4
```

Autres services observés :

| Service | Canal RFCOMM | Usage |
|---|---:|---|
| `BS AOC` | 2 | service constructeur / HT APP |
| `Voice Gateway` | 3 | profil mains-libres |
| `SPP Dev` | 1 ou 4 | **KISS TNC** |

Il ne faut donc pas supposer que le canal est toujours 1. L'application Go le
découvre automatiquement dans l'enregistrement SDP :

```bash
go run . -kiss 'rfcomm://auto' -api :8080
```

Avec une adresse MAC explicite :

```bash
go run . -kiss 'rfcomm://38:D2:00:AA:BB:CC' -api :8080
```

La découverte utilise `sdptool search --bdaddr <MAC> SP`, qui est très rapide
(observé : **0,04 s**), avec `sdptool records` en secours si nécessaire
(`records` a pris **13,3 s** sur cette radio, donc il n'est pas utilisé en
premier). En cas d'échec de la découverte, l'application retombe sur le canal 1.
Pour forcer un canal :

```bash
go run . -kiss 'rfcomm://auto?channel=4' -api :8080
```

Si le service SPP est absent, c'est que la radio n'est pas en mode KISS : il
faut le réactiver sur la radio.

---

## 3. Configuration audio du PC

### 3.1 Pourquoi la carte USB G430 a été abandonnée

La G430 se déconnecte à chaque transmission RF :

```text
usb 3-2-port4: disabled by hub (EMI?), re-enabling...
usb 3-2.4: USB disconnect, device number 23
```

Direwolf s'arrête alors avec :

```text
Audio input device 0 error code -19: No such device
Terminating after audio device 0 input failure.
```

L'isolateur USB n'a pas suffi, la carte étant derrière un hub. Le test final utilise la **carte son de la carte mère**.

### 3.2 Carte PCH et sortie ligne arrière

Carte :

```text
card 1: PCH [HDA Intel PCH], device 0: ALC897 Analog
```

La sortie utilisée est la **sortie ligne arrière** (jack vert). Réglages ALSA observés :

```bash
amixer -c 1 contents
```

- `Front Headphone Jack` : `off` (aucun casque façade)
- `Line Out Jack` : `on`
- `Front Playback Switch` : `on,on`
- `Front Playback Volume` : `87,87` (maximum)
- `Master Playback Switch` : `on`
- `PCM Playback Volume` : `255,255`
- `Headphone Playback Switch` : `off,off`
- `Auto-Mute Mode` : `Disabled`

Régler si besoin :

```bash
amixer -c 1 cset numid=19 0          # Auto-Mute désactivé
amixer -c 1 cset numid=3 on          # Front Playback Switch
amixer -c 1 cset numid=2 87,87       # Front Playback Volume
amixer -c 1 cset numid=30 on         # Master Playback Switch
amixer -c 1 cset numid=29 87         # Master Playback Volume
amixer -c 1 cset numid=67 255,255    # PCM Playback Volume
```

### 3.3 PipeWire

Avec PipeWire actif, `plughw:1,0` est occupé. Utiliser le périphérique ALSA `default`, qui passe par PipeWire :

```bash
pactl get-default-sink
# alsa_output.pci-0000_80_1f.3.analog-stereo

pactl list sinks | grep -E 'Port actif|Active Port|analog-output-'
# Port actif : analog-output-lineout
```

La sortie active doit être `analog-output-lineout`. Pour la forcer :

```bash
pactl set-sink-port alsa_output.pci-0000_80_1f.3.analog-stereo analog-output-lineout
```

Alternative sans PipeWire : arrêter PipeWire/WirePlumber puis utiliser directement `plughw:1,0`. C'est utile si l'on veut éviter la latence et le routage logiciel, mais cela coupe l'audio du bureau pendant le test.

---

## 4. Configuration Direwolf

### 4.1 Configuration utilisée pour le test

Fichier temporaire : `/tmp/opencode/direwolf-pch.conf`, copie de `direwolf.conf` avec :

```ini
ADEVICE  default
```

Extrait du démarrage :

```text
Audio device for both receive and transmit: default  (channel 0)
Channel 0: 1200 baud, AFSK 1200 & 2200 Hz, 44100 sample rate, Tx AX.25.
Note: PTT not configured for channel 0. (OK if using VOX.)
```

Aucun PTT n'est configuré : l'émission est déclenchée par le **VOX du Baofeng**.

### 4.2 Réglages de timing

Direwolf envoie des **flags HDLC** pendant le préambule. C'est ce signal qui déclenche le VOX.

| Réglage | Unité | Valeur recommandée | Rôle |
|---|---:|---:|---|
| `TXDELAY` | 10 ms | **40** = **400 ms** (30 = 300 ms validé à chaud) | préambule avant les données |
| `TXTAIL` | 10 ms | **10** = **100 ms** | maintien après les données |

Dans `direwolf.conf`, sous `CHANNEL 0` :

```ini
# 400 ms : recommandé après redémarrage du talkie / VOX froid
TXDELAY 40
TXTAIL 10
```

`TXDELAY 30` (300 ms) fonctionne bien quand le VOX est déjà chaud, mais a donné
seulement 3/5 après un redémarrage du talkie.

La valeur KISS maximale de `TXDELAY` est 255 (2,55 s). Une valeur de 300 est invalide et fait échouer le client KISS avant l'émission.

### 4.3 Avertissement VOX

Direwolf rappelle que le VOX intégré d'un émetteur n'est pas idéal pour le packet :

```text
Using VOX built in to the radio is a VERY BAD idea...
```

C'est acceptable ici pour un test APRS en émission ponctuelle, mais un PTT filaire ou un CM108 serait préférable pour un usage régulier.

---

## 5. Configuration du Baofeng BF-F8HP

- **VOX = 10** (sur cette unité, 10 est le plus sensible ; selon les firmwares, l'échelle peut être inversée, essayer 1 et 10).
- **Fréquence APRS** : 144.800 MHz en France, identique sur le VR-N76.
- **Puissance** : LOW recommandé pour limiter les perturbations RF du PC.
- **Câble** : câble APRS avec **deux fiches** :
  - 3,5 mm pour le haut-parleur (réception),
  - **2,5 mm pour le micro/PTT** (émission).

Un mauvais câble a été la cause d'une absence totale d'émission : la LED TX du Baofeng ne s'allumait pas malgré un audio Direwolf correct. Avec le bon câble et le VOX à 10, l'émission fonctionne.

---

## 6. Trames et protocole KISS

### 6.1 Trame APRS de test

Trame AX.25 UI, source `F4XXX-15`, destination `APRS`, **sans digipeater** :

```text
F4XXX-15>APRS : >DIREWOLF TX TEST -> VR-N76 - ignore
```

Encodage AX.25 :

```python
def ax25_addr(call, ssid=0, last=False):
    data = bytes(ord(c) << 1 for c in call.ljust(6))
    ssid_byte = 0x60 | ((ssid & 0x0F) << 1) | (1 if last else 0)
    return data + bytes([ssid_byte])

frame = (
    ax25_addr("APRS", 0, False)
    + ax25_addr("F4XXX", 15, True)
    + bytes([0x03, 0xF0])                  # UI + PID 0xF0
    + b">DIREWOLF TX TEST -> VR-N76 - ignore"
)
```

Encapsulation KISS :

```python
def kiss_wrap(payload, cmd=0x00):
    out = bytearray([0xC0, cmd])
    for b in payload:
        if b == 0xC0:
            out += bytes([0xDB, 0xDC])
        elif b == 0xDB:
            out += bytes([0xDB, 0xDD])
        else:
            out.append(b)
    out.append(0xC0)
    return bytes(out)

def kiss_command(cmd, value):
    return bytes([0xC0, cmd, value, 0xC0])
```

Commandes KISS utilisées :

| Commande | Octet | Valeur |
|---|---:|---:|
| `TXDELAY` | `0x01` | 30 = 300 ms |
| `TXTAIL` | `0x04` | 10 = 100 ms |

### 6.2 Sens VR-N76 KISS → Direwolf

Le TNC KISS du VR-N76 a été utilisé pour émettre une trame `F4XXX-7>APRS` :

```text
>KISS TX TEST via VR-N76 - ignore
```

Direwolf l'a reçue et décodée :

```text
[PKT #1] F4XXX-7  F4XXX-7>APRS  >KISS TX TEST via VR-N76 - ignore
```

### 6.3 Sens Direwolf → VR-N76

Le client KISS se connecte au canal SPP de la radio, garde la liaison ouverte, puis envoie une trame à Direwolf sur le port 8001. La radio reçoit la trame RF et la renvoie en KISS au client.

Exemple de réception côté VR-N76 :

```text
KISS RX: F4XXX-15>APRS : >300MS RELIABILITY 10/10
```

---

## 7. Résultats

### 7.1 Réception Direwolf du talkie

Deux trames de test ont été décodées (données anonymisées) :

```text
18:36:32  F4XXX-7>APN000,WIDE1-1,WIDE2-2  >
18:36:53  F4XXX-7>APN000,WIDE1-1,WIDE2-2
          =0000.00N/00000.00E$/A=000300FICTIONAL POSITION
```

Décodage :

- Source : `F4XXX-7`
- Position : **0.0000 N, 0.0000 E (position fictive)**
- Altitude : **générique (exemple)**
- Commentaire : **`FICTIONAL POSITION`**

Cela valide la chaîne audio talkie → carte son → Direwolf.

### 7.2 Premier test inverse réussi

À 19:25:57, avec un préambule de 2 s, la trame Direwolf a été reçue par le VR-N76 :

```text
KISS RX: F4XXX-15>APRS : >DIREWOLF TX TEST -> VR-N76 - ignore
```

À ce moment, la sortie audio utilisée était le **casque façade** du PC. Le test a ensuite été refait sur la **sortie ligne arrière**, qui est la configuration finale.

### 7.3 Balayage du préambule

Balayage initial (une trame par valeur, canal SPP 4, écart 1,5 s) :

| Préambule | Résultat |
|---:|---|
| 50 ms | échec |
| 80 ms | échec |
| 100 ms | OK |
| 150 ms | OK |
| 200 ms | OK |
| 250 ms | OK |
| 300 ms | OK |
| 400 ms | OK |
| 500 ms | échec (probablement un raté de re-déclenchement VOX) |

### 7.4 Fiabilité avec un écart de 4 s entre trames

L'écart long laisse le VOX retomber complètement. Le préambule doit alors être plus long.

| Préambule | TXTAIL | Réussite |
|---:|---:|---:|
| 100 ms | 20 | 1/10 (9/10 avec seulement 1,5 s d'écart) |
| 150 ms | 0 | 5/10 |
| 150 ms | 10 | 6/10 |
| 200 ms | 10 | 8/10 |
| **300 ms** | **10** | **10/10** |

Conclusion : avec un écart long entre les trames, **300 ms est fiable quand le VOX est chaud**. 150 ms est trop juste. Le TXTAIL à 0 n'améliore pas la fiabilité ; garder 10 (100 ms). Après un redémarrage du talkie, voir la section 7.7 : 400 ms est nécessaire.

### 7.5 Test final 300 ms

```text
19:42:13 RADIO KISS CONNECTED on channel 1
19:42:13 TX 1/10   → RX OK
19:42:19 TX 2/10   → RX OK
...
19:42:59 TX 10/10  → RX OK
--- RESULT: 10/10 OK at 300 ms ---
```

### 7.6 Validation de l'application Go

L'application Go a été testée avec `rfcomm://auto` (découverte du périphérique
**et** du canal) après un cycle ON/OFF de la radio :

```text
[KISS] Connecting to rfcomm://auto?channel=auto ...
[KISS] auto-selected 38:D2:00:AA:BB:CC (VR-N76)
[KISS] SPP channel 4
[KISS] Connected to rfcomm://auto?channel=auto
```

- `GET /api/status` : `{"addr":"rfcomm://auto?channel=auto","status":"connected"}`
- `sdptool search` a été utilisé pour trouver le canal 4 en quelques dizaines de
  millisecondes.
- Trois trames Direwolf ont été envoyées ; l'application en a reçu **2/3**
  (la première après un long repos a été perdue au réveil du VOX, pas à cause
  du Bluetooth) :

```text
[PKT #1] F4XXX-15  F4XXX-15>APRS  >DIREWOLF TX TEST -> VR-N76 - ignore
[PKT #2] F4XXX-15  F4XXX-15>APRS  >DIREWOLF TX TEST -> VR-N76 - ignore
```

- `/api/packets` a bien renvoyé les paquets décodés (source `F4XXX-15`,
  destination `APRS`, type `status`).

La liaison Bluetooth est restée connectée pendant tout le test ; les pertes
éventuelles sont côté RF/VOX (premier paquet après un long idle).

### 7.7 Après redémarrage du talkie (20:04)

Le talkie a été redémarré. L'application Go a été relancée en `rfcomm://auto` :

```text
[KISS] auto-selected 38:D2:00:AA:BB:CC (VR-N76)
[KISS] SPP channel 1
[KISS] Connected to rfcomm://auto?channel=auto
```

Deux lots de 5 trames ont été envoyés, avec 4 s d'écart :

| Préambule | Réussite | Détail |
|---:|---:|---|
| 300 ms | **3/5** | 2/5, 4/5 et 5/5 reçues ; 1/5 et 3/5 perdues |
| **400 ms** | **5/5** | 1/5 à 5/5 reçues |

Exemples de paquets décodés par l'application :

```text
20:04:13 [PKT #1] F4XXX-15  F4XXX-15>APRS  >APP RETEST 2/5
20:04:22 [PKT #2] F4XXX-15  F4XXX-15>APRS  >APP RETEST 4/5
20:04:26 [PKT #3] F4XXX-15  F4XXX-15>APRS  >APP RETEST 5/5
20:05:01 [PKT #8] F4XXX-15  F4XXX-15>APRS  >APP RETEST400 5/5
```

Conclusion : après un redémarrage du talkie / VOX froid, **400 ms est le
préambule recommandé**. La liaison Bluetooth et la découverte automatique du
canal SPP sont restées stables.

---

## 8. Problèmes rencontrés et solutions

| Problème | Cause | Solution |
|---|---|---|
| Canal KISS 1 refusé | Profil audio/Headset Bluetooth actif | `[General] Disable=Headset` dans `/etc/bluetooth/input.conf`, redémarrer Bluetooth, ré-appairer |
| Canal RFCOMM introuvable | Canal SPP dynamique (1 ou 4) | `sdptool records` → `SPP Dev` → `Channel` |
| Radio quitte le mode KISS | La liaison RFCOMM se ferme | Garder le service connecté ou réactiver KISS |
| Aucune émission Baofeng | Mauvais câble audio / VOX trop haut | Câble 2 fiches 3,5 mm + 2,5 mm, VOX 10 |
| Direwolf s'arrête à chaque émission | Carte USB G430 déconnectée par EMI | Sortie ligne arrière de la carte mère, port USB direct, ferrite, baisse de puissance |
| `plughw:1,0` occupé | PipeWire | Utiliser `ADEVICE default` ou arrêter PipeWire/WirePlumber |
| Pas de son sur la sortie arrière | Port PipeWire/ALSA encore sur le casque façade | `pactl set-sink-port ... analog-output-lineout`, activer `Front Playback`, désactiver `Auto-Mute` |
| 100/150 ms non fiables | VOX redémarre à froid après un écart long | `TXDELAY 40` (400 ms) |
| 300 ms instable après redémarrage du talkie | VOX froid | `TXDELAY 40` (400 ms) |
| TXDELAY 300 invalide | Limite KISS de 255 | Utiliser 30 (300 ms) ou 40 (400 ms), pas 300 |
| Erreurs AGW sur le port 8000 | Client HTTP/OpenCode interroge le port AGW | Ignorer ou fermer le client ; le KISS est sur 8001 |

---

## 9. Configuration finale recommandée

### 9.1 Direwolf (`direwolf.conf`)

Sous `CHANNEL 0` :

```ini
ADEVICE  default
# 400 ms : recommandé après redémarrage du talkie / VOX froid
# 30 (300 ms) suffit quand le VOX est déjà chaud
TXDELAY  40
TXTAIL   10
```

`default` passe par PipeWire et utilise la sortie ligne arrière du PCH. Si PipeWire est arrêté, utiliser :

```ini
ADEVICE  plughw:1,0
```

Aucun PTT n'est configuré : le Baofeng est en VOX. Pour un usage régulier, prévoir un PTT filaire/CM108.

### 9.2 Bluetooth

```ini
# /etc/bluetooth/input.conf
[General]
Disable=Headset
```

### 9.3 VR-N76

- TNC Mode : **KISS**
- Digital Mode : **Enable**
- Tail Elimination : **OFF**
- HT APP du téléphone : **fermée**
- Rester sur l'écran KISS / garder la liaison ouverte

### 9.4 Application Direwolf API

```bash
go run . -kiss 'rfcomm://auto' -api :8080
```

Le canal SPP est découvert automatiquement via SDP. Pour le vérifier ou forcer
un canal :

```bash
sdptool search --bdaddr 38:D2:00:AA:BB:CC SP
# ou
go run . -kiss 'rfcomm://auto?channel=4' -api :8080
```

---

## 10. Limites et prochaines étapes

- **Canal SPP dynamique** : il est découvert automatiquement via SDP
  (`sdptool search`, puis `records` en secours). Si `sdptool` est absent ou
  échoue, l'application retombe sur le canal 1 ; `?channel=N` permet de forcer.
- **Premier paquet après un long repos** : il peut être perdu au réveil du VOX.
  Utiliser `TXDELAY 40` (400 ms) ou envoyer une trame de chauffe. 300 ms est
  suffisant quand le VOX est déjà chaud.
- **Réception via `default`** : le périphérique `default` de PipeWire utilise la source par défaut. Pour la réception du talkie, il faut que la source par défaut soit l'entrée audio réelle (PCH line-in/front mic ou G430), pas le monitor de la sortie.
- **VOX** : acceptable pour un test, mais moins fiable qu'un PTT filaire. Le TXDELAY de 400 ms est un compromis.
- **Windows** : non testé ici ; l'application supporte `serial:COMx` pour les ports COM Bluetooth.
- **Configuration permanente** : le test a utilisé `/tmp/opencode/direwolf-pch.conf`. Le `direwolf.conf` principal n'a pas encore été modifié.

---

## Annexe — commandes utiles

```bash
# État Bluetooth
bluetoothctl info 38:D2:00:AA:BB:CC

# Canal SPP
sdptool records 38:D2:00:AA:BB:CC

# Mixer PCH
amixer -c 1 contents

# Sortie PipeWire active
pactl list sinks | grep -E 'Port actif|Active Port|analog-output-'

# Test de réception KISS
# (script de test : connexion RFCOMM SPP + envoi KISS à Direwolf :8001)
```
