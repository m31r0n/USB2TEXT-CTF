# USB2TEXT 🐍

A simple USB-HID keystroke decoder for CTF forensics.  
Automatically extracts and decodes HID reports from `.pcap`/`.pcapng` (via `tshark`) or raw hex.

---

## 🔧 Features

- **Auto-detect HID field** (`usbhid.data`, `usb.capdata`, or `hid.data`)
- **Supports** Shift, Caps-Lock and Backspace
- **Two views**:  
  1. Raw text with explicit `[CAPS]` markers  
  2. Final resolved text with correct casing
- **CLI-only**, no GUI dependencies

---

## ⚙️ Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/m31r0n/USB2TEXT-CTF.git
   cd USB2TEXT-CTF
   ```
2. Ensure you have:
   - Python 3.6+  
   - `tshark` (Wireshark CLI) in your `PATH`

---

## 🚀 Usage

```bash
# decode a pcapng
python3 usb2text.py <file>.pcapng

# decode raw hex from stdin
tshark -r <file>.pcapng -Y usb.transfer_type==1 -T fields -e usbhid.data \
  | python3 usb2text.py -

# save resolved text to file
python3 usb2text.py -o output.txt <file>.pcapng
```

Sample output:

```
[+] Starting: <file>.pcapng
[+] Using HID field: usbhid.data
[+] Completed processing 181 packets.

=== HID with [CAPS] Markers ===

root
[CAPS]welcome123
ls -la
curl -ks https;//root;[CAPS]welcome1232intranet/secret.zip
unzip secret.zip
[CAPS]pyj4m4[CAPS]p4rt[CAPS]y22017
cat secret.txt
display hamburg	
logout


=== Resolved Text ===

root
Welcome123
ls -la
curl -ks https://root:Welcome123@XXXXX/secret.zip
unzip secret.zip
Pyj4m4P4rtY@2017
cat secret.txt
display hamburg	
logout

```

---

## 📄 License

MIT
