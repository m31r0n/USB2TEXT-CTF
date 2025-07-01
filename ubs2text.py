#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
usb2text.py – Decode USB HID keystrokes from pcap/pcapng or raw hex; automatically detect the HID data field.

USAGE:
  usb2text.py [-h] [-o OUTPUT] INPUT

INPUT can be:
  • Path to a .pcap/.pcapng (invokes tshark under the hood)
  • Path to a .txt file with raw hex data
  • “-” to read raw hex from stdin

EXAMPLES:
  usb2text.py capture.pcapng
  usb2text.py -o keys.txt capture.pcap
  tshark -r capture.pcap -Y usb.interrupt -T fields -e usbhid.data \
    | usb2text.py -
"""

import sys
import subprocess
import shutil
from pathlib import Path
import argparse

# Possible tshark fields that may contain HID payloads
POSSIBLE_FIELDS = ['usbhid.data', 'usb.capdata', 'hid.data']

# HID usage code to character mapping: [without-shift, with-shift]
KEY_CODES = {
    0x04:['a','A'],0x05:['b','B'],0x06:['c','C'],0x07:['d','D'],0x08:['e','E'],0x09:['f','F'],
    0x0A:['g','G'],0x0B:['h','H'],0x0C:['i','I'],0x0D:['j','J'],0x0E:['k','K'],0x0F:['l','L'],
    0x10:['m','M'],0x11:['n','N'],0x12:['o','O'],0x13:['p','P'],0x14:['q','Q'],0x15:['r','R'],
    0x16:['s','S'],0x17:['t','T'],0x18:['u','U'],0x19:['v','V'],0x1A:['w','W'],0x1B:['x','X'],
    0x1C:['y','Y'],0x1D:['z','Z'],0x1E:['1','!'],0x1F:['2','@'],0x20:['3','#'],0x21:['4','$'],
    0x22:['5','%'],0x23:['6','^'],0x24:['7','&'],0x25:['8','*'],0x26:['9','('],0x27:['0',')'],
    0x28:['\n','\n'],0x2B:['\t','\t'],0x2C:[' ',' '],0x2D:['-','_'],0x2E:['=','+'],
    0x2F:['[','{'],0x30:[']','}'],0x31:['\\','|'],0x32:['#','~'],0x33:[';',':'],
    0x34:["'",'"'],0x36:[',','<'],0x37:['.','>'],0x38:['/','?']
}

BACKSPACE   = 0x2A
CAPS_TOGGLE = 0x39
SHIFT_MASK  = 0x22  # Left-Shift (0x02) or Right-Shift (0x20)

# ----------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(description='Decode USB HID keystrokes')
    parser.add_argument('input', help='pcap/pcapng, txt, or "-" for stdin')
    parser.add_argument('-o','--output', type=Path, help='Save resolved text to a file')
    return parser.parse_args()

# ----------------------------------------------------------------------------

def detect_hid_field(pcap_path: Path) -> str:
    """Automatically detect which tshark field contains the HID data."""
    for fld in POSSIBLE_FIELDS:
        cmd = ['tshark', '-r', str(pcap_path), '-Y', f'usb.transfer_type==1 && {fld}', '-T', 'fields', '-e', fld]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        # skip lines that are just zeros or empty
        if any(line.strip('0:') for line in res.stdout.splitlines() if line):
            print(f"[+] Using HID field: {fld}", file=sys.stderr)
            return fld
    sys.exit('ERROR: No HID data field detected in the capture.')

# ----------------------------------------------------------------------------

def stream_from_tshark(pcap_path: Path, field: str):
    """Spawn tshark to stream HID data for each USB interrupt packet."""
    if not shutil.which('tshark'):
        sys.exit('ERROR: tshark not found in $PATH')
    cmd = ['tshark', '-r', str(pcap_path), '-Y', f'usb.transfer_type==1 && {field}', '-T', 'fields', '-e', field]
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1).stdout

# ----------------------------------------------------------------------------

def line_source(source: str, field: str):
    """Yield raw hex strings either from stdin, a pcap via tshark, or a text file."""
    if source == '-':
        yield from (line.strip() for line in sys.stdin if line.strip())
    else:
        p = Path(source)
        if not p.exists():
            sys.exit(f"ERROR: '{source}' not found")
        if p.suffix.lower() in ('.pcap', '.pcapng'):
            yield from (line.strip() for line in stream_from_tshark(p, field) if line.strip())
        else:
            with p.open('r', encoding='utf-8', errors='ignore') as f:
                yield from (line.strip() for line in f if line.strip())

# ----------------------------------------------------------------------------

def split_bytes(h: str):
    """Split a hex string into individual byte strings."""
    return h.split(':') if ':' in h else [h[i:i+2] for i in range(0, len(h), 2)]

# ----------------------------------------------------------------------------

def decode(lines):
    """Decode HID reports into two outputs: markers and resolved text."""
    hid_marked = []  # with [CAPS] markers
    resolved   = []  # final text with correct case
    caps_lock  = False
    prev_keys  = set()
    count      = 0

    for rep in lines:
        count += 1
        if count % 1000 == 0:
            print(f"[+] Processed {count} packets...", file=sys.stderr)

        parts = split_bytes(rep)
        if len(parts) < 3:
            continue
        try:
            mod = int(parts[0], 16)
            keys = [int(b, 16) for b in parts[2:8] if b and b != '00']
        except ValueError:
            continue

        curr_keys = set(keys)
        new_keys  = curr_keys - prev_keys
        prev_keys = curr_keys

        for code in new_keys:
            if code == CAPS_TOGGLE:
                caps_lock = not caps_lock
                continue
            if code == BACKSPACE:
                if hid_marked: hid_marked.pop()
                if resolved:   resolved.pop()
                continue

            base, shift_char = KEY_CODES.get(code, ('', ''))
            if not base:
                continue

            shift_active = bool(mod & SHIFT_MASK)
            if base.isalpha():
                effective = shift_active ^ caps_lock
            else:
                effective = shift_active

            char = shift_char if effective else base
            if effective and base.isalpha():
                hid_marked.extend(['[CAPS]', base])
            else:
                hid_marked.append(base)
            resolved.append(char)

    print(f"[+] Completed processing {count} packets.", file=sys.stderr)
    return ''.join(hid_marked), ''.join(resolved)

# ----------------------------------------------------------------------------

def main():
    args = parse_args()
    print(f"[+] Starting: {args.input}", file=sys.stderr)

    field = None
    if args.input != '-':
        p = Path(args.input)
        if p.suffix.lower() in ('.pcap', '.pcapng'):
            field = detect_hid_field(p)

    marked, text = decode(line_source(args.input, field))

    print("\n=== HID with [CAPS] Markers ===\n")
    print(marked)
    print("\n=== Resolved Text ===\n")
    print(text)

    if args.output:
        try:
            args.output.write_text(text + '\n', encoding='utf-8')
            print(f"[+] Saved to {args.output}", file=sys.stderr)
        except Exception as e:
            sys.exit(f"ERROR writing {args.output}: {e}")

if __name__ == '__main__':
    main()
