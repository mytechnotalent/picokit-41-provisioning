![picokit-41-provisioning](https://raw.githubusercontent.com/mytechnotalent/picokit-41-provisioning/main/picokit-41-provisioning.png)

<br>

## FREE Reverse Engineering Self-Study Course [HERE](https://github.com/mytechnotalent/reverse-engineering)
## FREE Embedded Hacking Course [HERE](https://github.com/mytechnotalent/Embedded-Hacking)

<br>

# PICOKIT-41 PROVISIONING

### Per-Device Key from a Device ID and Salt, Two Keys Proven Different
#### Lesson 41 of the Picokit Series

<br>

***
**LEGAL DISCLAIMER:**
The information, tools, and code provided in this repository and course are strictly for educational, research, and defensive purposes only.

You are explicitly prohibited from using any materials contained herein to access, test, modify, or exploit any device, network, or system that you do not own 100% or for which you do not have explicit, documented, and legally binding authorization to interact with.

By using this repository and course, you acknowledge and agree that:

1. Any illegal, unauthorized, or malicious use of this information is solely your responsibility.
2. The author(s) and contributor(s) of this repository and course shall not be held liable for any damages, legal repercussions, criminal charges, or unauthorized actions resulting from the use, misuse, or abuse of the contents herein.
3. You will comply with all applicable local, state, national, and international laws regarding cybersecurity and computer fraud.

**IF YOU DO NOT AGREE WITH THESE TERMS, DO NOT USE THIS REPOSITORY AND COURSE.**
***

<br>
<br>

## Overview

The forty-first Picokit lesson. The node derives a per-device key from the
device identity and a salt, instead of relying on one shared key. On each
heartbeat it derives its own key, derives the key a neighbouring device id would
produce, and proves the two keys are different. The authenticated heartbeat
reports the device identity.

<br>

## What it teaches

- Binding a device identity into the Argon2id salt.
- Deriving a per-device key from the identity and the bound salt.
- Proving that two device ids produce two different keys.
- Reporting the provisioned device id in the authenticated heartbeat.

<br>

## Hardware

| Peripheral | Pico 2 pin | Role |
| --- | --- | --- |
| Red / Yellow / Green | GP16 / GP18 / GP17 | annunciator status |
| Onboard LED | GP25 | heartbeat, one blink per transmit |
| RYLR998 | GP8 TX / GP9 RX | LoRa heartbeat |
| Debug Probe | SWCLK/SWDIO/GND, GP0/GP1 | SWD and the console |

<br>

## How it works

The node runs `monitor_step` in a loop. Every 5 seconds it derives the key for
its own device id, derives the key for the next device id, and confirms they
differ. The heartbeat body `{"n":41,"s":<seq>,"d":<device id>}` is sealed with
the shared field key and sent over LoRa.

<br>

## Build and flash

```bash
cd firmware
cmake -S . -B build -G Ninja -DPICO_BOARD=pico2 -DPICO_PLATFORM=rp2350-arm-s
cmake --build build
openocd -f interface/cmsis-dap.cfg -f target/rp2350.cfg \
  -c "program build/picokit_41_provisioning.elf verify reset exit"
```

<br>

## Watch the node

Open the console at 115200 and reset:

```text
BOOT
=== PICOKIT-41 PROVISIONING // PER-DEVICE KEY + SALT ===
PROVISION d=41 distinct=1 seq=1
PROVISION d=41 distinct=1 seq=2
RX from 0x0001, N bytes
```

<br>

## The gateway

```bash
cd gateway
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 listen.py --port /dev/cu.usbserial-A50285BI --hub 0001 --network 18 --db gateway.db
```

It prints `OK node=41 rssi=...` per authenticated heartbeat. The terminal
dashboard `python3 tui.py --db gateway.db` and the web dashboard
`python3 web/app.py --db gateway.db` show the same rows.

<br>

## Verify

```bash
python3 .opencode/skill/embedded-c-standard/audit_c_standard.py
python3 .opencode/skill/embedded-python-standard/audit_python_standard.py
python3 .opencode/skill/iot-readme-standard/validate_readme.py
python3 .opencode/skill/iot-banner-standard/validate_banner.py
python3 scripts/run_tests.py
python3 scripts/check_coverage.py
```

<br>

# Next
[picokit-42-tamper-log](https://github.com/mytechnotalent/picokit-42-tamper-log)

<br>

# License
[MIT License](https://github.com/mytechnotalent/picokit-41-provisioning/blob/main/LICENSE)
