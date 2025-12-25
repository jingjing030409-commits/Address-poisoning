# ETH Address Poisoning Tool

A full python tool for simulating Ethereum address poisoning attacks for educational and security research purposes. This tool generates vanity addresses that mimic a target address and sends nominal transactions to execute the poisoning of a user's transaction history.

---

![image](https://i.imgur.com/83SZusC.png)

## ⚠️ Disclaimer: For Ethical and Educational Use Only

This tool is intended strictly for educational purposes and authorized security research. Misusing this tool to deceive or harm others can result in significant financial loss and is illegal.

-   **Do not use this tool against any address or entity without their explicit, written consent.**
-   The developers assume no liability and are not responsible for any misuse or damage caused by this tool. By using this software, you agree to use it lawfully and ethically.

---

## Table of Contents

-   [How It Works](#how-it-works)
-   [Getting Started](#getting-started)
-   [Usage](#usage)
-   [Contributing](#contributing)

---

## How It Works

This tool automates the address poisoning for security testing:

1.  **Scan:** The tool scan the network for USDT transfers.
2.  **Vanity Address Generation:** The tool generates addresses that match a specified number of prefix and suffix characters of the target address.
3.  **Transaction Simulation:** Using a provided RPC endpoint and private key, the tool sends a configurable, near-zero value transaction from each generated vanity address to the target address.
4.  **Logging:** The tool outputs the generated addresses and corresponding transaction hashes for analysis.

---

## Getting Started

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/1652933138/eth-address-poisoning-tool.git
    cd eth-address-poisoning-tool
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Configure the tool:**
    Rename `env.example` to `.env` and edit it with your RPC URL, private key, and default transaction value.

---

## Usage

```bash
py poison.py
```


## Contributing

Contributions are welcome. Please fork the repository, create a feature branch, and open a pull request with a clear description of your changes.

---
