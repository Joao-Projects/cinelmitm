## 🛠️ CINELMITM - Canivete suiço p/ pentesting

> [!TIP]
> **Utilização:** `python cinelmitm.py -h`

> [!IMPORTANT]
> Antes de utilizar, instale os requisitos necessários:
> 1. `python3 -m venv .venv`
> 2. `source .venv/bin/activate`
> 3. `pip install -r requirements.txt`

---

### 📑 Histórico de Versões

<details open>
<summary><b>v1.1 - Atual (20/04/26)</b></summary>

- [x] Implementado DNS Spoofing (Cache poisoning).
- [ ] **TO DO:** Corrigir *Race Condition* nos pacotes ARP (enviar apenas após ARP Request).
  
*Responsável: João Alonso*
</details>

<details>
<summary><b>v1.0 - Inicial (10/09/24)</b></summary>

- [ ] Analisador de pacotes HTTP / DNS.
- [ ] DNS Spoofing (injeção).
- [ ] ICMP Spoofing (redirect).
- [ ] **TO DO:** Melhorar descodificação ASN.1 LDAP (Trocar biblioteca).

*Responsável: João Alonso*
</details>

### 🚀 Roadmap (Futuro)
- [ ] DHCP Starvation & Rogue DHCP Server.
- [ ] Rogue HTTP/S Server (Phishing/Payloads).
- [ ] SMB over HTTP (NTLM Relaying).
- [ ] VLAN Hopping & STP MiTM.

---

> [!NOTE]
> Esta ferramenta foi desenvolvida inicialmente em Windows, mas o foco atual é Linux. Algumas funcionalidades de injeção de pacotes podem não funcionar corretamente em Windows.
