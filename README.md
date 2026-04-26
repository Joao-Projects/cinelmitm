
┌────────────────────────────┐

│ cinelmitm v1.1 - canivete suiço p/ pentesting  │

└────────────────────────────┘

Utilização: python cinelmitm -h

- Nota: Esta ferramenta foi desenvolvida inicialmente em Windows tendo acabado por lhe dar seguimento em Linux, pelo que nem todo o código (especialmente a parte de injeção de pacotes) poderá funcionar corretamente se executado em Windows.

 - Importante: Antes de a utilizar, instalar os requisitos necessários (requirements.txt). Isso pode ser feito da seguinte forma:


1. Criar ambiente virtual

	$ python3 -m venv .venv

2. Ativar/Desativar o ambiente virtual

	$ source .venv/bin/activate
	
	$ deactivate
	
3. instalar os requisitos

	$ python -m pip install -r requirements.txt

4. executar o cinelmitm

	$ python3 cinelmitm.py

v1.0:
- Por implementar:
   - analisador de pacotes HTTP
   - analisador de pacotes DNS 
   - DNS Spoofing (injeção de pacotes DNS modificados)
   - ICMP Spoofing (redirect)
   - Melhor descodificação das sequencias ASN.1 LDAP (bug. necessário outra livraria)

   João Alonso @10/09/24
   

v1.1: 
   - implementando DNS Spoofing (Cache poisoning)
   
   João Alonso @22/10/24
   
- TO DO
  - Race Condition: está a ser enviado ARP reply automatico a cada 30s aproximadamente, independentemente do ARP request existir ou não.
     Solução (por implementar): monitorizar os ARP request e enviar apenas quando observado o pedido.

- Possíveis implementações futuras:
   - dhcp starvation e rouge dhcp server para injeção de leases com gw/dns evenenados
   - rouge/built-in http/s server para injeção de payloads / (spear) phishing
   - smb over http para ntlm relaying
   - vlan hoping/sniffing
   - STP mitm
 
