
## CINELMITM - Canivete suiço p/ pentesting

> [!TIP]
_Utilização: python cinelmitm -h_

> [!IMPORTANT]
Antes de a utilizar, instalar os requisitos necessários (requirements.txt). Isso pode ser feito da seguinte forma:


**1. Criar ambiente virtual:**
   
	$ python3 -m venv .venv

**3. Ativar/Desativar o ambiente virtual:**
   
	$ source .venv/bin/activate

	$ deactivate
	
**5. instalar os requisitos:**
   
	$ python -m pip install -r requirements.txt

**7. executar o cinelmitm:**
   
	$ python3 cinelmitm.py

### Versões


**v1.0:**
- Por implementar:
   - analisador de pacotes HTTP
   - analisador de pacotes DNS 
   - DNS Spoofing (injeção de pacotes DNS modificados)
   - ICMP Spoofing (redirect)
   - Melhor descodificação das sequencias ASN.1 LDAP (bug. necessário outra livraria)

   João Alonso @10/09/24
   

**v1.1:**
   - implementado DNS Spoofing (Cache poisoning)
     
   - TO DO: Existe uma Race Condition porque estão a ser enviados ARP reply automaticos a cada 30s aproximadamente, independentemente de existir um ARP request ou não.
   		- Solução (por implementar): monitorizar os ARP request e enviar apenas quando observado o pedido.

   João Alonso @20/04/26
   
- Possíveis implementações futuras:
   - dhcp starvation e rouge dhcp server para injeção de leases com gw/dns evenenados
   - rouge/built-in http/s server para injeção de payloads / (spear) phishing
   - smb over http para ntlm relaying
   - vlan hoping/sniffing
   - STP mitm


> [!NOTE]
 _Esta ferramenta foi desenvolvida inicialmente em Windows tendo acabado por lhe dar seguimento em Linux, pelo que nem todo o código (especialmente a parte de injeção de pacotes) poderá funcionar corretamente se executado em Windows._
 
