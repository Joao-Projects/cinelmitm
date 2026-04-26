from pyasn1.codec.ber import decoder
from ldap3.protocol.rfc4511 import LDAPMessage

# Interpreta os pacotes de rede LDAP com base nas specs ASN.1
# https://cwiki.apache.org/confluence/display/DIRxSRVx10/Ldap+ASN.1+Codec

BLUE = '\033[0;38;5;12m'
ORANGE = '\033[0;38;5;214m'
RESET = '\033[0m'
RED = '\033[1;31m'


def ldap_parser(ldap_data):

    # Decode da msg
    ldap_message, _ = decoder.decode(ldap_data, asn1Spec=LDAPMessage())

    # localiza o bind request dentro da msg ldap
    bind_request = ldap_message['protocolOp'].getComponentByName('bindRequest')

    # extração de alguns campos
    name = bind_request['name'].asOctets()  # Converte para binário para à posteriori converter em utf-8.
    authentication = bind_request['authentication']

    # Se possivel, descodifica em UTF-8
    try:
        name_str = name.decode('utf-8')
    except UnicodeDecodeError:
        name_str = name.hex()  # Em caso de falha, imprime em hex.

    # Deteção do tipo de autenticação
    auth_type = authentication.getName()
    if auth_type == 'simple':
        try:
            credentials = str(authentication['simple'])
        except UnicodeDecodeError:
            credentials = authentication['simple'].asOctets().hex()

        print(f"{ORANGE}[*]{ORANGE} Autenticação LDAP Simples interceptada!{RESET}")
        print(f"{ORANGE}[*]{RED} Utilizador:{RESET} {name_str}")
        print(f"{ORANGE}[*]{RED} Palavra-passe:{RESET} {credentials}")

    # TODO Melhorar a descodificaçao da sequencia ASN.1 LDAP, via outra livraria.
    # Bug: esta livraria ldap3.protocol.rfc4511 não está a interpretar corretamente as
    # msgs ldap codificadas em ASN.1, pelo que não se consegue descodificar corretamente
    # a parte do Bind Request. Necessito de procurar por outra livraria que implemente melhor o RFC4511.
    '''
    elif (auth_type == 'sasl'):
        sasl_mech = authentication['sasl']['mechanism']
        sasl_creds = authentication['sasl']['credentials'].asOctets().hex()  # Bug

        print(f"Autenticação: SASL | Mecanismo: {sasl_mech}")
        print(f"Utilizador: {name_str}")
        print(f"Token: {sasl_creds}")
    '''