#!/usr/bin/env python3
import ssl
import socket
from OpenSSL import SSL
from typing import Dict
from scanner.config import Config

def test_tls1_3(domain: str) -> bool:
    try:
        ctx = SSL.Context(SSL.TLS_METHOD)
        ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
        ctx.set_max_proto_version(SSL.TLS1_3_VERSION)
        conn = SSL.Connection(ctx, socket.create_connection((domain, 443)))
        conn.set_connect_state()
        conn.set_tlsext_host_name(domain.encode('utf-8'))
        
        try:
            conn.do_handshake()
            conn.close()
            return True
        except:
            conn.close()
            return False
    except:
        return False

def test_tls1_2(domain: str) -> bool:
    try:
        ctx = SSL.Context(SSL.TLS_METHOD)
        ctx.set_min_proto_version(SSL.TLS1_2_VERSION)
        ctx.set_max_proto_version(SSL.TLS1_2_VERSION)
        conn = SSL.Connection(ctx, socket.create_connection((domain, 443)))
        conn.set_connect_state()
        conn.set_tlsext_host_name(domain.encode('utf-8'))
        
        try:
            conn.do_handshake()
            conn.close()
            return True
        except:
            conn.close()
            return False
    except:
        return False

def test_tls1_1(domain: str) -> bool:
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
        conn = socket.create_connection((domain, 443))
        
        try:
            SSLsock = context.wrap_socket(conn, server_hostname=domain)
            SSLsock.do_handshake()
            SSLsock.close()
            conn.close()
            return True
        except:
            conn.close()
            return False
    except:
        return False

def test_tls1_0(domain: str) -> bool:
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        conn = socket.create_connection((domain, 443))
        
        try:
            SSLsock = context.wrap_socket(conn, server_hostname=domain)
            SSLsock.do_handshake()
            SSLsock.close()
            conn.close()
            return True
        except:
            conn.close()
            return False
    except:
        return False

def aggregate_tls_stats(results: Dict) -> Dict:
    stats = {
        'tls1_3': {'supported': 0, 'unsupported': 0},
        'tls1_2': {'supported': 0, 'unsupported': 0},
        'tls1_1': {'supported': 0, 'unsupported': 0},
        'tls1_0': {'supported': 0, 'unsupported': 0},
        'total': len(results)
    }
    
    for domain, data in results.items():
        for version in ['tls1_3', 'tls1_2', 'tls1_1', 'tls1_0']:
            if data.get(version):
                stats[version]['supported'] += 1
            else:
                stats[version]['unsupported'] += 1
    
    return stats