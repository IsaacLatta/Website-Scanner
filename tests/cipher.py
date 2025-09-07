#!/usr/bin/env python3
import socket
from OpenSSL import SSL
from typing import Dict, Optional
from config import Config

def test_normal_handshake(domain: str) -> str:
    security = "error"
    try:
        ctx = SSL.Context(SSL.TLS_METHOD)
        conn = SSL.Connection(ctx, socket.create_connection((domain, 443)))
        conn.set_connect_state()
        conn.set_tlsext_host_name(domain.encode('utf-8'))
        conn.do_handshake()
        
        cipher_name = conn.get_cipher_name()
        
        if Config.CIPHERSUITES:
            for suite_data in Config.CIPHERSUITES:
                for key, value in suite_data.items():
                    if value.get("openssl_name") == cipher_name or key == cipher_name:
                        security = value.get('security', 'unknown')
                        break
        
        conn.close()
    except Exception as e:
        print(f"  Error in normal handshake for {domain}: {e}")
    
    return security

def test_sha1_support(domain: str) -> bool:
    try:
        ctx = SSL.Context(SSL.TLS_METHOD)
        ctx.set_min_proto_version(SSL.TLS1_2_VERSION)
        ctx.set_max_proto_version(SSL.TLS1_2_VERSION)
        ctx.set_cipher_list(b"SHA1")
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

def test_cbc_support(domain: str) -> bool:
    try:
        ctx = SSL.Context(SSL.TLS_METHOD)
        ctx.set_min_proto_version(SSL.TLS1_2_VERSION)
        ctx.set_max_proto_version(SSL.TLS1_2_VERSION)
        ctx.set_cipher_list(b"CBC")
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

def aggregate_cipher_stats(results: Dict) -> Dict:
    stats = {
        'cipher_security': {
            'recommended': 0,
            'secure': 0,
            'weak': 0,
            'insecure': 0,
            'error': 0
        },
        'sha1_support': {'yes': 0, 'no': 0},
        'cbc_support': {'yes': 0, 'no': 0},
        'total': len(results)
    }
    
    for domain, data in results.items():
        security = data.get('normal_handshake', 'error')
        if security == 'recommended':
            stats['cipher_security']['recommended'] += 1
        elif security == 'secure':
            stats['cipher_security']['secure'] += 1
        elif security == 'weak':
            stats['cipher_security']['weak'] += 1
        elif security == 'insecure':
            stats['cipher_security']['insecure'] += 1
        else:
            stats['cipher_security']['error'] += 1
        
        if data.get('sha1_support'):
            stats['sha1_support']['yes'] += 1
        else:
            stats['sha1_support']['no'] += 1
        
        if data.get('cbc_support'):
            stats['cbc_support']['yes'] += 1
        else:
            stats['cbc_support']['no'] += 1
    
    return stats
