#!/usr/bin/env python
"""
Utilities for using M2Crypto SSL with DIRAC.
"""

from M2Crypto import SSL

from DIRAC.Core.Security import Locations
from DIRAC.Core.Security.m2crypto.X509Chain import X509Chain

# Default ciphers to use if unspecified
DEFAULT_SSL_CIPHERS = "ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:RSA+AESGCM:RSA+AES:!aNULL:!MD5:!DSS"
# Verify depth of peer certs
VERIFY_DEPTH = 50

# TODO: Error handling in Context config functions...
def __loadM2SSLCTXHostcert(ctx):
  certKeyTuple = Locations.getHostCertificateAndKeyLocation()
  ctx.load_cert(certKeyTuple[0], certKeyTuple[1], callback=lambda: "")

def __loadM2SSLCTXProxy(ctx, proxyPath=None):
  if not proxyPath:
    proxyPath = Locations.getProxyLocation()
  ctx.load_cert_chain(proxyPath, proxyPath, callback=lambda: "")

def __loadM2SSLCTXProxyStr(ctx, proxy):
  pass

def getM2SSLContext(**kwargs):
  """ Gets an M2Crypto.SSL.Context configured using the standard
      DIRAC connection keywords from kwargs. The known keywords
      are: TODO TODO TODO
      Returns the new context.
  """
  # TODO: Session support
  print kwargs
  ctx = SSL.Context()

  # Set certificates for connection
  if kwargs.get('clientMode', False):
    # Client mode has a choice of possible options
    if kwargs.get('useCertificates', False):
      # Use hostcert
      __loadM2SSLCTXHostcert(ctx)
    elif kwargs.get('proxyString', None):
      # Use literal proxy
      __loadM2SSLCTXProxy(ctx, kwargs['proxyString'])
    else:
      # Use normal proxy
      __loadM2SSLCTXProxy(ctx, proxyPath=kwargs.get('proxyLocation', None))
  else:
    # Server mode always uses hostcert
    __loadM2SSLCTXHostcert(ctx)

  # Set peer verification
  if kwargs.get('skipCACheck', False):
    # Don't validate peer, but still request creds
    ctx.set_verify(SSL.verify_fail_if_no_peer_cert, VERIFY_DEPTH)
  else:
    # Do validate peer
    ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert, VERIFY_DEPTH)
    # Set CA location
    caPath = Locations.getCAsLocation()
    # TODO: Check for missing caPath here
    ctx.load_verify_locations(capath=caPath)

  # Other parameters
  # TODO: sslMethod
  #sslMethod = kwargs.get('sslMethod', "ALL"):
  ciphers = kwargs.get('sslCiphers', DEFAULT_SSL_CIPHERS)
  ctx.set_cipher_list(ciphers)
  return ctx

def getM2PeerInfo(conn):
  """ Gets the details of the current peer as a standard dict. The peer
      details are obtained from the supplied M2 SSL Connection obj "conn".
      The details returned are:
         DN - Full peer DN as string
         CN - The CN part of the DN as string (without CN= prefix)
         x509Chain - Full chain of peer
         isProxy - Boolean, True if chain ends with proxy
         isLimitedProxy - Boolean, True if chain ends with limited proxy
         group - String, DIRAC group for this peer, if known
      Returns a dict of details.
  """
  chain = X509Chain.generateX509ChainFromSSLConnection(conn)
  creds = chain.getCredentials()
  peer = {}
  # TODO: Check DIRAC OK of creds & sub-calls
  peer['DN'] = creds['Value']['identity']
  peer['x509Chain'] = chain
  peer['isProxy'] = chain.isProxy()['Value']
  peer['isLimitedProxy'] = chain.isLimitedProxy()['Value']
  return peer

