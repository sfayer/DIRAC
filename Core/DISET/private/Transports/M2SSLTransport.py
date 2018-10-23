#!/usr/bin/env python
"""
M2Crypto SSLTransport Library
"""

__RCSID__ = "$Id$"

import os
from M2Crypto import SSL, threading as M2Threading

from DIRAC.Core.Security import Locations
from DIRAC.Core.Utilities.ReturnValues import S_ERROR, S_OK
from DIRAC.Core.Security.m2crypto.X509Chain import X509Chain
from DIRAC.Core.DISET.private.Transports.BaseTransport import BaseTransport
from DIRAC.Core.DISET.private.Transports.SSL.M2Utils import getM2SSLContext, getM2PeerInfo

# For now we have to set an environment variable for proxy support in OpenSSL
# Eventually we may need to add API support for this to M2Crypto...
# TODO: Fix this properly
os.environ['OPENSSL_ALLOW_PROXY_CERTS'] = '1'
M2Threading.init()

# TODO: CRL checking, another item that will need support in M2Crypto to work
# properly. This probably involves mapping quite a few functions through.


class SSLTransport(BaseTransport):
  """ SSL Transport implementaiton using the M2Crypto library. """

  def __init__(self, *args, **kwargs):
    self.remoteAddress = None
    self.peerCredentials = {}
    self.__timeout = 1
    self.__ctx = getM2SSLContext(**kwargs)
    BaseTransport.__init__(self, *args, **kwargs)

  def setSocketTimeout(self, timeout):
    self.__timeout = timeout

  def initAsClient(self):
    if self.serverMode():
      raise RuntimeError("SSLTransport is in server mode.")
    self.oSocket = SSL.Connection(self.__ctx)
    self.oSocket.connect(self.stServerAddress)
    self.remoteAddress = self.oSocket.getpeername()
    return S_OK()

  def initAsServer(self):
    if not self.serverMode():
      raise RuntimeError("SSLTransport is in client mode.")
    self.oSocket = SSL.Connection(self.__ctx)
    # TODO: Process bAllowReuseAddress here!
    self.oSocket.bind(self.stServerAddress)
    self.oSocket.listen(self.iListenQueueSize)
    return S_OK()


  def close(self):
    if self.oSocket:
      self.oSocket.close()
      self.oSocket = None
    return S_OK()

  def renewServerContext(self):
    if not self.serverMode():
      raise RuntimeError("SSLTransport is in client mode.")
    # TODO: Renew context or something here!
    return S_OK()

  def handshake(self):
    # This isn't used any more, the handshake is done inside the M2Crypto library
    return S_OK()

  def setClientSocket(self, oSocket):
    if self.serverMode():
      raise RuntimeError("SSLTransport is in server mode.")
    self.oSocket = oSocket
    self.remoteAddress = self.oSocket.getpeername()
    self.peerCredentials = getM2PeerInfo(self.oSocket)

  def acceptConnection(self):
    oClient, _ = self.oSocket.accept()
    oClientTrans = SSLTransport(self.stServerAddress)
    oClientTrans.setClientSocket(oClient)
    return S_OK(oClientTrans)
 
  def _read(self, bufSize=4096, skipReadyCheck=False):
    return S_OK(self.oSocket.read(bufSize))

  def isLocked(self):
    return False

  def _write(self, bufOut):
    return S_OK(self.oSocket.write(bufOut))

def checkSanity(urlTuple, kwargs):
  pass

def delegate(delegationRequest, kwargs):
  pass

