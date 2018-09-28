# $HeadURL$
__RCSID__ = "$Id$"

import errno
import time
import copy
import os
import os.path
import socket
import tempfile
from DIRAC.Core.Utilities.ReturnValues import S_ERROR, S_OK
from DIRAC.Core.Utilities.Network import checkHostsMatch
from DIRAC.Core.Utilities.LockRing import LockRing
from DIRAC.FrameworkSystem.Client.Logger import gLogger
from DIRAC.Core.Security import Locations


# import GSI
import M2Crypto
from M2Crypto import m2, SSL, Err


from DIRAC.Core.Security.m2crypto.X509Chain import X509Chain
from DIRAC.Core.Security.m2crypto.X509Certificate import X509Certificate
from DIRAC.Core.Security.m2crypto.X509CRL import X509CRL

DEFAULT_SSL_CIPHERS = "ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+3DES:!aNULL:!MD5:!DSS"

VERIFY_DEPTH = 50  # isn't it A BIT too deep?


class SocketInfo:

  __cachedCAsCRLs = False  # Contains the X509 CA store
  __cachedCAsCRLsLastLoaded = 0  # Contains the epoch timestamp of the last load
  __cachedCAsCRLsLoadLock = LockRing().getLock()  # lock to protect the __cachedCAsCRLs

  def __init__(self, infoDict, sslContext=None):
    """ C'tor
        Create the SSL Context

        :param infoDict: socket and connection options
                * clientMode: boolean. If True, we act as a client, else as a server
                * useCertificates: boolean. If true and clientMode true, use the host certificates
                * proxyString: proxy pem string. If set and clientMode true, use that to establish the connection
                * proxyLocation: path. If set and clientMode true, use the proxy at the given path
        :param sslContext: use this sslContext if given as parameter, otherwise
                          constructs it from the info in infoDict

    """

    self.__retry = 0
    self.infoDict = infoDict

    if sslContext:
      self.sslContext = sslContext
    else:
      if self.infoDict['clientMode']:
        if self.infoDict.get('useCertificates'):
          retVal = self.__generateContextWithCerts()
        elif self.infoDict.get('proxyString'):
          retVal = self.__generateContextWithProxyString()
        else:
          retVal = self.__generateContextWithProxy()
      else:
        retVal = self.__generateServerContext()
      if not retVal['OK']:
        raise Exception(retVal['Message'])

  def getLocalCredentialsLocation(self):
    """ Get the local cedentials location
        :returns: tuple (cert path, key path)
    """

    return self.infoDict['localCredentialsLocation']

  def gatherPeerCredentials(self):
    """ This returns the credentials of the remote peer

    """

    peerChain = X509Chain.generateX509ChainFromSSLConnection(self.sslSocket)
    isProxyChain = peerChain.isProxy()['Value']
    isLimitedProxyChain = peerChain.isLimitedProxy()['Value']
    if isProxyChain:
      if peerChain.isPUSP()['Value']:
        identitySubject = peerChain.getCertInChain(-2)['Value'].getSubjectNameObject()['Value']
      else:
        identitySubject = peerChain.getIssuerCert()['Value'].getSubjectNameObject()['Value']
    else:
      identitySubject = peerChain.getCertInChain(0)['Value'].getSubjectNameObject()['Value']
    credDict = {}

    subjectString = str(identitySubject)
    credDict = {'DN': subjectString,
                'CN': subjectString.split('CN')[1][1:],
                'x509Chain': peerChain,
                'isProxy': isProxyChain,
                'isLimitedProxy': isLimitedProxyChain}
    diracGroup = peerChain.getDIRACGroup()
    if diracGroup['OK'] and diracGroup['Value']:
      credDict['group'] = diracGroup['Value']
    self.infoDict['peerCredentials'] = credDict
    return credDict

  def setSSLSocket(self, sslSocket):
    self.sslSocket = sslSocket

  def getSSLSocket(self):
    return self.sslSocket

  def getSSLContext(self):
    return self.sslContext

  def clone(self):
    try:
      return S_OK(SocketInfo(dict(self.infoDict), self.sslContext))
    except Exception as e:
      return S_ERROR(str(e))

  # Seems unused
  # def verifyCallback(self, *args, **kwargs):
  #   """ Seems unused ?"""
  #   #gLogger.debug( "verify Callback %s" % str( args ) )
  #   if self.infoDict['clientMode']:
  #     return self._clientCallback(*args, **kwargs)
  #   else:
  #     return self._serverCallback(*args, **kwargs)

  def _verifyCert(self, peerCert):
    """
        Returns True if peercert is valid according to the configured
        validation mode and hostname.
        The ssl handshake already tested the certificate for a valid
        CA signature; the only thing that remains is to check
        the hostname.

        :param peerCert: ~M2Crypto.X509 object, host certificate
    """

    gLogger.warn("IMPLEMENT ME")
    return True

  # Seems unused
  # def _clientCallback(self, conn, cert, errnum, depth, ok):
  #   # This obviously has to be updated
  #   if depth == 0 and ok == 1:
  #     hostnameCN = ''
  #     if os.getenv('DIRAC_USE_M2CRYPTO', 'NO').lower() in ('yes', 'true'):
  #       hostnameCN = str(cert.getSubjectNameObject())
  #     else:
  #       hostnameCN = cert.get_subject().commonName
  #     # if hostnameCN in ( self.infoDict[ 'hostname' ], "host/%s" % self.infoDict[ 'hostname' ]  ):
  #     if self.__isSameHost(hostnameCN, self.infoDict['hostname']):
  #       return 1
  #     else:
  #       gLogger.warn("Server is not who it's supposed to be",
  #                    "Connecting to %s and it's %s" % (self.infoDict['hostname'], hostnameCN))
  #       return ok
  #   return ok
  #
  # def _serverCallback(self, conn, cert, errnum, depth, ok):
  #   return ok

  def __getCAStore(self):
    SocketInfo.__cachedCAsCRLsLoadLock.acquire()
    try:
      if not SocketInfo.__cachedCAsCRLs or time.time() - SocketInfo.__cachedCAsCRLsLastLoaded > 900:
        # Need to generate the CA Store
        casDict = {}
        crlsDict = {}
        casPath = Locations.getCAsLocation()
        if not casPath:
          return S_ERROR("No valid CAs location found")
        gLogger.debug("CAs location is %s" % casPath)
        casFound = 0
        crlsFound = 0
        SocketInfo.__caStore = M2Crypto.X509.X509_Store()
        for fileName in os.listdir(casPath):
          filePath = os.path.join(casPath, fileName)
          if not os.path.isfile(filePath):
            continue
          fObj = file(filePath, "rb")
          pemData = fObj.read()
          fObj.close()
          # Try to load CA Cert
          try:
            caCert = X509Certificate(certString=pemData)
            expired = caCert.hasExpired()
            if expired['OK'] and expired['Value']:
              continue
            subject = caCert.getSubjectDN()
            if not subject['OK']:
              return subject
            issuer = caCert.getIssuerDN()
            if not issuer['OK']:
              return issuer
            caID = (str(subject['Value']), str(issuer['Value']))
            caNotAfter = caCert.getNotAfterDate()
            if caID not in casDict:
              casDict[caID] = (caNotAfter, caCert)
              casFound += 1
            else:
              if casDict[caID][0] < caNotAfter:
                casDict[caID] = (caNotAfter, caCert)
            continue
          except BaseException:
            if fileName.find(".0") == len(fileName) - 2:
              gLogger.exception("LOADING %s" % filePath)
          if 'IgnoreCRLs' not in self.infoDict or not self.infoDict['IgnoreCRLs']:
            # Try to load CRL
            crl = X509CRL.instanceFromFile(filePath)
            if crl["OK"]:
              crl = crl["Value"]
            else:
              return crl
            if crl.hasExpired():
              continue
            crlsDict[crl.getIssuer()] = crl
            crlsFound += 1
            continue

        gLogger.debug("Loaded %s CAs [%s CRLs]" % (casFound, crlsFound))
        SocketInfo.__cachedCAsCRLs = ([casDict[k][1] for k in casDict],
                                      [crlsDict[k] for k in crlsDict])
        SocketInfo.__cachedCAsCRLsLastLoaded = time.time()
    except:
      gLogger.exception("Failed to init CA store")
    finally:
      SocketInfo.__cachedCAsCRLsLoadLock.release()
    # Generate CA Store
    caStore = M2Crypto.X509.X509_Store()
    caList = SocketInfo.__cachedCAsCRLs[0]
    for caCert in caList:
      caStore.add_x509(caCert)
    crlList = SocketInfo.__cachedCAsCRLs[1]

    return S_OK(caStore)

  def __createContext(self):
    clientContext = self.infoDict.get('clientMode', False)
    # Initialize context
    # contextOptions = M2Crypto.SSL.op_all
    # if not clientContext:
    #   # M2Crypto.m2.SSL_OP_NO_SSLv2 and M2Crypto.m2.SSL_OP_NO_SSLv3 exist, not sure why pylint throws an error
    #   contextOptions |= M2Crypto.m2.SSL_OP_NO_SSLv2 | M2Crypto.m2.SSL_OP_NO_SSLv3  # pylint: disable=E1101
    #   self.sslContext.set_options(contextOptions)

    ssl_version = self.infoDict.get('sslMethod', 'tls')


    self.sslContext = M2Crypto.SSL.Context(protocol=ssl_version)

    # print debug message
    self.sslContext.set_info_callback()
    x509Store = self.sslContext.get_cert_store()

    #TODO: CHRIS UNCOMMENT THAT !!!
    self.sslContext.set_cipher_list(self.infoDict.get('sslCiphers', DEFAULT_SSL_CIPHERS))

    # This is not quite true.
    # If skipCACheck is False, not only don't we load the verify location,
    # but we also do not check the remote peer !
    if not self.infoDict.get('skipCACheck', False):
      self.sslContext.set_verify(M2Crypto.SSL.verify_peer | M2Crypto.SSL.verify_fail_if_no_peer_cert, VERIFY_DEPTH)
      print "CHRIS TAKING CA FROM %s"%Locations.getCAsLocation()
      loadedCA = self.sslContext.load_verify_locations(capath = Locations.getCAsLocation())

      if not loadedCA:
        print "boom :'('"
        raise Exception("CA Certificates not loaded")
      else:
        print "CHRIS LOADED CA PROPERLY"
    else:
      self.sslContext.set_verify(M2Crypto.SSL.VERIFY_NONE, VERIFY_DEPTH)  # Do not require a
    return S_OK()

  def __generateContextWithCerts(self):
    certKeyTuple = Locations.getHostCertificateAndKeyLocation()
    if not certKeyTuple:
      return S_ERROR("No valid certificate or key found")
    self.infoDict['localCredentialsLocation'] = certKeyTuple
    gLogger.debug("Using certificate %s\nUsing key %s" % certKeyTuple)
    retVal = self.__createContext()
    if not retVal['OK']:
      return retVal
    self.sslContext.load_cert_chain(certchainfile=certKeyTuple[0], keyfile=certKeyTuple[1])
    return S_OK()

  def __generateContextWithProxy(self, proxyPath=None):
    print "CHRIS ICI !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    if not proxyPath:
      if 'proxyLocation' in self.infoDict:
        proxyPath = self.infoDict['proxyLocation']
        if not os.path.isfile(proxyPath):
          return S_ERROR("Defined proxy is not a file")
      else:
        proxyPath = Locations.getProxyLocation()
        if not proxyPath:
          return S_ERROR("No valid proxy found")
    self.infoDict['localCredentialsLocation'] = (proxyPath, proxyPath)
    gLogger.debug("Using proxy %s" % proxyPath)
    retVal = self.__createContext()
    if not retVal['OK']:
      return retVal

    # # # TODO CHRIS REMOVE THAT
    proxyPath = '/home/chaen/dirac/DIRAC/Core/Security/test/certs/user/usercert.pem'
    proxyKey = '/home/chaen/dirac/DIRAC/Core/Security/test/certs/user/userkey.pem'
    self.sslContext.load_cert_chain(certchainfile=proxyPath, keyfile=proxyKey)
    return S_OK()

  def __generateContextWithProxyString(self):
    # if bugs, maybe proxyFile gets deleted?
    proxyString = self.infoDict['proxyString']
    with tempfile.NamedTemporaryFile() as proxyFile:
      proxyFile.write(proxyString)
      proxyFile.flush()
      retVal = self.__generateContextWithProxy(proxyPath=proxyFile.name)
      if not retVal['OK']:
        return retVal
    return S_OK()

  def __generateServerContext(self):
    retVal = self.__generateContextWithCerts()
    if not retVal['OK']:
      return retVal
    self.sslContext.set_session_id_ctx("DISETConnection%s" % str(time.time()))
    if 'SSLSessionTimeout' in self.infoDict:
      timeout = int(self.infoDict['SSLSessionTimeout'])
      gLogger.debug("Setting session timeout to %s" % timeout)
      self.sslContext.set_session_timeout(timeout)
    return S_OK()

  def doClientHandshake(self):
    # sslbio = M2Crypto.BIO.SSLBio()
    # readbio = M2Crypto.BIO.MemoryBuffer()
    # writebio = M2Crypto.BIO.MemoryBuffer()
    # sslbio.set_ssl(self.sslSocket)
    # self.sslSocket.set_bio(readbio, writebio)
    # self.sslSocket.set_connect_state()
    # return self.__sslHandshake()
    print "CHRIS doClientHandhsake %s"%self.infoDict
    return self._do_ssl_handshake()

  def doServerHandshake(self):
    # self.sslSocket.setup_ssl()
    # self.sslSocket.set_accept_state()
    # self.sslSocket.accept_ssl()
    # res = self.sslSocket.do_handshake()
    print "CHRIS doServerHandshake"
    return self._do_ssl_handshake()

  def _do_ssl_handshake(self):
    print "OHHHHHHHHH YES "
    clientSide = self.infoDict.get('clientMode')
    try:
      print "_do_ssl_handshake setup_ssl"
      self.sslSocket.setup_ssl()

      # Set the socket to a different state depending on the client/server mode
      # Actual accept/connect logic
      if clientSide:
        self.sslSocket.set_connect_state()
        res = self.sslSocket.connect_ssl()
      else:
        # CHRIS TEST
        pass
        res = 1
        print "CHRIS DO NOTHING in do_ssl_andshake"
        # print "_do_ssl_handshake set_accept_state"
        # self.sslSocket.set_accept_state()
        # print "_do_ssl_handshake accept_ssl"
        # res = self.sslSocket.accept_ssl()
        # print "_do_ssl_handshake accept_ssl result %s"%res


      # There was an error, but everything was closed properly
      # see ~M2Crypto.SSL.Connection.accept_ssl for detailed description
      if res == 0:
        return S_ERROR("CHRIS Problem connecting")


      if res < 0:
        print "CHRIS NEGATIVE RES"
        err_num = self.sslSocket.ssl_get_error(res)
        print "Err: %s" % err_num
        print "Err Str: %s" % Err.get_error_reason(err_num)

        self.sslSocket.close()
        return S_ERROR(err_num, Err.get_error_reason(err_num))
    except SSL.SSLError as e:
      print "CHRIS ERROR in _do_ssl_handshake %s"%repr(e)
      print "NON "
      raise
    except socket.error as err:
      print "Socket error!"
      # Some port scans (e.g. nmap in -sT mode) have been known
      # to cause do_handshake to raise EBADF and ENOTCONN, so make
      # those errors quiet as well.
      # https://groups.google.com/forum/?fromgroups#!topic/python-tornado/ApucKJat1_0
      if err.args[0] in (errno.EBADF, errno.ENOTCONN):
        return self.sslSocket.close(exc_info=err)
      raise
    except AttributeError as err:
      print 'quand meme ?'
      # On Linux, if the connection was reset before the call to
      # wrap_socket, do_handshake will fail with an
      # AttributeError.
      return self.sslSocket.close(exc_info=err)
    else:
      print 'CHRIS ALL FINE'
      certValid = self._verifyCert(self.sslSocket.get_peer_cert())
      if not certValid:
        print "CHRIS VALIDATION FAILED!"
        self.sslSocket.close()
        return S_ERROR("CERT INVALID CHANGE ME CHRIS")

    print "CHRIS Connect complete! (Sever: %s)!" % (not clientSide)
    credentialsDict = self.gatherPeerCredentials()

    return S_OK(credentialsDict)

  #
  # def __sslHandshake(self):
  #   print "NOOOOOOOOOOOOOO"
  #   start = time.time()
  #   timeout = self.infoDict['timeout']
  #
  #   while True:
  #     if timeout:
  #       if time.time() - start > timeout:
  #         return S_ERROR("Handshake timeout exceeded")
  #     try:
  #       self.sslSocket.do_handshake()
  #       break
  #     except GSI.SSL.WantReadError:
  #       time.sleep(0.001)
  #     except GSI.SSL.WantWriteError:
  #       time.sleep(0.001)
  #     except GSI.SSL.Error as v:
  #       if self.__retry < 3:
  #         self.__retry += 1
  #         return self.__sslHandshake()
  #       else:
  #         # gLogger.warn( "Error while handshaking", "\n".join( [ stError[2] for stError in v.args[0] ] ) )
  #         gLogger.warn("Error while handshaking", v)
  #         return S_ERROR("Error while handshaking")
  #     except Exception as v:
  #       gLogger.warn("Error while handshaking", v)
  #       if self.__retry < 3:
  #         self.__retry += 1
  #         return self.__sslHandshake()
  #       else:
  #         # gLogger.warn( "Error while handshaking", "\n".join( [ stError[2] for stError in v.args[0] ] ) )
  #         gLogger.warn("Error while handshaking", v)
  #         return S_ERROR("Error while handshaking")
  #
  #   credentialsDict = self.gatherPeerCredentials()
  #   if self.infoDict['clientMode']:
  #     hostnameCN = credentialsDict['CN']
  #     # if hostnameCN.split("/")[-1] != self.infoDict[ 'hostname' ]:
  #     if not self._verifyCert(self.sslSocket.get_peer_cert()):
  #       gLogger.warn("Server is not who it's supposed to be",
  #                    "Connecting to %s and it's %s" % (self.infoDict['hostname'], hostnameCN))
  #   gLogger.debug("", "Authenticated peer (%s)" % credentialsDict['DN'])
  #   return S_OK(credentialsDict)
