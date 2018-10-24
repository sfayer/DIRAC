__RCSID__ = "$Id$"

import os

from DIRAC.Core.Security import Locations
from DIRAC.Core.Utilities.ReturnValues import S_ERROR, S_OK

if os.getenv('DIRAC_USE_M2CRYPTO', 'NO').lower() in ('yes', 'true'):
  from DIRAC.Core.Security.m2crypto.X509Chain import X509Chain
  from DIRAC.Core.Security.m2crypto.X509Certificate import X509Certificate
  from DIRAC.Core.DISET.private.Transports.M2SSLTransport import SSLTransport
else:
  from DIRAC.Core.Security.X509Chain import X509Chain
  from DIRAC.Core.Security.X509Certificate import X509Certificate
  from DIRAC.Core.DISET.private.Transports.GSISSLTransport import SSLTransport


def checkSanity( urlTuple, kwargs ):
  """
  Check that all ssl environment is ok
  """
  useCerts = False
  certFile = ''
  if "useCertificates" in kwargs and kwargs[ 'useCertificates' ]:
    certTuple = Locations.getHostCertificateAndKeyLocation()
    if not certTuple:
      gLogger.error( "No cert/key found! " )
      return S_ERROR( "No cert/key found! " )
    certFile = certTuple[0]
    useCerts = True
  elif "proxyString" in kwargs:
    if not isinstance( kwargs[ 'proxyString' ], basestring ):
      gLogger.error( "proxyString parameter is not a valid type", str( type( kwargs[ 'proxyString' ] ) ) )
      return S_ERROR( "proxyString parameter is not a valid type" )
  else:
    if "proxyLocation" in kwargs:
      certFile = kwargs[ "proxyLocation" ]
    else:
      certFile = Locations.getProxyLocation()
    if not certFile:
      gLogger.error( "No proxy found" )
      return S_ERROR( "No proxy found" )
    elif not os.path.isfile( certFile ):
      gLogger.error( "Proxy file does not exist", certFile )
      return S_ERROR( "%s proxy file does not exist" % certFile )

  #For certs always check CA's. For clients skipServerIdentityCheck
  if 'skipCACheck' not in kwargs or not kwargs[ 'skipCACheck' ]:
    if not Locations.getCAsLocation():
      gLogger.error( "No CAs found!" )
      return S_ERROR( "No CAs found!" )

  if "proxyString" in kwargs:
    certObj = X509Chain()
    retVal = certObj.loadChainFromString( kwargs[ 'proxyString' ] )
    if not retVal[ 'OK' ]:
      gLogger.error( "Can't load proxy string" )
      return S_ERROR( "Can't load proxy string" )
  else:
    if useCerts:
      certObj = X509Certificate()
      certObj.loadFromFile( certFile )
    else:
      certObj = X509Chain()
      certObj.loadChainFromFile( certFile )

  retVal = certObj.hasExpired()
def checkSanity( urlTuple, kwargs ):
  """
  Check that all ssl environment is ok
  """
  useCerts = False
  certFile = ''
  if "useCertificates" in kwargs and kwargs[ 'useCertificates' ]:
    certTuple = Locations.getHostCertificateAndKeyLocation()
    if not certTuple:
      gLogger.error( "No cert/key found! " )
      return S_ERROR( "No cert/key found! " )
    certFile = certTuple[0]
    useCerts = True
  elif "proxyString" in kwargs:
    if not isinstance( kwargs[ 'proxyString' ], basestring ):
      gLogger.error( "proxyString parameter is not a valid type", str( type( kwargs[ 'proxyString' ] ) ) )
      return S_ERROR( "proxyString parameter is not a valid type" )
  else:
    if "proxyLocation" in kwargs:
      certFile = kwargs[ "proxyLocation" ]
    else:
      certFile = Locations.getProxyLocation()
    if not certFile:
      gLogger.error( "No proxy found" )
      return S_ERROR( "No proxy found" )
    elif not os.path.isfile( certFile ):
      gLogger.error( "Proxy file does not exist", certFile )
      return S_ERROR( "%s proxy file does not exist" % certFile )

  #For certs always check CA's. For clients skipServerIdentityCheck
  if 'skipCACheck' not in kwargs or not kwargs[ 'skipCACheck' ]:
    if not Locations.getCAsLocation():
      gLogger.error( "No CAs found!" )
      return S_ERROR( "No CAs found!" )

  if "proxyString" in kwargs:
    certObj = X509Chain()
    retVal = certObj.loadChainFromString( kwargs[ 'proxyString' ] )
    if not retVal[ 'OK' ]:
      gLogger.error( "Can't load proxy string" )
      return S_ERROR( "Can't load proxy string" )
  else:
    if useCerts:
      certObj = X509Certificate()
      certObj.loadFromFile( certFile )
    else:
      certObj = X509Chain()
      certObj.loadChainFromFile( certFile )

  retVal = certObj.hasExpired()
