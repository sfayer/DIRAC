""" Test the SSLTransport mechanism """

import os
import select
import socket
import time
import threading

from pytest import fixture

from DIRAC.Core.Security.test.x509TestUtilities import CERTDIR, USERCERT, getCertOption

from DIRAC.ConfigurationSystem.Client.ConfigurationData import gConfigurationData
from DIRAC.Core.DISET.private.Transports import PlainTransport, GSISSLTransport,M2SSLTransport

# Define all the locations
caLocation = os.path.join(CERTDIR, 'ca')
hostCertLocation = os.path.join(CERTDIR, 'host/hostcert.pem')
hostKeyLocation = os.path.join(CERTDIR, 'host/hostkey.pem')
gConfigurationData.setOptionInCFG('/DIRAC/Security/CALocation', caLocation)
gConfigurationData.setOptionInCFG('/DIRAC/Security/CertFile', hostCertLocation)
gConfigurationData.setOptionInCFG('/DIRAC/Security/KeyFile', hostKeyLocation)

proxyFile = os.path.join(os.path.dirname(__file__), 'proxy.pem')



MAGIC_QUESTION = "Who let the dog out"
MAGIC_ANSWER = "Who, Who, who ?"


PORT_NUMBER = 1234

TRANSPORTTYPES = (PlainTransport.PlainTransport, M2SSLTransport.SSLTransport)
# TRANSPORTTYPES = (SSLTransport.SSLTransport, )
# TRANSPORTTYPES = (M2SSLTransport.SSLTransport, )
# TRANSPORTTYPES = (GSISSLTransport.SSLTransport, )



# https://www.ibm.com/developerworks/linux/library/l-openssl/index.html
# http://www.herongyang.com/Cryptography/

class DummyServiceReactor(object):
  """ This class behaves like a ServiceReactor, except that it exists after treating a single request """

  def __init__(self, transportObject, port):
    """ c'tor

        :param transportObject: type of TransportObject we will use
        :param port: port to listen to
    """

    self.port = port
    self.transportObject = transportObject

    # Server transport object
    self.transport = None
    # Client connection
    self.clientTransport = None
    # Message received from the client
    self.receivedMessage = None

  def handleConnection(self, clientTransport):
    """ This is normally done is Service.py in different thread
        It more or less does Service._processInThread
    """

    self.clientTransport = clientTransport
    res = clientTransport.handshake()
    assert res['OK'], res

    self.receivedMessage = clientTransport.receiveData(1024)
    clientTransport.sendData(MAGIC_ANSWER)
    clientTransport.close()

  def serve(self):
    """ Create the listener, and listen """

    self.__createListeners()
    self.__acceptIncomingConnection()

  def __createListeners(self):
    """ Create the listener transport """
    self.transport = self.transportObject(("", self.port), bServerMode=True)
    res = self.transport.initAsServer()
    assert res['OK']

  def __acceptIncomingConnection(self, ):
    """
      This method just gets the incoming connection, and handle it, once.
    """
    sockets = [self.transport.getSocket()]

    try:
      _inList, _outList, _exList = select.select(sockets, [], [], 2)

      clientTransport = self.transport.acceptConnection()['Value']

      self.handleConnection(clientTransport)

    except socket.error:
      return

  def closeListeningConnections(self):
    """ Close the connection """
    self.transport.close()


@fixture(scope="function", params=TRANSPORTTYPES)
def create_serverAndClient(request):
  """ This function starts a server, and closes it after
    The server will use the parametrized transport type
  """

  transportObject = request.param

  sr = DummyServiceReactor(transportObject, PORT_NUMBER)
  server_thread = threading.Thread(target=sr.serve)
  server_thread.start()

  # Create the client
  clientOptions = {'clientMode': True,
                   'proxyLocation': proxyFile,
                  }

  time.sleep(1)


  clientTransport = transportObject(("localhost", PORT_NUMBER), bServerMode=False, **clientOptions)
  res = clientTransport.initAsClient()
  assert res['OK'], res

  yield sr, clientTransport


  clientTransport.close()
  sr.closeListeningConnections()
  server_thread.join()
  time.sleep(1)


def ping_server(clientTransport):
  """ This sends a message to the server and expects an answer
      This basically does the same as BaseClient.py

      :param clientTransport: the Transport object to be used as client
  """

  clientTransport.setSocketTimeout(5)
  clientTransport.sendData(MAGIC_QUESTION)
  serverReturn = clientTransport.receiveData()
  return serverReturn


def test_simpleMessage(create_serverAndClient):
  """ Send a message, wait for an answer """

  serv, client = create_serverAndClient
  serverAnswer = ping_server(client)
  assert serv.receivedMessage == MAGIC_QUESTION
  assert serverAnswer == MAGIC_ANSWER


def test_getRemoteInfo(create_serverAndClient):
  """ Check the information from remote peer"""
  serv, client = create_serverAndClient
  ping_server(client)

  addr_info = client.getRemoteAddress()
  assert addr_info[0] in ('127.0.0.1', '::ffff:127.0.0.1', '::1')
  assert addr_info[1] == PORT_NUMBER
  assert client.peerCredentials == {} # The peer credentials are not filled on the client side

  # We do not know about the port, so check only the address, taking into account bloody IPv6
  assert serv.clientTransport.getRemoteAddress()[0] in ('127.0.0.1', '::ffff:127.0.0.1', '::1')
  peerCreds =  serv.clientTransport.peerCredentials

  # There are no credentials for PlainTransport
  if client.__class__.__name__ == 'PlainTransport':
    assert peerCreds == {}
  else:
    assert peerCreds['DN'] == getCertOption(USERCERT, 'subjectDN')
    assert peerCreds['x509Chain'].getNumCertsInChain()['Value'] == 2
    assert peerCreds['isProxy'] is True
    assert peerCreds['isLimitedProxy'] is False
