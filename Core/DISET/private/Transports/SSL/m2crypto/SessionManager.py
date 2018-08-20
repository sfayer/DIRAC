""" SSL session manager. Unused for now """
__RCSID__ = "$Id$"

from M2Crypto.SSL import Session

class SessionManager(object):
  """ SSL Session manager. At the moment, this seems totaly unused.
      I leave it here for future, maybe...
  """
  def __init__( self ):
    self.sessionsDict = {}

  def __generateSession( self ):
    return Session()

  def get( self, sessionId ):
    if sessionId not in self.sessionsDict:
      self.sessionsDict[ sessionId ] = self.__generateSession()
    return self.sessionsDict[ sessionId ]

  def isValid( self, sessionId ):
    return sessionId in self.sessionsDict and self.sessionsDict[ sessionId ].valid()

  def free( self, sessionId ):
    self.sessionsDict[ sessionId ].free()

  def set( self, sessionId, sessionObject ):
    self.sessionsDict[ sessionId ] = sessionObject

gSessionManager = SessionManager()
