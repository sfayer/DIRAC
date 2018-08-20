__RCSID__ = "$Id$"

import os
if os.getenv('DIRAC_USE_M2CRYPTO', 'NO').lower() in ('yes', 'true'):
  from DIRAC.Core.DISET.private.Transports.M2SSLTransport import SSLTransport, checkSanity, delegate
else:
  from DIRAC.Core.DISET.private.Transports.GSISSLTransport import SSLTransport, checkSanity, delegate
