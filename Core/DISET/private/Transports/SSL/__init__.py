import os
from pkgutil import extend_path

# If we want to use M2Crypto, we add the m2crypto subpackage to the search path
# Nice kind of tricks you find in libraries like xml...
if os.getenv('DIRAC_USE_M2CRYPTO', 'NO').lower() in ('yes', 'true'):
  __path__ = extend_path(__path__, __name__ + '.m2crypto')
else:
  __path__ = extend_path(__path__, __name__ + '.pygsi')
