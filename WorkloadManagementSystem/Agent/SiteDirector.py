########################################################################
# File :    SiteDirector.py
# Author :  A.T.
########################################################################

"""  The Site Director is a simple agent performing pilot job submission to particular sites.
"""
import os
import base64
import bz2
import tempfile
import random
import socket
import hashlib
from collections import defaultdict


import DIRAC
from DIRAC                                                 import S_OK, S_ERROR, gConfig
from DIRAC.ResourceStatusSystem.Client.ResourceStatus      import ResourceStatus
from DIRAC.ResourceStatusSystem.Client.SiteStatus          import SiteStatus
from DIRAC.Core.Utilities.File                             import mkDir
from DIRAC.Core.Base.AgentModule                           import AgentModule
from DIRAC.ConfigurationSystem.Client.Helpers              import CSGlobals, Registry, Operations, Resources
from DIRAC.Resources.Computing.ComputingElementFactory     import ComputingElementFactory
from DIRAC.WorkloadManagementSystem.Client.ServerUtils     import pilotAgentsDB, jobDB
from DIRAC.WorkloadManagementSystem.Service.WMSUtilities   import getGridEnv
from DIRAC.WorkloadManagementSystem.private.ConfigHelper   import findGenericPilotCredentials
from DIRAC.FrameworkSystem.Client.ProxyManagerClient       import gProxyManager
from DIRAC.AccountingSystem.Client.Types.Pilot             import Pilot as PilotAccounting
from DIRAC.AccountingSystem.Client.DataStoreClient         import gDataStoreClient
from DIRAC.Core.DISET.RPCClient                            import RPCClient
from DIRAC.Core.Security                                   import CS
from DIRAC.Core.Utilities.SiteCEMapping                    import getSiteForCE
from DIRAC.Core.Utilities.Time                             import dateTime, second
from DIRAC.Core.Utilities.List                             import fromChar

__RCSID__ = "$Id$"

DIRAC_PILOT = os.path.join( DIRAC.rootPath, 'DIRAC', 'WorkloadManagementSystem', 'PilotAgent', 'dirac-pilot.py' )
DIRAC_INSTALL = os.path.join( DIRAC.rootPath, 'DIRAC', 'Core', 'scripts', 'dirac-install.py' )
DIRAC_MODULES = [ os.path.join( DIRAC.rootPath, 'DIRAC', 'WorkloadManagementSystem', 'PilotAgent', 'pilotCommands.py' ),
                  os.path.join( DIRAC.rootPath, 'DIRAC', 'WorkloadManagementSystem', 'PilotAgent', 'pilotTools.py' ) ]
TRANSIENT_PILOT_STATUS = ['Submitted', 'Waiting', 'Running', 'Scheduled', 'Ready', 'Unknown']
WAITING_PILOT_STATUS = ['Submitted', 'Waiting', 'Scheduled', 'Ready']
FINAL_PILOT_STATUS = ['Aborted', 'Failed', 'Done']
MAX_PILOTS_TO_SUBMIT = 100
MAX_JOBS_IN_FILLMODE = 5

def getSubmitPools( group = None, vo = None ):
  """ This method gets submit pools
  """
  if group:
    return Registry.getGroupOption( group, 'SubmitPools', '' )
  if vo:
    return Registry.getVOOption( vo, 'SubmitPools', '' )
  return ''


class SiteDirector( AgentModule ):
  """ SiteDirector class provides an implementation of a DIRAC agent.

      Used for submitting pilots to Computing Elements.
  """

  def __init__( self, *args, **kwargs ):
    """ c'tor
    """
    super(SiteDirector, self).__init__( *args, **kwargs )
    self.queueDict = {}
    self.queueCECache = {}
    self.queueSlots = {}
    self.failedQueues = defaultdict( int )
    self.firstPass = True
    self.maxJobsInFillMode = MAX_JOBS_IN_FILLMODE
    self.maxPilotsToSubmit = MAX_PILOTS_TO_SUBMIT

    self.gridEnv = ''
    self.vo = ''
    self.group = ''
    # self.voGroups contain all the eligible user groups for pilots submitted by this SiteDirector
    self.voGroups = []
    self.pilotDN = ''
    self.pilotGroup = ''
    self.platforms = []
    self.sites = []

    self.proxy = None

    self.updateStatus = True
    self.getOutput = False
    self.sendAccounting = True

    self.siteClient = None
    self.rssClient = None
    self.rssFlag = None

    self.globalParameters = { "NumberOfProcessors": 1,
                              "MaxRAM": 2048 }

  def initialize( self ):
    """ Initial settings
    """
    # Clients
    self.siteClient = SiteStatus()
    self.rssClient = ResourceStatus()
    self.rssFlag = self.rssClient.rssFlag

    # set of CS options
    self.am_setOption( "PollingTime", 60.0 )
    self.am_setOption( "maxPilotWaitingHours", 6 )
    return S_OK()

  def beginExecution( self ):

    self.gridEnv = self.am_getOption( "GridEnv", getGridEnv() )
    # The SiteDirector is for a particular user community
    self.vo = self.am_getOption( "VO", '' )
    if not self.vo:
      self.vo = self.am_getOption( "Community", '' )
    if not self.vo:
      self.vo = CSGlobals.getVO()
    # The SiteDirector is for a particular user group
    self.group = self.am_getOption( "Group", '' )

    # Choose the group for which pilots will be submitted. This is a hack until
    # we will be able to match pilots to VOs.
    if not self.group:
      if self.vo:
        result = Registry.getGroupsForVO( self.vo )
        if not result['OK']:
          return result
        self.voGroups = []
        for group in result['Value']:
          if 'NormalUser' in Registry.getPropertiesForGroup( group ):
            self.voGroups.append( group )
    else:
      self.voGroups = [ self.group ]

    result = findGenericPilotCredentials( vo = self.vo )
    if not result[ 'OK' ]:
      return result
    self.pilotDN, self.pilotGroup = result[ 'Value' ]
    self.pilotDN = self.am_getOption( "PilotDN", self.pilotDN )
    self.pilotGroup = self.am_getOption( "PilotGroup", self.pilotGroup )

    self.defaultSubmitPools = getSubmitPools( self.group, self.vo )
    self.pilot = self.am_getOption( 'PilotScript', DIRAC_PILOT )
    self.install = DIRAC_INSTALL
    self.extraModules = self.am_getOption( 'ExtraPilotModules', [] ) + DIRAC_MODULES
    self.workingDirectory = self.am_getOption( 'WorkDirectory' )
    self.maxQueueLength = self.am_getOption( 'MaxQueueLength', 86400 * 3 )
    self.pilotLogLevel = self.am_getOption( 'PilotLogLevel', 'INFO' )
    self.maxJobsInFillMode = self.am_getOption( 'MaxJobsInFillMode', self.maxJobsInFillMode )
    self.maxPilotsToSubmit = self.am_getOption( 'MaxPilotsToSubmit', self.maxPilotsToSubmit )
    self.pilotWaitingFlag = self.am_getOption( 'PilotWaitingFlag', True )
    self.pilotWaitingTime = self.am_getOption( 'MaxPilotWaitingTime', 3600 )
    self.failedQueueCycleFactor = self.am_getOption( 'FailedQueueCycleFactor', 10 )
    self.pilotStatusUpdateCycleFactor = self.am_getOption( 'PilotStatusUpdateCycleFactor', 10 )
    self.addPilotsToEmptySites = self.am_getOption( 'AddPilotsToEmptySites', False )

    # Flags
    self.updateStatus = self.am_getOption( 'UpdatePilotStatus', True )
    self.getOutput = self.am_getOption( 'GetPilotOutput', False )
    self.sendAccounting = self.am_getOption( 'SendPilotAccounting', True )

    # Get the site description dictionary
    siteNames = None
    if self.am_getOption( 'Site', 'Any' ).lower() != "any":
      siteNames = self.am_getOption( 'Site', [] )
      if not siteNames:
        siteNames = None
    ceTypes = None
    if self.am_getOption( 'CETypes', 'Any' ).lower() != "any":
      ceTypes = self.am_getOption( 'CETypes', [] )
    ces = None
    if self.am_getOption( 'CEs', 'Any' ).lower() != "any":
      ces = self.am_getOption( 'CEs', [] )
      if not ces:
        ces = None
    result = Resources.getQueues( community = self.vo,
                                  siteList = siteNames,
                                  ceList = ces,
                                  ceTypeList = ceTypes,
                                  mode = 'Direct' )
    if not result['OK']:
      return result
    resourceDict = result['Value']
    result = self.getQueues( resourceDict )
    if not result['OK']:
      return result

    #if not siteNames:
    #  siteName = gConfig.getValue( '/DIRAC/Site', 'Unknown' )
    #  if siteName == 'Unknown':
    #    return S_OK( 'No site specified for the SiteDirector' )
    #  else:
    #    siteNames = [siteName]
    #self.siteNames = siteNames

    if self.updateStatus:
      self.log.always( 'Pilot status update requested' )
    if self.getOutput:
      self.log.always( 'Pilot output retrieval requested' )
    if self.sendAccounting:
      self.log.always( 'Pilot accounting sending requested' )

    self.log.always( 'VO:', self.vo )
    if self.voGroups:
      self.log.always( 'Group(s):', self.voGroups )
    self.log.always( 'Sites:', siteNames )
    self.log.always( 'CETypes:', ceTypes )
    self.log.always( 'CEs:', ces )
    self.log.always( 'PilotDN:', self.pilotDN )
    self.log.always( 'PilotGroup:', self.pilotGroup )
    self.log.always( 'MaxPilotsToSubmit:', self.maxPilotsToSubmit )
    self.log.always( 'MaxJobsInFillMode:', self.maxJobsInFillMode )

    self.localhost = socket.getfqdn()
    self.proxy = ''

    if self.firstPass:
      if self.queueDict:
        self.log.always( "Agent will serve queues:" )
        for queue in self.queueDict:
          self.log.always( "Site: %s, CE: %s, Queue: %s" % ( self.queueDict[queue]['Site'],
                                                             self.queueDict[queue]['CEName'],
                                                             queue ) )
    self.firstPass = False
    return S_OK()

  def __generateQueueHash( self, queueDict ):
    """ Generate a hash of the queue description
    """
    myMD5 = hashlib.md5()
    myMD5.update( str( queueDict ) )
    hexstring = myMD5.hexdigest()
    return hexstring

  def getQueues( self, resourceDict ):
    """ Get the list of relevant CEs and their descriptions
    """

    self.queueDict = {}
    ceFactory = ComputingElementFactory()

    for site in resourceDict:
      for ce in resourceDict[site]:
        ceDict = resourceDict[site][ce]
        pilotRunDirectory = ceDict.get( 'PilotRunDirectory', '' )
        ceMaxRAM = ceDict.get( 'MaxRAM', None )
        qDict = ceDict.pop( 'Queues' )
        for queue in qDict:
          queueName = '%s_%s' % ( ce, queue )
          self.queueDict[queueName] = {}
          self.queueDict[queueName]['ParametersDict'] = qDict[queue]
          self.queueDict[queueName]['ParametersDict']['Queue'] = queue
          self.queueDict[queueName]['ParametersDict']['Site'] = site
          self.queueDict[queueName]['ParametersDict']['GridEnv'] = self.gridEnv
          self.queueDict[queueName]['ParametersDict']['Setup'] = gConfig.getValue( '/DIRAC/Setup', 'unknown' )
          # Evaluate the CPU limit of the queue according to the Glue convention
          # To Do: should be a utility
          if "maxCPUTime" in self.queueDict[queueName]['ParametersDict'] and \
             "SI00" in self.queueDict[queueName]['ParametersDict']:
            maxCPUTime = float( self.queueDict[queueName]['ParametersDict']['maxCPUTime'] )
            # For some sites there are crazy values in the CS
            maxCPUTime = max( maxCPUTime, 0 )
            maxCPUTime = min( maxCPUTime, 86400 * 12.5 )
            si00 = float( self.queueDict[queueName]['ParametersDict']['SI00'] )
            queueCPUTime = 60. / 250. * maxCPUTime * si00
            self.queueDict[queueName]['ParametersDict']['CPUTime'] = int( queueCPUTime )

          # Tags & RequiredTags defined on the Queue level and on the CE level are concatenated
          # This also converts them from a string to a list if required.
          for tagFieldName in ( 'Tag', 'RequiredTag' ):
            ceTags = ceDict.get( tagFieldName, [] )
            if isinstance( ceTags, basestring ):
              ceTags = fromChar( ceTags )
            queueTags = self.queueDict[queueName]['ParametersDict'].get( tagFieldName )
            if queueTags and isinstance( queueTags, basestring ):
              queueTags = fromChar( queueTags )
              self.queueDict[queueName]['ParametersDict'][tagFieldName] = queueTags
            if ceTags:
              if queueTags:
                allTags = list( set( ceTags + queueTags ) )
                self.queueDict[queueName]['ParametersDict'][tagFieldName] = allTags
              else:
                self.queueDict[queueName]['ParametersDict'][tagFieldName] = ceTags

          # Some parameters can be defined on the CE level and are inherited by all Queues
          for parameter in [ 'MaxRAM', 'NumberOfProcessors', 'WholeNode' ]:
            queueParameter = self.queueDict[queueName]['ParametersDict'].get( parameter )
            ceParameter = ceDict.get( parameter )
            if ceParameter or queueParameter:
              self.queueDict[queueName]['ParametersDict'][parameter] = ceParameter if not queueParameter \
                                                                                   else queueParameter

          if pilotRunDirectory:
            self.queueDict[queueName]['ParametersDict']['JobExecDir'] = pilotRunDirectory
          qwDir = os.path.join( self.workingDirectory, queue )
          mkDir(qwDir)
          self.queueDict[queueName]['ParametersDict']['WorkingDirectory'] = qwDir
          platform = ''
          if "Platform" in self.queueDict[queueName]['ParametersDict']:
            platform = self.queueDict[queueName]['ParametersDict']['Platform']
          elif "Platform" in ceDict:
            platform = ceDict['Platform']
          elif "OS" in ceDict:
            architecture = ceDict.get( 'architecture', 'x86_64' )
            platform = '_'.join( [architecture, ceDict['OS']] )
          if platform and not platform in self.platforms:
            self.platforms.append( platform )

          if not "Platform" in self.queueDict[queueName]['ParametersDict'] and platform:
            result = Resources.getDIRACPlatform( platform )
            if result['OK']:
              self.queueDict[queueName]['ParametersDict']['Platform'] = result['Value'][0]

          ceQueueDict = dict( ceDict )
          ceQueueDict.update( self.queueDict[queueName]['ParametersDict'] )

          # Generate the CE object for the queue or pick the already existing one
          # if the queue definition did not change
          queueHash = self.__generateQueueHash( ceQueueDict )
          if queueName in self.queueCECache and self.queueCECache[queueName]['Hash'] == queueHash:
            queueCE = self.queueCECache[queueName]['CE']
          else:
            result = ceFactory.getCE( ceName = ce,
                                      ceType = ceDict['CEType'],
                                      ceParametersDict = ceQueueDict )
            if not result['OK']:
              return result
            self.queueCECache.setdefault( queueName, {} )
            self.queueCECache[queueName]['Hash'] = queueHash
            self.queueCECache[queueName]['CE'] = result['Value']
            queueCE = self.queueCECache[queueName]['CE']

          self.queueDict[queueName]['CE'] = queueCE
          self.queueDict[queueName]['CEName'] = ce
          self.queueDict[queueName]['CEType'] = ceDict['CEType']
          self.queueDict[queueName]['Site'] = site
          self.queueDict[queueName]['QueueName'] = queue
          self.queueDict[queueName]['Platform'] = platform
          self.queueDict[queueName]['QueryCEFlag'] = ceDict.get( 'QueryCEFlag', "false" )

          result = self.queueDict[queueName]['CE'].isValid()
          if not result['OK']:
            self.log.fatal( result['Message'] )
            return result
          if 'BundleProxy' in self.queueDict[queueName]['ParametersDict']:
            if self.queueDict[queueName]['ParametersDict']['BundleProxy'].lower() in ['true','yes','1']:
              self.queueDict[queueName]['BundleProxy'] = True
          elif 'BundleProxy' in ceDict:
            if ceDict['BundleProxy'].lower() in ['true','yes','1']:
              self.queueDict[queueName]['BundleProxy'] = True

          if site not in self.sites:
            self.sites.append( site )

          if "WholeNode" in self.queueDict[queueName]['ParametersDict']:
            self.globalParameters['WholeNode'] = 'True'
          for parameter in [ 'MaxRAM', 'NumberOfProcessors' ]:
            if parameter in self.queueDict[queueName]['ParametersDict']:
              self.globalParameters[parameter] = max( self.globalParameters[parameter],
                                                      int( self.queueDict[queueName]['ParametersDict'][parameter] ))


    return S_OK()

  def execute( self ):
    """ Main execution method (what is called at each agent cycle).

        It basically just calls self.submitJobs() method
    """

    if not self.queueDict:
      self.log.warn( 'No site defined, exiting the cycle' )
      return S_OK()

    result = self.submitJobs()
    if not result['OK']:
      self.log.error( 'Errors in the job submission: ', result['Message'] )

    cyclesDone = self.am_getModuleParam( 'cyclesDone' )
    if self.updateStatus and cyclesDone % self.pilotStatusUpdateCycleFactor == 0:
      result = self.updatePilotStatus()
      if not result['OK']:
        self.log.error( 'Errors in updating pilot status: ', result['Message'] )

    return S_OK()

  def submitJobs( self ):
    """ Go through defined computing elements and submit jobs if necessary
    """
    # Check that there is some work at all
    setup = CSGlobals.getSetup()
    tqDict = { 'Setup':setup,
               'CPUTime': 9999999,
               'SubmitPool' : self.defaultSubmitPools }
    if self.vo:
      tqDict['Community'] = self.vo
    if self.voGroups:
      tqDict['OwnerGroup'] = self.voGroups
    result = Resources.getCompatiblePlatforms( self.platforms )
    if not result['OK']:
      return result
    tqDict['Platform'] = result['Value']
    tqDict['Site'] = self.sites

    # Get a union of all tags
    tags = []
    for queue in self.queueDict:
      tags += self.queueDict[queue]['ParametersDict'].get( 'Tag', [] )
    tqDict['Tag'] = list( set( tags ) )

    # Add overall max values for all queues
    tqDict.update( self.globalParameters )

    self.log.verbose( 'Checking overall TQ availability with requirements' )
    self.log.verbose( tqDict )

    rpcMatcher = RPCClient( "WorkloadManagement/Matcher" )
    result = rpcMatcher.getMatchingTaskQueues( tqDict )
    if not result[ 'OK' ]:
      return result
    if not result['Value']:
      self.log.verbose( 'No Waiting jobs suitable for the director' )
      return S_OK()

    jobSites = set()
    anySite = False
    testSites = set()
    totalWaitingJobs = 0
    for tqID in result['Value']:
      if "Sites" in result['Value'][tqID]:
        for site in result['Value'][tqID]['Sites']:
          if site.lower() != 'any':
            jobSites.add( site )
          else:
            anySite = True
      else:
        anySite = True
      if "JobTypes" in result['Value'][tqID]:
        if "Sites" in result['Value'][tqID]:
          for site in result['Value'][tqID]['Sites']:
            if site.lower() != 'any':
              testSites.add( site )
      totalWaitingJobs += result['Value'][tqID]['Jobs']

    tqIDList = result['Value'].keys()
    result = pilotAgentsDB.countPilots( { 'TaskQueueID': tqIDList,
                                          'Status': WAITING_PILOT_STATUS },
                                        None )
    totalWaitingPilots = 0
    if result['OK']:
      totalWaitingPilots = result['Value']
    self.log.info( 'Total %d jobs in %d task queues with %d waiting pilots' \
                  % (totalWaitingJobs, len( tqIDList ), totalWaitingPilots ) )
    #if totalWaitingPilots >= totalWaitingJobs:
    #  self.log.info( 'No more pilots to be submitted in this cycle' )
    #  return S_OK()

    result = self.siteClient.getUsableSites()
    if not result['OK']:
      return result
    siteMaskList = result['Value']

    queues = self.queueDict.keys()
    random.shuffle( queues )
    totalSubmittedPilots = 0
    matchedQueues = 0
    for queue in queues:

      # Check if the queue failed previously
      failedCount = self.failedQueues[ queue ] % self.failedQueueCycleFactor
      if failedCount != 0:
        self.log.warn( "%s queue failed recently, skipping %d cycles" % ( queue, 10-failedCount ) )
        self.failedQueues[queue] += 1
        continue

      ce = self.queueDict[queue]['CE']
      ceName = self.queueDict[queue]['CEName']
      ceType = self.queueDict[queue]['CEType']
      queueName = self.queueDict[queue]['QueueName']
      siteName = self.queueDict[queue]['Site']
      platform = self.queueDict[queue]['Platform']
      siteMask = siteName in siteMaskList

      # Check the status of the Site
      result = self.siteClient.getUsableSites(siteName)
      if not result['OK']:
        self.log.error("Can not get the status of site",
                       " %s: %s" % (siteName, result['Message']))
        continue
      if siteName not in result.get('Value', []):
        self.log.info("site %s is not active" % siteName)
        continue

      if self.rssFlag:
        # Check the status of the ComputingElement
        result = self.rssClient.getElementStatus(ceName, "ComputingElement")
        if not result['OK']:
          self.log.error("Can not get the status of computing element",
                         " %s: %s" % (siteName, result['Message']))
          continue
        if result['Value']:
          result = result['Value'][ceName]['all']   #get the value of the status

        if result not in ('Active', 'Degraded'):
          self.log.verbose( "Skipping computing element %s at %s: resource not usable" % (ceName, siteName) )
          continue

      if not anySite and siteName not in jobSites:
        self.log.verbose( "Skipping queue %s at %s: no workload expected" % (queueName, siteName) )
        continue
      if not siteMask and siteName not in testSites:
        self.log.verbose( "Skipping queue %s: site %s not in the mask" % (queueName, siteName) )
        continue

      if 'CPUTime' in self.queueDict[queue]['ParametersDict'] :
        queueCPUTime = int( self.queueDict[queue]['ParametersDict']['CPUTime'] )
      else:
        self.log.warn( 'CPU time limit is not specified for queue %s, skipping...' % queue )
        continue
      if queueCPUTime > self.maxQueueLength:
        queueCPUTime = self.maxQueueLength

      # Prepare the queue description to look for eligible jobs
      ceDict = ce.getParameterDict()
      ceDict[ 'GridCE' ] = ceName
      #if not siteMask and 'Site' in ceDict:
      #  self.log.info( 'Site not in the mask %s' % siteName )
      #  self.log.info( 'Removing "Site" from matching Dict' )
      #  del ceDict[ 'Site' ]
      if not siteMask:
        ceDict['JobType'] = "Test"
      if self.vo:
        ceDict['Community'] = self.vo
      if self.voGroups:
        ceDict['OwnerGroup'] = self.voGroups

      # This is a hack to get rid of !
      ceDict['SubmitPool'] = self.defaultSubmitPools

      result = Resources.getCompatiblePlatforms( platform )
      if not result['OK']:
        continue
      ceDict['Platform'] = result['Value']

      # Get the number of eligible jobs for the target site/queue
      result = rpcMatcher.getMatchingTaskQueues( ceDict )
      if not result['OK']:
        self.log.error( 'Could not retrieve TaskQueues from TaskQueueDB', result['Message'] )
        return result
      taskQueueDict = result['Value']
      if not taskQueueDict:
        self.log.verbose( 'No matching TQs found for %s' % queue )
        continue

      matchedQueues += 1
      totalTQJobs = 0
      tqIDList = taskQueueDict.keys()
      for tq in taskQueueDict:
        totalTQJobs += taskQueueDict[tq]['Jobs']

      self.log.verbose( '%d job(s) from %d task queue(s) are eligible for %s queue' \
                       % (totalTQJobs, len( tqIDList ), queue) )

      # Get the number of already waiting pilots for these task queues
      totalWaitingPilots = 0
      manyWaitingPilotsFlag = False
      if self.pilotWaitingFlag:
        lastUpdateTime = dateTime() - self.pilotWaitingTime * second
        result = pilotAgentsDB.countPilots( { 'TaskQueueID': tqIDList,
                                              'Status': WAITING_PILOT_STATUS },
                                            None, lastUpdateTime )
        if not result['OK']:
          self.log.error( 'Failed to get Number of Waiting pilots', result['Message'] )
          totalWaitingPilots = 0
        else:
          totalWaitingPilots = result['Value']
          self.log.verbose( 'Waiting Pilots for TaskQueue %s:' % tqIDList, totalWaitingPilots )
      if totalWaitingPilots >= totalTQJobs:
        self.log.verbose( "%d waiting pilots already for all the available jobs" % totalWaitingPilots )
        manyWaitingPilotsFlag = True
        if not self.addPilotsToEmptySites:
          continue

      self.log.verbose( "%d waiting pilots for the total of %d eligible jobs for %s" \
                       % (totalWaitingPilots, totalTQJobs, queue) )

      # Get the working proxy
      cpuTime = queueCPUTime + 86400
      self.log.verbose( "Getting pilot proxy for %s/%s %d long" % ( self.pilotDN, self.pilotGroup, cpuTime ) )
      result = gProxyManager.getPilotProxyFromDIRACGroup( self.pilotDN, self.pilotGroup, cpuTime )
      if not result['OK']:
        return result
      self.proxy = result['Value']
      # Check returned proxy lifetime
      result = self.proxy.getRemainingSecs() #pylint: disable=no-member
      if not result['OK']:
        return result
      lifetime_secs = result['Value']
      ce.setProxy( self.proxy, lifetime_secs )

      # Get the number of available slots on the target site/queue
      totalSlots = self.getQueueSlots( queue, manyWaitingPilotsFlag )
      if totalSlots == 0:
        self.log.debug( '%s: No slots available' % queue )
        continue

      if manyWaitingPilotsFlag:
        # Throttle submission of extra pilots to empty sites
        pilotsToSubmit = self.maxPilotsToSubmit/10 + 1
      else:
        pilotsToSubmit = max( 0, min( totalSlots, totalTQJobs - totalWaitingPilots ) )
        self.log.info( '%s: Slots=%d, TQ jobs=%d, Pilots: waiting %d, to submit=%d' % \
                                ( queue, totalSlots, totalTQJobs, totalWaitingPilots, pilotsToSubmit ) )

      # Limit the number of pilots to submit to MAX_PILOTS_TO_SUBMIT
      pilotsToSubmit = min( self.maxPilotsToSubmit, pilotsToSubmit )

      while pilotsToSubmit > 0:
        self.log.info( 'Going to submit %d pilots to %s queue' % ( pilotsToSubmit, queue ) )

        bundleProxy = self.queueDict[queue].get( 'BundleProxy', False )
        jobExecDir = ''
        jobExecDir = self.queueDict[queue]['ParametersDict'].get( 'JobExecDir', jobExecDir )
        httpProxy = self.queueDict[queue]['ParametersDict'].get( 'HttpProxy', '' )

        result = self.getExecutable( queue, pilotsToSubmit,
                                     bundleProxy = bundleProxy,
                                     httpProxy = httpProxy,
                                     jobExecDir = jobExecDir )
        if not result['OK']:
          return result

        executable, pilotSubmissionChunk = result['Value']
        result = ce.submitJob( executable, '', pilotSubmissionChunk )
        ### FIXME: The condor thing only transfers the file with some
        ### delay, so when we unlink here the script is gone
        ### FIXME 2: but at some time we need to clean up the pilot wrapper scripts...
        if not ( ceType == 'HTCondorCE' or ( ceType == 'Local' and ce.batchSystem == 'Condor' ) ):
          os.unlink( executable )
        if not result['OK']:
          self.log.error( 'Failed submission to queue %s:\n' % queue, result['Message'] )
          pilotsToSubmit = 0
          self.failedQueues[queue] += 1
          continue

        pilotsToSubmit = pilotsToSubmit - pilotSubmissionChunk
        # Add pilots to the PilotAgentsDB assign pilots to TaskQueue proportionally to the
        # task queue priorities
        pilotList = result['Value']
        self.queueSlots[queue]['AvailableSlots'] -= len( pilotList )
        totalSubmittedPilots += len( pilotList )
        self.log.info( 'Submitted %d pilots to %s@%s' % ( len( pilotList ), queueName, ceName ) )
        stampDict = result.get('PilotStampDict', {})
        tqPriorityList = []
        sumPriority = 0.
        for tq in taskQueueDict:
          sumPriority += taskQueueDict[tq]['Priority']
          tqPriorityList.append( ( tq, sumPriority ) )
        tqDict = {}
        for pilotID in pilotList:
          rndm = random.random() * sumPriority
          for tq, prio in tqPriorityList:
            if rndm < prio:
              tqID = tq
              break
          if tqID not in tqDict:
            tqDict[tqID] = []
          tqDict[tqID].append( pilotID )

        for tqID, pilotList in tqDict.items():
          result = pilotAgentsDB.addPilotTQReference( pilotList,
                                                      tqID,
                                                      self.pilotDN,
                                                      self.pilotGroup,
                                                      self.localhost,
                                                      ceType,
                                                      '',
                                                      stampDict )
          if not result['OK']:
            self.log.error( 'Failed add pilots to the PilotAgentsDB: ', result['Message'] )
            continue
          for pilot in pilotList:
            result = pilotAgentsDB.setPilotStatus(pilot, 'Submitted', ceName,
                                                  'Successfully submitted by the SiteDirector',
                                                  siteName, queueName )
            if not result['OK']:
              self.log.error( 'Failed to set pilot status: ', result['Message'] )
              continue

    self.log.info( "%d pilots submitted in total in this cycle, %d matched queues" \
                  % ( totalSubmittedPilots, matchedQueues ) )
    return S_OK()

  def getQueueSlots( self, queue, manyWaitingPilotsFlag ):
    """ Get the number of available slots in the queue
    """
    ce = self.queueDict[queue]['CE']
    ceName = self.queueDict[queue]['CEName']
    queueName = self.queueDict[queue]['QueueName']
    queryCEFlag = self.queueDict[queue]["QueryCEFlag"].lower() in ["1", "yes", "true"]

    self.queueSlots.setdefault( queue, {} )
    totalSlots = self.queueSlots[queue].get( 'AvailableSlots', 0 )

    # See if there are waiting pilots for this queue. If not, allow submission
    if totalSlots and manyWaitingPilotsFlag:
      result = pilotAgentsDB.selectPilots( {'DestinationSite':ceName,
                                            'Queue':queueName,
                                            'Status': WAITING_PILOT_STATUS } )
      if result['OK']:
        jobIDList = result['Value']
        if not jobIDList:
          return totalSlots
      return 0

    availableSlotsCount = self.queueSlots[queue].setdefault( 'AvailableSlotsCount', 0 )
    waitingJobs = 1
    if totalSlots == 0:
      if availableSlotsCount % 10 == 0:

        # Get the list of already existing pilots for this queue
        jobIDList = None
        result = pilotAgentsDB.selectPilots( {'DestinationSite':ceName,
                                              'Queue':queueName,
                                              'Status': TRANSIENT_PILOT_STATUS } )

        if result['OK']:
          jobIDList = result['Value']

        if queryCEFlag:
          result = ce.available( jobIDList )
          if not result['OK']:
            self.log.warn( 'Failed to check the availability of queue %s: \n%s' % ( queue, result['Message'] ) )
            self.failedQueues[queue] += 1
          else:
            ceInfoDict = result['CEInfoDict']
            self.log.info( "CE queue report(%s_%s): Wait=%d, Run=%d, Submitted=%d, Max=%d" % \
                           ( ceName, queueName, ceInfoDict['WaitingJobs'], ceInfoDict['RunningJobs'],
                             ceInfoDict['SubmittedJobs'], ceInfoDict['MaxTotalJobs'] ) )
            totalSlots = result['Value']
            self.queueSlots[queue]['AvailableSlots'] = totalSlots
            waitingJobs = ceInfoDict['WaitingJobs']
        else:
          maxWaitingJobs = int( self.queueDict[queue]['ParametersDict'].get( 'MaxWaitingJobs', 10 ) )
          maxTotalJobs = int( self.queueDict[queue]['ParametersDict'].get( 'MaxTotalJobs', 10 ) )
          waitingJobs = 0
          totalJobs = 0
          if jobIDList:
            result = pilotAgentsDB.getPilotInfo( jobIDList )
            if not result['OK']:
              self.log.warn( 'Failed to check PilotAgentsDB for queue %s: \n%s' % ( queue, result['Message'] ) )
              self.failedQueues[queue] += 1
            else:
              for _pilotRef, pilotDict in result['Value'].iteritems():
                if pilotDict["Status"] in TRANSIENT_PILOT_STATUS:
                  totalJobs += 1
                  if pilotDict["Status"] in WAITING_PILOT_STATUS:
                    waitingJobs += 1
              runningJobs = totalJobs - waitingJobs
              self.log.info( "PilotAgentsDB report(%s_%s): Wait=%d, Run=%d, Max=%d" % \
                             ( ceName, queueName, waitingJobs, runningJobs, maxTotalJobs ) )
          totalSlots = min( (maxTotalJobs - totalJobs), (maxWaitingJobs - waitingJobs) )
          self.queueSlots[queue]['AvailableSlots'] = totalSlots

    self.queueSlots[queue]['AvailableSlotsCount'] += 1

    if manyWaitingPilotsFlag and waitingJobs:
      return 0
    return totalSlots

#####################################################################################
  def getExecutable( self, queue, pilotsToSubmit, bundleProxy = True, httpProxy = '', jobExecDir = '' ):
    """ Prepare the full executable for queue
    """

    proxy = None
    if bundleProxy:
      proxy = self.proxy
    pilotOptions, pilotsToSubmit = self._getPilotOptions( queue, pilotsToSubmit )
    if pilotOptions is None:
      self.log.error( "Pilot options empty, error in compilation" )
      return S_ERROR( "Errors in compiling pilot options" )
    self.log.verbose( 'pilotOptions: ', ' '.join( pilotOptions ) )
    executable = self._writePilotScript( self.workingDirectory, pilotOptions, proxy, httpProxy, jobExecDir )
    return S_OK( [ executable, pilotsToSubmit ] )

#####################################################################################
  def _getPilotOptions( self, queue, pilotsToSubmit ):
    """ Prepare pilot options
    """
    queueDict = self.queueDict[queue]['ParametersDict']
    pilotOptions = []

    setup = gConfig.getValue( "/DIRAC/Setup", "unknown" )
    if setup == 'unknown':
      self.log.error( 'Setup is not defined in the configuration' )
      return [ None, None ]
    pilotOptions.append( '-S %s' % setup )
    opsHelper = Operations.Operations( group = self.pilotGroup, setup = setup )

    #Installation defined?
    installationName = opsHelper.getValue( "Pilot/Installation", "" )
    if installationName:
      pilotOptions.append( '-V %s' % installationName )

    #Project defined?
    projectName = opsHelper.getValue( "Pilot/Project", "" )
    if projectName:
      pilotOptions.append( '-l %s' % projectName )
    else:
      self.log.info( 'DIRAC project will be installed by pilots' )

    #Request a release
    diracVersion = opsHelper.getValue( "Pilot/Version", [] )
    if not diracVersion:
      self.log.error( 'Pilot/Version is not defined in the configuration' )
      return [ None, None ]
    # diracVersion is a list of accepted releases
    pilotOptions.append( '-r %s' % ','.join( str( it ) for it in diracVersion ) )

    #lcgBundle defined?
    lcgBundleVersion = opsHelper.getValue( "Pilot/LCGBundleVersion", "" )
    if lcgBundleVersion:
      self.log.warn( "lcgBundle version %s defined in CS: will overwrite possible per-release lcg bundle versions" %lcgBundleVersion )
      pilotOptions.append( '-g %s' % lcgBundleVersion )

    ownerDN = self.pilotDN
    ownerGroup = self.pilotGroup
    # Request token for maximum pilot efficiency
    result = gProxyManager.requestToken( ownerDN, ownerGroup, pilotsToSubmit * self.maxJobsInFillMode )
    if not result[ 'OK' ]:
      self.log.error( 'Invalid proxy token request', result['Message'] )
      return [ None, None ]
    ( token, numberOfUses ) = result[ 'Value' ]
    pilotOptions.append( '-o /Security/ProxyToken=%s' % token )
    # Use Filling mode
    pilotOptions.append( '-M %s' % min( numberOfUses, self.maxJobsInFillMode ) )

    # Since each pilot will execute min( numberOfUses, self.maxJobsInFillMode )
    # with numberOfUses tokens we can submit at most:
    #    numberOfUses / min( numberOfUses, self.maxJobsInFillMode )
    # pilots
    newPilotsToSubmit = numberOfUses / min( numberOfUses, self.maxJobsInFillMode )
    if newPilotsToSubmit != pilotsToSubmit:
      self.log.info( 'Number of pilots to submit is changed to %d after getting the proxy token' % newPilotsToSubmit )
      pilotsToSubmit = newPilotsToSubmit
    # Debug
    if self.pilotLogLevel.lower() == 'debug':
      pilotOptions.append( '-ddd' )
    # CS Servers
    csServers = gConfig.getValue( "/DIRAC/Configuration/Servers", [] )
    pilotOptions.append( '-C %s' % ",".join( csServers ) )

    # DIRAC Extensions to be used in pilots
    pilotExtensionsList = opsHelper.getValue( "Pilot/Extensions", [] )
    extensionsList = []
    if pilotExtensionsList:
      if pilotExtensionsList[0] != 'None':
        extensionsList = pilotExtensionsList
    else:
      extensionsList = [ext for ext in CSGlobals.getCSExtensions() if 'Web' not in ext]
    if extensionsList:
      pilotOptions.append( '-e %s' % ",".join( extensionsList ) )

    # Requested CPU time
    pilotOptions.append( '-T %s' % queueDict['CPUTime'] )
    # CEName
    pilotOptions.append( '-N %s' % self.queueDict[queue]['CEName'] )
    # Queue
    pilotOptions.append( '-Q %s' % self.queueDict[queue]['QueueName'] )
    # SiteName
    pilotOptions.append( '-n %s' % queueDict['Site'] )
    if 'ClientPlatform' in queueDict:
      pilotOptions.append( "-p '%s'" % queueDict['ClientPlatform'] )

    if 'SharedArea' in queueDict:
      pilotOptions.append( "-o '/LocalSite/SharedArea=%s'" % queueDict['SharedArea'] )

#     if 'SI00' in queueDict:
#       factor = float( queueDict['SI00'] ) / 250.
#       pilotOptions.append( "-o '/LocalSite/CPUScalingFactor=%s'" % factor )
#       pilotOptions.append( "-o '/LocalSite/CPUNormalizationFactor=%s'" % factor )
#     else:
#       if 'CPUScalingFactor' in queueDict:
#         pilotOptions.append( "-o '/LocalSite/CPUScalingFactor=%s'" % queueDict['CPUScalingFactor'] )
#       if 'CPUNormalizationFactor' in queueDict:
#         pilotOptions.append( "-o '/LocalSite/CPUNormalizationFactor=%s'" % queueDict['CPUNormalizationFactor'] )

    if "ExtraPilotOptions" in queueDict:
      pilotOptions.append( queueDict['ExtraPilotOptions'] )

    # Hack
    if self.defaultSubmitPools:
      pilotOptions.append( '-o /Resources/Computing/CEDefaults/SubmitPool=%s' % self.defaultSubmitPools )

    if self.group:
      pilotOptions.append( '-G %s' % self.group )

    return [ pilotOptions, pilotsToSubmit ]

####################################################################################
  def _writePilotScript( self, workingDirectory, pilotOptions, proxy = None,
                         httpProxy = '', pilotExecDir = '' ):
    """ Bundle together and write out the pilot executable script, admix the proxy if given
    """

    try:
      compressedAndEncodedProxy = ''
      proxyFlag = 'False'
      if proxy is not None:
        compressedAndEncodedProxy = base64.encodestring( bz2.compress( proxy.dumpAllToString()['Value'] ) )
        proxyFlag = 'True'
      compressedAndEncodedPilot = base64.encodestring( bz2.compress( open( self.pilot, "rb" ).read(), 9 ) )
      compressedAndEncodedInstall = base64.encodestring( bz2.compress( open( self.install, "rb" ).read(), 9 ) )
      compressedAndEncodedExtra = {}
      for module in self.extraModules:
        moduleName = os.path.basename( module )
        compressedAndEncodedExtra[moduleName] = base64.encodestring( bz2.compress( open( module, "rb" ).read(), 9 ) )
    except:
      self.log.exception( 'Exception during file compression of proxy, dirac-pilot or dirac-install' )
      return S_ERROR( 'Exception during file compression of proxy, dirac-pilot or dirac-install' )

    # Extra modules
    mStringList = []
    for moduleName in compressedAndEncodedExtra:
      mString = """open( '%s', "w" ).write(bz2.decompress( base64.decodestring( \"\"\"%s\"\"\" ) ) )""" % \
                ( moduleName, compressedAndEncodedExtra[moduleName] )
      mStringList.append( mString )
    extraModuleString = '\n  '.join( mStringList )

    localPilot = """#!/bin/bash
/usr/bin/env python << EOF
#
import os
import stat
import tempfile
import sys
import shutil
import base64
import bz2
import logging
import time

formatter = logging.Formatter(fmt='%%(asctime)s UTC %%(levelname)-8s %%(message)s', datefmt='%%Y-%%m-%%d %%H:%%M:%%S')
logging.Formatter.converter = time.gmtime
try:
  screen_handler = logging.StreamHandler(stream=sys.stdout)
except TypeError: #python2.6
  screen_handler = logging.StreamHandler(strm=sys.stdout)
screen_handler.setFormatter(formatter)
logger = logging.getLogger('pippoLogger')
logger.setLevel(logging.DEBUG)
logger.addHandler(screen_handler)

try:
  pilotExecDir = '%(pilotExecDir)s'
  if not pilotExecDir:
    pilotExecDir = os.getcwd()
  pilotWorkingDirectory = tempfile.mkdtemp( suffix = 'pilot', prefix = 'DIRAC_', dir = pilotExecDir )
  pilotWorkingDirectory = os.path.realpath( pilotWorkingDirectory )
  os.chdir( pilotWorkingDirectory )
  if %(proxyFlag)s:
    open( 'proxy', "w" ).write(bz2.decompress( base64.decodestring( \"\"\"%(compressedAndEncodedProxy)s\"\"\" ) ) )
    os.chmod("proxy", stat.S_IRUSR | stat.S_IWUSR)
    os.environ["X509_USER_PROXY"]=os.path.join(pilotWorkingDirectory, 'proxy')
  open( '%(pilotScript)s', "w" ).write(bz2.decompress( base64.decodestring( \"\"\"%(compressedAndEncodedPilot)s\"\"\" ) ) )
  open( '%(installScript)s', "w" ).write(bz2.decompress( base64.decodestring( \"\"\"%(compressedAndEncodedInstall)s\"\"\" ) ) )
  os.chmod("%(pilotScript)s", stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR )
  os.chmod("%(installScript)s", stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR )
  %(extraModuleString)s
  if "LD_LIBRARY_PATH" not in os.environ:
    os.environ["LD_LIBRARY_PATH"]=""
  if "%(httpProxy)s":
    os.environ["HTTP_PROXY"]="%(httpProxy)s"
  os.environ["X509_CERT_DIR"]=os.path.join(pilotWorkingDirectory, 'etc/grid-security/certificates')
  # TODO: structure the output
  print '==========================================================='
  logger.debug('Environment of execution host\\n')
  for key, val in os.environ.iteritems():
    logger.debug( key + '=' + val )
  print '===========================================================\\n'
except Exception as x:
  print >> sys.stderr, x
  shutil.rmtree( pilotWorkingDirectory )
  sys.exit(-1)
cmd = "python %(pilotScript)s %(pilotOptions)s"
logger.info('Executing: %%s' %% cmd)
sys.stdout.flush()
os.system( cmd )

shutil.rmtree( pilotWorkingDirectory )

EOF
""" % { 'compressedAndEncodedProxy': compressedAndEncodedProxy,
        'compressedAndEncodedPilot': compressedAndEncodedPilot,
        'compressedAndEncodedInstall': compressedAndEncodedInstall,
        'extraModuleString': extraModuleString,
        'httpProxy': httpProxy,
        'pilotExecDir': pilotExecDir,
        'pilotScript': os.path.basename( self.pilot ),
        'installScript': os.path.basename( self.install ),
        'pilotOptions': ' '.join( pilotOptions ),
        'proxyFlag': proxyFlag }

    fd, name = tempfile.mkstemp( suffix = '_pilotwrapper.py', prefix = 'DIRAC_', dir = workingDirectory )
    pilotWrapper = os.fdopen( fd, 'w' )
    pilotWrapper.write( localPilot )
    pilotWrapper.close()
    return name

  def updatePilotStatus( self ):
    """ Update status of pilots in transient states
    """
    for queue in self.queueDict:
      ce = self.queueDict[queue]['CE']
      ceName = self.queueDict[queue]['CEName']
      queueName = self.queueDict[queue]['QueueName']
      ceType = self.queueDict[queue]['CEType']
      siteName = self.queueDict[queue]['Site']
      abortedPilots = 0

      result = pilotAgentsDB.selectPilots( {'DestinationSite':ceName,
                                            'Queue':queueName,
                                            'GridType':ceType,
                                            'GridSite':siteName,
                                            'Status':TRANSIENT_PILOT_STATUS,
                                            'OwnerDN': self.pilotDN,
                                            'OwnerGroup': self.pilotGroup } )
      if not result['OK']:
        self.log.error('Failed to select pilots", ": %s' % result['Message'])
        continue
      pilotRefs = result['Value']
      if not pilotRefs:
        continue

      result = pilotAgentsDB.getPilotInfo( pilotRefs )
      if not result['OK']:
        self.log.error( 'Failed to get pilots info from DB', result['Message'] )
        continue
      pilotDict = result['Value']

      stampedPilotRefs = []
      for pRef in pilotDict:
        if pilotDict[pRef]['PilotStamp']:
          stampedPilotRefs.append( pRef + ":::" + pilotDict[pRef]['PilotStamp'] )
        else:
          stampedPilotRefs = list( pilotRefs )
          break

      # This proxy is used for checking the pilot status and renewals
      # We really need at least a few hours otherwise the renewed
      # proxy may expire before we check again...
      result = ce.isProxyValid( 3*3600 )
      if not result['OK']:
        result = gProxyManager.getPilotProxyFromDIRACGroup( self.pilotDN, self.pilotGroup, 23400 )
        if not result['OK']:
          return result
        self.proxy = result['Value']
        ce.setProxy( self.proxy, 23300 )

      result = ce.getJobStatus( stampedPilotRefs )
      if not result['OK']:
        self.log.error( 'Failed to get pilots status from CE', '%s: %s' % ( ceName, result['Message'] ) )
        continue
      pilotCEDict = result['Value']

      for pRef in pilotRefs:
        newStatus = ''
        oldStatus = pilotDict[pRef]['Status']
        if pRef in pilotCEDict:
          ceStatus = pilotCEDict[pRef]
        else:
          ceStatus = oldStatus
        lastUpdateTime = pilotDict[pRef]['LastUpdateTime']
        sinceLastUpdate = dateTime() - lastUpdateTime

        if oldStatus == ceStatus and ceStatus != "Unknown":
          # Normal status did not change, continue
          continue
        elif ceStatus == "Unknown" and oldStatus == "Unknown":
          if sinceLastUpdate < 3600*second:
            # Allow 1 hour of Unknown status assuming temporary problems on the CE
            continue
          else:
            newStatus = 'Aborted'
        elif ceStatus == "Unknown" and not oldStatus in FINAL_PILOT_STATUS:
          # Possible problems on the CE, let's keep the Unknown status for a while
          newStatus = 'Unknown'
        elif ceStatus != 'Unknown' :
          # Update the pilot status to the new value
          newStatus = ceStatus

        if newStatus:
          self.log.info( 'Updating status to %s for pilot %s' % ( newStatus, pRef ) )
          result = pilotAgentsDB.setPilotStatus( pRef, newStatus, '', 'Updated by SiteDirector' )
          if newStatus == "Aborted":
            abortedPilots += 1
        # Retrieve the pilot output now
        if newStatus in FINAL_PILOT_STATUS:
          if pilotDict[pRef]['OutputReady'].lower() == 'false' and self.getOutput:
            self.log.info( 'Retrieving output for pilot %s' % pRef )
            pilotStamp = pilotDict[pRef]['PilotStamp']
            pRefStamp = pRef
            if pilotStamp:
              pRefStamp = pRef + ':::' + pilotStamp
            result = ce.getJobOutput( pRefStamp )
            if not result['OK']:
              self.log.error( 'Failed to get pilot output', '%s: %s' % ( ceName, result['Message'] ) )
            else:
              output, error = result['Value']
              if output:
                result = pilotAgentsDB.storePilotOutput( pRef, output, error )
                if not result['OK']:
                  self.log.error( 'Failed to store pilot output', result['Message'] )
              else:
                self.log.warn( 'Empty pilot output not stored to PilotDB' )

      # If something wrong in the queue, make a pause for the job submission
      if abortedPilots:
        self.failedQueues[queue] += 1

    # The pilot can be in Done state set by the job agent check if the output is retrieved
    for queue in self.queueDict:
      ce = self.queueDict[queue]['CE']

      if not ce.isProxyValid(120)['OK']:
        result = gProxyManager.getPilotProxyFromDIRACGroup( self.pilotDN, self.pilotGroup, 1000 )
        if not result['OK']:
          return result
        self.proxy = result['Value']
        ce.setProxy( self.proxy, 940 )

      ceName = self.queueDict[queue]['CEName']
      queueName = self.queueDict[queue]['QueueName']
      ceType = self.queueDict[queue]['CEType']
      siteName = self.queueDict[queue]['Site']
      result = pilotAgentsDB.selectPilots( {'DestinationSite':ceName,
                                            'Queue':queueName,
                                            'GridType':ceType,
                                            'GridSite':siteName,
                                            'OutputReady':'False',
                                            'Status':FINAL_PILOT_STATUS} )

      if not result['OK']:
        self.log.error( 'Failed to select pilots', result['Message'] )
        continue
      pilotRefs = result['Value']
      if not pilotRefs:
        continue
      result = pilotAgentsDB.getPilotInfo( pilotRefs )
      if not result['OK']:
        self.log.error( 'Failed to get pilots info from DB', result['Message'] )
        continue
      pilotDict = result['Value']
      if self.getOutput:
        for pRef in pilotRefs:
          self.log.info( 'Retrieving output for pilot %s' % pRef )
          pilotStamp = pilotDict[pRef]['PilotStamp']
          pRefStamp = pRef
          if pilotStamp:
            pRefStamp = pRef + ':::' + pilotStamp
          result = ce.getJobOutput( pRefStamp )
          if not result['OK']:
            self.log.error( 'Failed to get pilot output', '%s: %s' % ( ceName, result['Message'] ) )
          else:
            output, error = result['Value']
            result = pilotAgentsDB.storePilotOutput( pRef, output, error )
            if not result['OK']:
              self.log.error( 'Failed to store pilot output', result['Message'] )

      # Check if the accounting is to be sent
      if self.sendAccounting:
        result = pilotAgentsDB.selectPilots( {'DestinationSite':ceName,
                                              'Queue':queueName,
                                              'GridType':ceType,
                                              'GridSite':siteName,
                                              'AccountingSent':'False',
                                              'Status':FINAL_PILOT_STATUS} )

        if not result['OK']:
          self.log.error( 'Failed to select pilots', result['Message'] )
          continue
        pilotRefs = result['Value']
        if not pilotRefs:
          continue
        result = pilotAgentsDB.getPilotInfo( pilotRefs )
        if not result['OK']:
          self.log.error( 'Failed to get pilots info from DB', result['Message'] )
          continue
        pilotDict = result['Value']
        result = self.sendPilotAccounting( pilotDict )
        if not result['OK']:
          self.log.error( 'Failed to send pilot agent accounting' )

    return S_OK()

  def sendPilotAccounting( self, pilotDict ):
    """ Send pilot accounting record
    """
    for pRef in pilotDict:
      self.log.verbose( 'Preparing accounting record for pilot %s' % pRef )
      pA = PilotAccounting()
      pA.setEndTime( pilotDict[pRef][ 'LastUpdateTime' ] )
      pA.setStartTime( pilotDict[pRef][ 'SubmissionTime' ] )
      retVal = CS.getUsernameForDN( pilotDict[pRef][ 'OwnerDN' ] )
      if not retVal[ 'OK' ]:
        userName = 'unknown'
        self.log.error( "Can't determine username for dn:", pilotDict[pRef][ 'OwnerDN' ] )
      else:
        userName = retVal[ 'Value' ]
      pA.setValueByKey( 'User', userName )
      pA.setValueByKey( 'UserGroup', pilotDict[pRef][ 'OwnerGroup' ] )
      result = getSiteForCE( pilotDict[pRef][ 'DestinationSite' ] )
      if result['OK'] and result[ 'Value' ].strip():
        pA.setValueByKey( 'Site', result['Value'].strip() )
      else:
        pA.setValueByKey( 'Site', 'Unknown' )
      pA.setValueByKey( 'GridCE', pilotDict[pRef][ 'DestinationSite' ] )
      pA.setValueByKey( 'GridMiddleware', pilotDict[pRef][ 'GridType' ] )
      pA.setValueByKey( 'GridResourceBroker', pilotDict[pRef][ 'Broker' ] )
      pA.setValueByKey( 'GridStatus', pilotDict[pRef][ 'Status' ] )
      if not 'Jobs' in pilotDict[pRef]:
        pA.setValueByKey( 'Jobs', 0 )
      else:
        pA.setValueByKey( 'Jobs', len( pilotDict[pRef]['Jobs'] ) )
      self.log.verbose( "Adding accounting record for pilot %s" % pilotDict[pRef][ 'PilotID' ] )
      retVal = gDataStoreClient.addRegister( pA )
      if not retVal[ 'OK' ]:
        self.log.error( 'Failed to send accounting info for pilot ', pRef )
      else:
        # Set up AccountingSent flag
        result = pilotAgentsDB.setAccountingFlag( pRef )
        if not result['OK']:
          self.log.error( 'Failed to set accounting flag for pilot ', pRef )

    self.log.info( 'Committing accounting records for %d pilots' % len( pilotDict ) )
    result = gDataStoreClient.commit()
    if result['OK']:
      for pRef in pilotDict:
        self.log.verbose( 'Setting AccountingSent flag for pilot %s' % pRef )
        result = pilotAgentsDB.setAccountingFlag( pRef )
        if not result['OK']:
          self.log.error( 'Failed to set accounting flag for pilot ', pRef )
    else:
      return result

    return S_OK()
