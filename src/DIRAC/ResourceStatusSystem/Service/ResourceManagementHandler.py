""" ResourceManagementHandler

  Module that allows users to access the ResourceManagementDB remotely.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import six

from DIRAC import gConfig, S_OK
from DIRAC.Core.DISET.RequestHandler import RequestHandler, getServiceOption
from DIRAC.ResourceStatusSystem.Utilities import Synchronizer
from DIRAC.ResourceStatusSystem.Service.ResourceStatusHandler import loadResourceStatusComponent

__RCSID__ = "$Id$"


class ResourceManagementHandler(RequestHandler):
    """
  The ResourceManagementHandler exposes the DB front-end functions through a
  XML-RPC server, functionalities inherited from :class:`DIRAC.Core.DISET.Reques\
  tHandler.RequestHandler`

  According to the ResourceManagementDB philosophy, only functions of the type:
  - insert
  - select
  - delete
  - addOrModify

  are exposed. If you need anything more complicated, either look for it on the
  :class:`ResourceManagementClient`, or code it yourself. This way the DB and the
  Service are kept clean and tidied.

  To can use this service on this way, but you MUST NOT DO IT. Use it through the
  :class:`ResourceManagementClient`. If offers in the worst case as good perfor\
  mance as the :class:`ResourceManagementHandler`, if not better.

   >>> from DIRAC.Core.DISET.RPCClient import RPCCLient
   >>> server = RPCCLient("ResourceStatus/ResourceManagement")
  """

    def __init__(self, *args, **kwargs):
        super(ResourceManagementHandler, self).__init__(*args, **kwargs)

    @classmethod
    def initializeHandler(cls, serviceInfoDict):
        """
        Dynamically loads ResourceManagement database plugin module, as advised by the config,
        (assumes that the module name and a class name are the same)

        :param serviceInfoDict: service info dictionary
        :return: standard Dirac return object
        """
        defaultOption, defaultClass = "ResourceManagementDB", "ResourceManagementDB"
        configValue = getServiceOption(serviceInfoDict, defaultOption, defaultClass)
        result = loadResourceStatusComponent(configValue, configValue)

        if not result["OK"]:
            return result

        cls.db = result["Value"]
        syncObject = Synchronizer.Synchronizer()
        gConfig.addListenerToNewVersionEvent(syncObject.sync)

        return S_OK()

    def __logResult(self, methodName, result):
        """
        Method that writes to log error messages
        """

        if not result["OK"]:
            self.log.error("%s : %s" % (methodName, result["Message"]))

    types_insert = [six.string_types, dict]

    def export_insert(self, table, params):
        """
        This method is a bridge to access :class:`ResourceManagementDB` remotely. It
        does not add neither processing nor validation. If you need to know more
        about this method, you must keep reading on the database documentation.

        :Parameters:
          **table** - `string` or `dict`
            should contain the table from which querying
            if it's a `dict` the query comes from a client prior to v6r18

          **params** - `dict`
            arguments for the mysql query. Currently it is being used only for column selection.
            For example: meta = { 'columns' : [ 'Name' ] } will return only the 'Name' column.

        :return: S_OK() || S_ERROR()
        """

        self.log.info("insert: %s %s" % (table, params))

        # remove unnecessary key generated by locals()
        del params["self"]

        res = self.db.insert(table, params)
        self.__logResult("insert", res)

        return res

    types_select = [[six.string_types, dict], dict]

    def export_select(self, table, params):
        """
        This method is a bridge to access :class:`ResourceManagementDB` remotely.
        It does not add neither processing nor validation. If you need to know more\
        about this method, you must keep reading on the database documentation.

        :Parameters:
          **table** - `string` or `dict`
            should contain the table from which querying
            if it's a `dict` the query comes from a client prior to v6r18

          **params** - `dict`
            arguments for the mysql query. Currently it is being used only for column selection.
            For example: meta = { 'columns' : [ 'Name' ] } will return only the 'Name' column.

        :return: S_OK() || S_ERROR()
        """

        params = {k: list(set(v)) if isinstance(v, list) else v for k, v in params.items()}
        self.log.info("select: %s %s" % (table, params))

        res = self.db.select(table, params)
        self.__logResult("select", res)

        return res

    types_delete = [[six.string_types, dict], dict]

    def export_delete(self, table, params):
        """
        This method is a bridge to access :class:`ResourceManagementDB` remotely.\
        It does not add neither processing nor validation. If you need to know more \
        about this method, you must keep reading on the database documentation.

        :Parameters:
          **table** - `string` or `dict`
            should contain the table from which querying
            if it's a `dict` the query comes from a client prior to v6r18

          **params** - `dict`
            arguments for the mysql query. Currently it is being used only for column selection.
            For example: meta = { 'columns' : [ 'Name' ] } will return only the 'Name' column.


        :return: S_OK() || S_ERROR()
        """

        self.log.info("delete: %s %s" % (table, params))

        res = self.db.delete(table, params)
        self.__logResult("delete", res)

        return res

    types_addOrModify = [[six.string_types, dict], dict]

    def export_addOrModify(self, table, params):
        """
        This method is a bridge to access :class:`ResourceManagementDB` remotely. It does
        not add neither processing nor validation. If you need to know more about
        this method, you must keep reading on the database documentation.

        :Parameters:
          **table** - `string` or `dict`
            should contain the table from which querying
            if it's a `dict` the query comes from a client prior to v6r18

          **params** - `dict`
            arguments for the mysql query. Currently it is being used only for column selection.
            For example: meta = { 'columns' : [ 'Name' ] } will return only the 'Name' column.

        :return: S_OK() || S_ERROR()
        """

        self.log.info("addOrModify: %s %s" % (table, params))

        res = self.db.addOrModify(table, params)
        self.__logResult("addOrModify", res)

        return res
