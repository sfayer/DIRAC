""" Test class for agents
"""

# pylint: disable=protected-access, missing-docstring, invalid-name, line-too-long

# imports
import importlib
import datetime

import pytest
from mock import MagicMock

from DIRAC import gLogger
# sut
from DIRAC.TransformationSystem.Agent.TaskManagerAgentBase import TaskManagerAgentBase
from DIRAC.TransformationSystem.Agent.TransformationAgent import TransformationAgent

gLogger.setLevel('DEBUG')


mockAM = MagicMock()
tmab_m = importlib.import_module('DIRAC.TransformationSystem.Agent.TaskManagerAgentBase')
tmab_m.AgentModule = mockAM
tmab_m.FileReport = MagicMock()
tmab = TaskManagerAgentBase()
tmab.log = gLogger
tmab.am_getOption = mockAM
tmab.log.setLevel('DEBUG')


@pytest.mark.parametrize("operationsOnTransformationsDict, expected", [
    ({1: {'Operations': ['op1', 'op2'], 'Body':'veryBigBody'}}, ([1], 1)),
    ({2: {'Operations': ['op3', 'op2'], 'Body':'veryveryBigBody'}}, ([1, 2], 2)),
    ({2: {'Operations': ['op3', 'op2'], 'Body':'veryveryBigBody'}}, ([1, 2], 2))
])
def test__fillTheQueue(operationsOnTransformationsDict, expected):
  tmab._fillTheQueue(operationsOnTransformationsDict)
  assert tmab.transInQueue == expected[0]
  assert tmab.transQueue.qsize() == expected[1]


# useful stuff

tc_mock = MagicMock()
tm_mock = MagicMock()
clients = {'TransformationClient': tc_mock, 'TaskManager': tm_mock}

transIDOPBody = {1: {'Operations': ['op1', 'op2'], 'Body': 'veryBigBody'}}
tasks = {'OK': True, 'Value': [{'CreationTime': None,
                                'ExternalID': '1',
                                'ExternalStatus': 'Reserved',
                                'LastUpdateTime': None,
                                'RunNumber': 0,
                                'TargetSE': 'Unknown',
                                'TaskID': 1,
                                'TransformationID': 101},
                               {'CreationTime': datetime.datetime(2014, 7, 21, 14, 19, 3),
                                'ExternalID': '0',
                                'ExternalStatus': 'Reserved',
                                'LastUpdateTime': datetime.datetime(2014, 7, 21, 14, 19, 3),
                                'RunNumber': 0,
                                'TargetSE': 'Unknown',
                                'TaskID': 2,
                                'TransformationID': 101}]}
sOk = {'OK': True, 'Value': []}
sError = {'OK': False, 'Message': 'a mess'}


@pytest.mark.parametrize("tcMockReturnValue, tmMockGetSubmittedTaskStatusReturnvalue, expected", [
    (sError, {'OK': True}, False),  # errors
    (sOk, {'OK': True}, True),  # no tasks
    (tasks, sError, False),  # tasks, fail in update
    (tasks, {'OK': True, 'Value': {}}, True),  # tasks, nothing to update
    (tasks, {'OK': True, 'Value': {'Running': [1, 2], 'Done': [3]}}, True)  # tasks, to update, no errors
])
def test_updateTaskStatusSuccess(tcMockReturnValue, tmMockGetSubmittedTaskStatusReturnvalue, expected):
  tc_mock.getTransformationTasks.return_value = tcMockReturnValue
  tm_mock.getSubmittedTaskStatus.return_value = tmMockGetSubmittedTaskStatusReturnvalue
  res = tmab.updateTaskStatus(transIDOPBody, clients)
  assert res['OK'] == expected


@pytest.mark.parametrize("tcMockGetTransformationFilesReturnValue, tmMockGetSubmittedFileStatusReturnValue, expected", [
    (sError, None, False),  # errors
    (sOk, None, True),  # no files
    ({'OK': True, 'Value': [{'file1': 'boh', 'TaskID': 1}]}, sError, False),  # files, failing to update
    ({'OK': True, 'Value': [{'file1': 'boh', 'TaskID': 1}]}, sOk, True),  # files, nothing to update
    ({'OK': True, 'Value': [{'file1': 'boh', 'TaskID': 1}]},
     {'OK': True, 'Value': {'file1': 'OK', 'file2': 'NOK'}}, True),  # files, something to update
])
def test_updateFileStatusSuccess(tcMockGetTransformationFilesReturnValue,
                                 tmMockGetSubmittedFileStatusReturnValue,
                                 expected):
  tc_mock.getTransformationFiles.return_value = tcMockGetTransformationFilesReturnValue
  tm_mock.getSubmittedFileStatus.return_value = tmMockGetSubmittedFileStatusReturnValue
  res = tmab.updateFileStatus(transIDOPBody, clients)
  assert res['OK'] == expected


@pytest.mark.parametrize("tcMockGetTransformationTasksReturnValue,"
                         + "tmMockUpdateTransformationReservedTasksReturnValue, "
                         + "tcMockSetTaskStatusAndWmsIDReturnValue, "
                         + "expected", [(sError, None, None, False),  # errors getting
                                        (sOk, None, None, True),  # no tasks
                                        (tasks, sError, None, False),  # tasks, failing to update
                                        (tasks, {'OK': True,
                                                 'Value': {'NoTasks': [], 'TaskNameIDs': {'1_1': 123, '2_1': 456}}},
                                         sError, False),  # tasks, something to update, fail
                                        (tasks, {'OK': True,
                                                 'Value': {'NoTasks': ['3_4', '5_6'],
                                                           'TaskNameIDs': {'1_1': 123, '2_1': 456}}},
                                         {'OK': True}, True)])  # tasks, something to update, no fail
def test_checkReservedTasks(tcMockGetTransformationTasksReturnValue,
                            tmMockUpdateTransformationReservedTasksReturnValue,
                            tcMockSetTaskStatusAndWmsIDReturnValue,
                            expected):
  tc_mock.getTransformationTasks.return_value = tcMockGetTransformationTasksReturnValue
  tm_mock.updateTransformationReservedTasks.return_value = tmMockUpdateTransformationReservedTasksReturnValue
  tc_mock.setTaskStatusAndWmsID.return_value = tcMockSetTaskStatusAndWmsIDReturnValue
  res = tmab.checkReservedTasks(transIDOPBody, clients)
  assert res['OK'] == expected


transIDOPBody = {1: {'Operations': ['op1', 'op2'], 'Body': 'veryBigBody',
                     'Owner': 'prodMan', 'OwnerDN': '/ca=man/user=prodMan', 'OwnerGroup': 'prodMans'}}
sOkJobDict = {'OK': True, 'Value': {'JobDictionary': {123: 'foo', 456: 'bar'}}}
sOkJobs = {'OK': True, 'Value': {123: 'foo', 456: 'bar'}}


@pytest.mark.parametrize("tcMockGetTasksToSubmitReturnValue, "
                         + "tmMockPrepareTransformationTasksReturnValue, "
                         + "tmMockSubmitTransformationTasksReturnValue, "
                         + "tmMockUpdateDBAfterTaskSubmissionReturnValue, "
                         + "expected", [(sError, None, None, None, False),  # errors getting
                                        ({'OK': True, 'Value': {'JobDictionary': {}}},
                                         None, None, None, True),  # no tasks
                                        (sOkJobDict, sError, None, None, False),  # tasks, errors
                                        (sOkJobDict, sOkJobs, sError, None, False),  # tasks, still errors
                                        (sOkJobDict, sOkJobs, sOk, sError, False),  # tasks, still errors
                                        (sOkJobDict, sOkJobs, sOk, sOk, True)])  # tasks, no errors
def test_submitTasks(tcMockGetTasksToSubmitReturnValue,
                     tmMockPrepareTransformationTasksReturnValue,
                     tmMockSubmitTransformationTasksReturnValue,
                     tmMockUpdateDBAfterTaskSubmissionReturnValue,
                     expected):
  tc_mock.getTasksToSubmit.return_value = tcMockGetTasksToSubmitReturnValue
  tm_mock.prepareTransformationTasks.return_value = tmMockPrepareTransformationTasksReturnValue
  tm_mock.submitTransformationTasks.return_value = tmMockSubmitTransformationTasksReturnValue
  tm_mock.updateDBAfterTaskSubmission.return_value = tmMockUpdateDBAfterTaskSubmissionReturnValue
  res = tmab.submitTasks(transIDOPBody, clients)
  assert res['OK'] == expected


# TransformationAgent


ta_m = importlib.import_module('DIRAC.TransformationSystem.Agent.TransformationAgent')
ta_m.AgentModule = mockAM
ta = TransformationAgent()
ta.log = gLogger
ta.am_getOption = mockAM

goodFiles = {'OK': True,
             'Value': [{'ErrorCount': 1,
                        'FileID': 17990660,
                        'InsertedTime': datetime.datetime(2012, 3, 15, 17, 5, 50),
                        'LFN': '/00012574_00000239_1.charmcompleteevent.dst',
                        'LastUpdate': datetime.datetime(2012, 3, 16, 23, 43, 26),
                        'RunNumber': 90269,
                        'Status': 'Unused',
                        'TargetSE': 'Unknown',
                        'TaskID': '222',
                        'TransformationID': 17042,
                        'UsedSE': 'CERN-DST,IN2P3-DST,PIC-DST,RAL-DST'},
                       {'ErrorCount': 1,
                        'FileID': 17022945,
                        'InsertedTime': datetime.datetime(2012, 3, 15, 17, 5, 50),
                        'LFN': '/00012574_00000119_1.charmcompleteevent.dst',
                        'LastUpdate': datetime.datetime(2012, 3, 16, 23, 54, 59),
                        'RunNumber': 90322,
                        'Status': 'Unused',
                        'TargetSE': 'Unknown',
                        'TaskID': '82',
                        'TransformationID': 17042,
                        'UsedSE': 'CERN-DST,CNAF-DST,RAL-DST,SARA-DST'}]
             }
noFiles = {'OK': True, 'Value': []}


@pytest.mark.parametrize("transDict, getTFiles, expected", [
    ({'TransformationID': 123, 'Status': 'Stopped', 'Type': 'Replication'}, goodFiles, True),
    ({'TransformationID': 123, 'Status': 'Stopped', 'Type': 'Removal'}, noFiles, True)
])
def test__getTransformationFiles(transDict, getTFiles, expected):
  tc_mock.getTransformationFiles.return_value = getTFiles
  res = ta._getTransformationFiles(transDict, {'TransformationClient': tc_mock})
  assert res['OK'] == expected
