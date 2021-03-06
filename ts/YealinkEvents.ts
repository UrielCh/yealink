export type YealinkEvents =
  | "AUSetupCompleted"
  | "AULogOn"
  | "AULogOff"
  | "AURegisterFailed"
  | "AUOffHook"
  | "AUOnHook"
  | "AUIncomingCall"
  | "AUCallOut"
  | "AUEstablished"
  | "AUTerminated"
  | "AUOpenDnd"
  | "AUCloseDnd"
  | "AUOpenAlwaysForward"
  | "AUCloseAlwaysForward"
  | "AUOpenBusyForward"
  | "AUCloseBusyForward"
  | "AUOpenNoAnswerForward"
  | "AUCloseNoAnswerForward"
  | "AUTransferCall"
  | "AUBlindTransfer"
  | "AUAttendedTransfer"
  | "AUHold"
  | "AUUnHold"
  | "AURemoteHold"
  | "AURemoteUnHold"
  | "AUMute"
  | "AUUnMute"
  | "AUMissedCall"
  | "AUIpChanged"
  | "AUBusyToIdle"
  | "AUIdleToBusy"
  | "AURejectIncomingCall"
  | "AUAnswerNewInCall"
  | "AUTransferFailed"
  | "AUTransferFinished"
  | "AUForwardIncomingCall"
  | "AUUCServer"
  | "AURemoteIP"
  | "AUAutopFinish"
  | "AUOpenCallWait"
  | "AUCloseCallWait"
  | "AUHeadSet"
  | "AUHandFree"
  | "AUCancelCallOut"
  | "AURemoteBusy"
  | "AUCallRemoteCanceled"
  | "AUPeripheralInformation";

export default YealinkEvents;