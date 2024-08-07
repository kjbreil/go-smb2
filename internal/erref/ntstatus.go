package erref

type NtStatus uint32

func (e NtStatus) Error() string {
	return ntStatusStrings[e]
}

const (
	StatusSuccess                                               NtStatus = 0x00000000
	StatusWait0                                                 NtStatus = 0x00000000
	StatusWait1                                                 NtStatus = 0x00000001
	StatusWait2                                                 NtStatus = 0x00000002
	StatusWait3                                                 NtStatus = 0x00000003
	StatusWait63                                                NtStatus = 0x0000003F
	StatusAbandoned                                             NtStatus = 0x00000080
	StatusAbandonedWait0                                        NtStatus = 0x00000080
	StatusAbandonedWait63                                       NtStatus = 0x000000BF
	StatusUserApc                                               NtStatus = 0x000000C0
	StatusAlerted                                               NtStatus = 0x00000101
	StatusTimeout                                               NtStatus = 0x00000102
	StatusPending                                               NtStatus = 0x00000103
	StatusReparse                                               NtStatus = 0x00000104
	StatusMoreEntries                                           NtStatus = 0x00000105
	StatusNotAllAssigned                                        NtStatus = 0x00000106
	StatusSomeNotMapped                                         NtStatus = 0x00000107
	StatusOplockBreakInProgress                                 NtStatus = 0x00000108
	StatusVolumeMounted                                         NtStatus = 0x00000109
	StatusRxactCommitted                                        NtStatus = 0x0000010A
	StatusNotifyCleanup                                         NtStatus = 0x0000010B
	StatusNotifyEnumDir                                         NtStatus = 0x0000010C
	StatusNoQuotasForAccount                                    NtStatus = 0x0000010D
	StatusPrimaryTransportConnectFailed                         NtStatus = 0x0000010E
	StatusPageFaultTransition                                   NtStatus = 0x00000110
	StatusPageFaultDemandZero                                   NtStatus = 0x00000111
	StatusPageFaultCopyOnWrite                                  NtStatus = 0x00000112
	StatusPageFaultGuardPage                                    NtStatus = 0x00000113
	StatusPageFaultPagingFile                                   NtStatus = 0x00000114
	StatusCachePageLocked                                       NtStatus = 0x00000115
	StatusCrashDump                                             NtStatus = 0x00000116
	StatusBufferAllZeros                                        NtStatus = 0x00000117
	StatusReparseObject                                         NtStatus = 0x00000118
	StatusResourceRequirementsChanged                           NtStatus = 0x00000119
	StatusTranslationComplete                                   NtStatus = 0x00000120
	StatusDsMembershipEvaluatedLocally                          NtStatus = 0x00000121
	StatusNothingToTerminate                                    NtStatus = 0x00000122
	StatusProcessNotInJob                                       NtStatus = 0x00000123
	StatusProcessInJob                                          NtStatus = 0x00000124
	StatusVolsnapHibernateReady                                 NtStatus = 0x00000125
	StatusFsfilterOpCompletedSuccessfully                       NtStatus = 0x00000126
	StatusInterruptVectorAlreadyConnected                       NtStatus = 0x00000127
	StatusInterruptStillConnected                               NtStatus = 0x00000128
	StatusProcessCloned                                         NtStatus = 0x00000129
	StatusFileLockedWithOnlyReaders                             NtStatus = 0x0000012A
	StatusFileLockedWithWriters                                 NtStatus = 0x0000012B
	StatusResourcemanagerReadOnly                               NtStatus = 0x00000202
	StatusWaitForOplock                                         NtStatus = 0x00000367
	DbgExceptionHandled                                         NtStatus = 0x00010001
	DbgContinue                                                 NtStatus = 0x00010002
	StatusFltIoComplete                                         NtStatus = 0x001C0001
	StatusFileNotAvailable                                      NtStatus = 0xC0000467
	StatusCallbackReturnedThreadAffinity                        NtStatus = 0xC0000721
	StatusObjectNameExists                                      NtStatus = 0x40000000
	StatusThreadWasSuspended                                    NtStatus = 0x40000001
	StatusWorkingSetLimitRange                                  NtStatus = 0x40000002
	StatusImageNotAtBase                                        NtStatus = 0x40000003
	StatusRxactStateCreated                                     NtStatus = 0x40000004
	StatusSegmentNotification                                   NtStatus = 0x40000005
	StatusLocalUserSessionKey                                   NtStatus = 0x40000006
	StatusBadCurrentDirectory                                   NtStatus = 0x40000007
	StatusSerialMoreWrites                                      NtStatus = 0x40000008
	StatusRegistryRecovered                                     NtStatus = 0x40000009
	StatusFtReadRecoveryFromBackup                              NtStatus = 0x4000000A
	StatusFtWriteRecovery                                       NtStatus = 0x4000000B
	StatusSerialCounterTimeout                                  NtStatus = 0x4000000C
	StatusNullLmPassword                                        NtStatus = 0x4000000D
	StatusImageMachineTypeMismatch                              NtStatus = 0x4000000E
	StatusReceivePartial                                        NtStatus = 0x4000000F
	StatusReceiveExpedited                                      NtStatus = 0x40000010
	StatusReceivePartialExpedited                               NtStatus = 0x40000011
	StatusEventDone                                             NtStatus = 0x40000012
	StatusEventPending                                          NtStatus = 0x40000013
	StatusCheckingFileSystem                                    NtStatus = 0x40000014
	StatusFatalAppExit                                          NtStatus = 0x40000015
	StatusPredefinedHandle                                      NtStatus = 0x40000016
	StatusWasUnlocked                                           NtStatus = 0x40000017
	StatusServiceNotification                                   NtStatus = 0x40000018
	StatusWasLocked                                             NtStatus = 0x40000019
	StatusLogHardError                                          NtStatus = 0x4000001A
	StatusAlreadyWin32                                          NtStatus = 0x4000001B
	StatusWx86Unsimulate                                        NtStatus = 0x4000001C
	StatusWx86Continue                                          NtStatus = 0x4000001D
	StatusWx86SingleStep                                        NtStatus = 0x4000001E
	StatusWx86Breakpoint                                        NtStatus = 0x4000001F
	StatusWx86ExceptionContinue                                 NtStatus = 0x40000020
	StatusWx86ExceptionLastchance                               NtStatus = 0x40000021
	StatusWx86ExceptionChain                                    NtStatus = 0x40000022
	StatusImageMachineTypeMismatchExe                           NtStatus = 0x40000023
	StatusNoYieldPerformed                                      NtStatus = 0x40000024
	StatusTimerResumeIgnored                                    NtStatus = 0x40000025
	StatusArbitrationUnhandled                                  NtStatus = 0x40000026
	StatusCardbusNotSupported                                   NtStatus = 0x40000027
	StatusWx86Createwx86tib                                     NtStatus = 0x40000028
	StatusMpProcessorMismatch                                   NtStatus = 0x40000029
	StatusHibernated                                            NtStatus = 0x4000002A
	StatusResumeHibernation                                     NtStatus = 0x4000002B
	StatusFirmwareUpdated                                       NtStatus = 0x4000002C
	StatusDriversLeakingLockedPages                             NtStatus = 0x4000002D
	StatusMessageRetrieved                                      NtStatus = 0x4000002E
	StatusSystemPowerstateTransition                            NtStatus = 0x4000002F
	StatusAlpcCheckCompletionList                               NtStatus = 0x40000030
	StatusSystemPowerstateComplexTransition                     NtStatus = 0x40000031
	StatusAccessAuditByPolicy                                   NtStatus = 0x40000032
	StatusAbandonHiberfile                                      NtStatus = 0x40000033
	StatusBizrulesNotEnabled                                    NtStatus = 0x40000034
	StatusWakeSystem                                            NtStatus = 0x40000294
	StatusDsShuttingDown                                        NtStatus = 0x40000370
	DbgReplyLater                                               NtStatus = 0x40010001
	DbgUnableToProvideHandle                                    NtStatus = 0x40010002
	DbgTerminateThread                                          NtStatus = 0x40010003
	DbgTerminateProcess                                         NtStatus = 0x40010004
	DbgControlC                                                 NtStatus = 0x40010005
	DbgPrintexceptionC                                          NtStatus = 0x40010006
	DbgRipexception                                             NtStatus = 0x40010007
	DbgControlBreak                                             NtStatus = 0x40010008
	DbgCommandException                                         NtStatus = 0x40010009
	RpcNtUuidLocalOnly                                          NtStatus = 0x40020056
	RpcNtSendIncomplete                                         NtStatus = 0x400200AF
	StatusCtxCdmConnect                                         NtStatus = 0x400A0004
	StatusCtxCdmDisconnect                                      NtStatus = 0x400A0005
	StatusSxsReleaseActivationContext                           NtStatus = 0x4015000D
	StatusRecoveryNotNeeded                                     NtStatus = 0x40190034
	StatusRmAlreadyStarted                                      NtStatus = 0x40190035
	StatusLogNoRestart                                          NtStatus = 0x401A000C
	StatusVideoDriverDebugReportRequest                         NtStatus = 0x401B00EC
	StatusGraphicsPartialDataPopulated                          NtStatus = 0x401E000A
	StatusGraphicsDriverMismatch                                NtStatus = 0x401E0117
	StatusGraphicsModeNotPinned                                 NtStatus = 0x401E0307
	StatusGraphicsNoPreferredMode                               NtStatus = 0x401E031E
	StatusGraphicsDatasetIsEmpty                                NtStatus = 0x401E034B
	StatusGraphicsNoMoreElementsInDataset                       NtStatus = 0x401E034C
	StatusGraphicsPathContentGeometryTransformationNotPinned    NtStatus = 0x401E0351
	StatusGraphicsUnknownChildStatus                            NtStatus = 0x401E042F
	StatusGraphicsLeadlinkStartDeferred                         NtStatus = 0x401E0437
	StatusGraphicsPollingTooFrequently                          NtStatus = 0x401E0439
	StatusGraphicsStartDeferred                                 NtStatus = 0x401E043A
	StatusNdisIndicationRequired                                NtStatus = 0x40230001
	StatusGuardPageViolation                                    NtStatus = 0x80000001
	StatusDatatypeMisalignment                                  NtStatus = 0x80000002
	StatusBreakpoint                                            NtStatus = 0x80000003
	StatusSingleStep                                            NtStatus = 0x80000004
	StatusBufferOverflow                                        NtStatus = 0x80000005
	StatusNoMoreFiles                                           NtStatus = 0x80000006
	StatusWakeSystemDebugger                                    NtStatus = 0x80000007
	StatusHandlesClosed                                         NtStatus = 0x8000000A
	StatusNoInheritance                                         NtStatus = 0x8000000B
	StatusGuidSubstitutionMade                                  NtStatus = 0x8000000C
	StatusPartialCopy                                           NtStatus = 0x8000000D
	StatusDevicePaperEmpty                                      NtStatus = 0x8000000E
	StatusDevicePoweredOff                                      NtStatus = 0x8000000F
	StatusDeviceOffLine                                         NtStatus = 0x80000010
	StatusDeviceBusy                                            NtStatus = 0x80000011
	StatusNoMoreEas                                             NtStatus = 0x80000012
	StatusInvalidEaName                                         NtStatus = 0x80000013
	StatusEaListInconsistent                                    NtStatus = 0x80000014
	StatusInvalidEaFlag                                         NtStatus = 0x80000015
	StatusVerifyRequired                                        NtStatus = 0x80000016
	StatusExtraneousInformation                                 NtStatus = 0x80000017
	StatusRxactCommitNecessary                                  NtStatus = 0x80000018
	StatusNoMoreEntries                                         NtStatus = 0x8000001A
	StatusFilemarkDetected                                      NtStatus = 0x8000001B
	StatusMediaChanged                                          NtStatus = 0x8000001C
	StatusBusReset                                              NtStatus = 0x8000001D
	StatusEndOfMedia                                            NtStatus = 0x8000001E
	StatusBeginningOfMedia                                      NtStatus = 0x8000001F
	StatusMediaCheck                                            NtStatus = 0x80000020
	StatusSetmarkDetected                                       NtStatus = 0x80000021
	StatusNoDataDetected                                        NtStatus = 0x80000022
	StatusRedirectorHasOpenHandles                              NtStatus = 0x80000023
	StatusServerHasOpenHandles                                  NtStatus = 0x80000024
	StatusAlreadyDisconnected                                   NtStatus = 0x80000025
	StatusLongjump                                              NtStatus = 0x80000026
	StatusCleanerCartridgeInstalled                             NtStatus = 0x80000027
	StatusPlugplayQueryVetoed                                   NtStatus = 0x80000028
	StatusUnwindConsolidate                                     NtStatus = 0x80000029
	StatusRegistryHiveRecovered                                 NtStatus = 0x8000002A
	StatusDllMightBeInsecure                                    NtStatus = 0x8000002B
	StatusDllMightBeIncompatible                                NtStatus = 0x8000002C
	StatusStoppedOnSymlink                                      NtStatus = 0x8000002D
	StatusDeviceRequiresCleaning                                NtStatus = 0x80000288
	StatusDeviceDoorOpen                                        NtStatus = 0x80000289
	StatusDataLostRepair                                        NtStatus = 0x80000803
	DbgExceptionNotHandled                                      NtStatus = 0x80010001
	StatusClusterNodeAlreadyUp                                  NtStatus = 0x80130001
	StatusClusterNodeAlreadyDown                                NtStatus = 0x80130002
	StatusClusterNetworkAlreadyOnline                           NtStatus = 0x80130003
	StatusClusterNetworkAlreadyOffline                          NtStatus = 0x80130004
	StatusClusterNodeAlreadyMember                              NtStatus = 0x80130005
	StatusCouldNotResizeLog                                     NtStatus = 0x80190009
	StatusNoTxfMetadata                                         NtStatus = 0x80190029
	StatusCantRecoverWithHandleOpen                             NtStatus = 0x80190031
	StatusTxfMetadataAlreadyPresent                             NtStatus = 0x80190041
	StatusTransactionScopeCallbacksNotSet                       NtStatus = 0x80190042
	StatusVideoHungDisplayDriverThreadRecovered                 NtStatus = 0x801B00EB
	StatusFltBufferTooSmall                                     NtStatus = 0x801C0001
	StatusFvePartialMetadata                                    NtStatus = 0x80210001
	StatusFveTransientState                                     NtStatus = 0x80210002
	StatusUnsuccessful                                          NtStatus = 0xC0000001
	StatusNotImplemented                                        NtStatus = 0xC0000002
	StatusInvalidInfoClass                                      NtStatus = 0xC0000003
	StatusInfoLengthMismatch                                    NtStatus = 0xC0000004
	StatusAccessViolation                                       NtStatus = 0xC0000005
	StatusInPageError                                           NtStatus = 0xC0000006
	StatusPagefileQuota                                         NtStatus = 0xC0000007
	StatusInvalidHandle                                         NtStatus = 0xC0000008
	StatusBadInitialStack                                       NtStatus = 0xC0000009
	StatusBadInitialPc                                          NtStatus = 0xC000000A
	StatusInvalidCid                                            NtStatus = 0xC000000B
	StatusTimerNotCanceled                                      NtStatus = 0xC000000C
	StatusInvalidParameter                                      NtStatus = 0xC000000D
	StatusNoSuchDevice                                          NtStatus = 0xC000000E
	StatusNoSuchFile                                            NtStatus = 0xC000000F
	StatusInvalidDeviceRequest                                  NtStatus = 0xC0000010
	StatusEndOfFile                                             NtStatus = 0xC0000011
	StatusWrongVolume                                           NtStatus = 0xC0000012
	StatusNoMediaInDevice                                       NtStatus = 0xC0000013
	StatusUnrecognizedMedia                                     NtStatus = 0xC0000014
	StatusNonexistentSector                                     NtStatus = 0xC0000015
	StatusMoreProcessingRequired                                NtStatus = 0xC0000016
	StatusNoMemory                                              NtStatus = 0xC0000017
	StatusConflictingAddresses                                  NtStatus = 0xC0000018
	StatusNotMappedView                                         NtStatus = 0xC0000019
	StatusUnableToFreeVm                                        NtStatus = 0xC000001A
	StatusUnableToDeleteSection                                 NtStatus = 0xC000001B
	StatusInvalidSystemService                                  NtStatus = 0xC000001C
	StatusIllegalInstruction                                    NtStatus = 0xC000001D
	StatusInvalidLockSequence                                   NtStatus = 0xC000001E
	StatusInvalidViewSize                                       NtStatus = 0xC000001F
	StatusInvalidFileForSection                                 NtStatus = 0xC0000020
	StatusAlreadyCommitted                                      NtStatus = 0xC0000021
	StatusAccessDenied                                          NtStatus = 0xC0000022
	StatusBufferTooSmall                                        NtStatus = 0xC0000023
	StatusObjectTypeMismatch                                    NtStatus = 0xC0000024
	StatusNoncontinuableException                               NtStatus = 0xC0000025
	StatusInvalidDisposition                                    NtStatus = 0xC0000026
	StatusUnwind                                                NtStatus = 0xC0000027
	StatusBadStack                                              NtStatus = 0xC0000028
	StatusInvalidUnwindTarget                                   NtStatus = 0xC0000029
	StatusNotLocked                                             NtStatus = 0xC000002A
	StatusParityError                                           NtStatus = 0xC000002B
	StatusUnableToDecommitVm                                    NtStatus = 0xC000002C
	StatusNotCommitted                                          NtStatus = 0xC000002D
	StatusInvalidPortAttributes                                 NtStatus = 0xC000002E
	StatusPortMessageTooLong                                    NtStatus = 0xC000002F
	StatusInvalidParameterMix                                   NtStatus = 0xC0000030
	StatusInvalidQuotaLower                                     NtStatus = 0xC0000031
	StatusDiskCorruptError                                      NtStatus = 0xC0000032
	StatusObjectNameInvalid                                     NtStatus = 0xC0000033
	StatusObjectNameNotFound                                    NtStatus = 0xC0000034
	StatusObjectNameCollision                                   NtStatus = 0xC0000035
	StatusPortDisconnected                                      NtStatus = 0xC0000037
	StatusDeviceAlreadyAttached                                 NtStatus = 0xC0000038
	StatusObjectPathInvalid                                     NtStatus = 0xC0000039
	StatusObjectPathNotFound                                    NtStatus = 0xC000003A
	StatusObjectPathSyntaxBad                                   NtStatus = 0xC000003B
	StatusDataOverrun                                           NtStatus = 0xC000003C
	StatusDataLateError                                         NtStatus = 0xC000003D
	StatusDataError                                             NtStatus = 0xC000003E
	StatusCrcError                                              NtStatus = 0xC000003F
	StatusSectionTooBig                                         NtStatus = 0xC0000040
	StatusPortConnectionRefused                                 NtStatus = 0xC0000041
	StatusInvalidPortHandle                                     NtStatus = 0xC0000042
	StatusSharingViolation                                      NtStatus = 0xC0000043
	StatusQuotaExceeded                                         NtStatus = 0xC0000044
	StatusInvalidPageProtection                                 NtStatus = 0xC0000045
	StatusMutantNotOwned                                        NtStatus = 0xC0000046
	StatusSemaphoreLimitExceeded                                NtStatus = 0xC0000047
	StatusPortAlreadySet                                        NtStatus = 0xC0000048
	StatusSectionNotImage                                       NtStatus = 0xC0000049
	StatusSuspendCountExceeded                                  NtStatus = 0xC000004A
	StatusThreadIsTerminating                                   NtStatus = 0xC000004B
	StatusBadWorkingSetLimit                                    NtStatus = 0xC000004C
	StatusIncompatibleFileMap                                   NtStatus = 0xC000004D
	StatusSectionProtection                                     NtStatus = 0xC000004E
	StatusEasNotSupported                                       NtStatus = 0xC000004F
	StatusEaTooLarge                                            NtStatus = 0xC0000050
	StatusNonexistentEaEntry                                    NtStatus = 0xC0000051
	StatusNoEasOnFile                                           NtStatus = 0xC0000052
	StatusEaCorruptError                                        NtStatus = 0xC0000053
	StatusFileLockConflict                                      NtStatus = 0xC0000054
	StatusLockNotGranted                                        NtStatus = 0xC0000055
	StatusDeletePending                                         NtStatus = 0xC0000056
	StatusCtlFileNotSupported                                   NtStatus = 0xC0000057
	StatusUnknownRevision                                       NtStatus = 0xC0000058
	StatusRevisionMismatch                                      NtStatus = 0xC0000059
	StatusInvalidOwner                                          NtStatus = 0xC000005A
	StatusInvalidPrimaryGroup                                   NtStatus = 0xC000005B
	StatusNoImpersonationToken                                  NtStatus = 0xC000005C
	StatusCantDisableMandatory                                  NtStatus = 0xC000005D
	StatusNoLogonServers                                        NtStatus = 0xC000005E
	StatusNoSuchLogonSession                                    NtStatus = 0xC000005F
	StatusNoSuchPrivilege                                       NtStatus = 0xC0000060
	StatusPrivilegeNotHeld                                      NtStatus = 0xC0000061
	StatusInvalidAccountName                                    NtStatus = 0xC0000062
	StatusUserExists                                            NtStatus = 0xC0000063
	StatusNoSuchUser                                            NtStatus = 0xC0000064
	StatusGroupExists                                           NtStatus = 0xC0000065
	StatusNoSuchGroup                                           NtStatus = 0xC0000066
	StatusMemberInGroup                                         NtStatus = 0xC0000067
	StatusMemberNotInGroup                                      NtStatus = 0xC0000068
	StatusLastAdmin                                             NtStatus = 0xC0000069
	StatusWrongPassword                                         NtStatus = 0xC000006A
	StatusIllFormedPassword                                     NtStatus = 0xC000006B
	StatusPasswordRestriction                                   NtStatus = 0xC000006C
	StatusLogonFailure                                          NtStatus = 0xC000006D
	StatusAccountRestriction                                    NtStatus = 0xC000006E
	StatusInvalidLogonHours                                     NtStatus = 0xC000006F
	StatusInvalidWorkstation                                    NtStatus = 0xC0000070
	StatusPasswordExpired                                       NtStatus = 0xC0000071
	StatusAccountDisabled                                       NtStatus = 0xC0000072
	StatusNoneMapped                                            NtStatus = 0xC0000073
	StatusTooManyLuidsRequested                                 NtStatus = 0xC0000074
	StatusLuidsExhausted                                        NtStatus = 0xC0000075
	StatusInvalidSubAuthority                                   NtStatus = 0xC0000076
	StatusInvalidAcl                                            NtStatus = 0xC0000077
	StatusInvalidSid                                            NtStatus = 0xC0000078
	StatusInvalidSecurityDescr                                  NtStatus = 0xC0000079
	StatusProcedureNotFound                                     NtStatus = 0xC000007A
	StatusInvalidImageFormat                                    NtStatus = 0xC000007B
	StatusNoToken                                               NtStatus = 0xC000007C
	StatusBadInheritanceAcl                                     NtStatus = 0xC000007D
	StatusRangeNotLocked                                        NtStatus = 0xC000007E
	StatusDiskFull                                              NtStatus = 0xC000007F
	StatusServerDisabled                                        NtStatus = 0xC0000080
	StatusServerNotDisabled                                     NtStatus = 0xC0000081
	StatusTooManyGuidsRequested                                 NtStatus = 0xC0000082
	StatusGuidsExhausted                                        NtStatus = 0xC0000083
	StatusInvalidIdAuthority                                    NtStatus = 0xC0000084
	StatusAgentsExhausted                                       NtStatus = 0xC0000085
	StatusInvalidVolumeLabel                                    NtStatus = 0xC0000086
	StatusSectionNotExtended                                    NtStatus = 0xC0000087
	StatusNotMappedData                                         NtStatus = 0xC0000088
	StatusResourceDataNotFound                                  NtStatus = 0xC0000089
	StatusResourceTypeNotFound                                  NtStatus = 0xC000008A
	StatusResourceNameNotFound                                  NtStatus = 0xC000008B
	StatusArrayBoundsExceeded                                   NtStatus = 0xC000008C
	StatusFloatDenormalOperand                                  NtStatus = 0xC000008D
	StatusFloatDivideByZero                                     NtStatus = 0xC000008E
	StatusFloatInexactResult                                    NtStatus = 0xC000008F
	StatusFloatInvalidOperation                                 NtStatus = 0xC0000090
	StatusFloatOverflow                                         NtStatus = 0xC0000091
	StatusFloatStackCheck                                       NtStatus = 0xC0000092
	StatusFloatUnderflow                                        NtStatus = 0xC0000093
	StatusIntegerDivideByZero                                   NtStatus = 0xC0000094
	StatusIntegerOverflow                                       NtStatus = 0xC0000095
	StatusPrivilegedInstruction                                 NtStatus = 0xC0000096
	StatusTooManyPagingFiles                                    NtStatus = 0xC0000097
	StatusFileInvalid                                           NtStatus = 0xC0000098
	StatusAllottedSpaceExceeded                                 NtStatus = 0xC0000099
	StatusInsufficientResources                                 NtStatus = 0xC000009A
	StatusDfsExitPathFound                                      NtStatus = 0xC000009B
	StatusDeviceDataError                                       NtStatus = 0xC000009C
	StatusDeviceNotConnected                                    NtStatus = 0xC000009D
	StatusFreeVmNotAtBase                                       NtStatus = 0xC000009F
	StatusMemoryNotAllocated                                    NtStatus = 0xC00000A0
	StatusWorkingSetQuota                                       NtStatus = 0xC00000A1
	StatusMediaWriteProtected                                   NtStatus = 0xC00000A2
	StatusDeviceNotReady                                        NtStatus = 0xC00000A3
	StatusInvalidGroupAttributes                                NtStatus = 0xC00000A4
	StatusBadImpersonationLevel                                 NtStatus = 0xC00000A5
	StatusCantOpenAnonymous                                     NtStatus = 0xC00000A6
	StatusBadValidationClass                                    NtStatus = 0xC00000A7
	StatusBadTokenType                                          NtStatus = 0xC00000A8
	StatusBadMasterBootRecord                                   NtStatus = 0xC00000A9
	StatusInstructionMisalignment                               NtStatus = 0xC00000AA
	StatusInstanceNotAvailable                                  NtStatus = 0xC00000AB
	StatusPipeNotAvailable                                      NtStatus = 0xC00000AC
	StatusInvalidPipeState                                      NtStatus = 0xC00000AD
	StatusPipeBusy                                              NtStatus = 0xC00000AE
	StatusIllegalFunction                                       NtStatus = 0xC00000AF
	StatusPipeDisconnected                                      NtStatus = 0xC00000B0
	StatusPipeClosing                                           NtStatus = 0xC00000B1
	StatusPipeConnected                                         NtStatus = 0xC00000B2
	StatusPipeListening                                         NtStatus = 0xC00000B3
	StatusInvalidReadMode                                       NtStatus = 0xC00000B4
	StatusIoTimeout                                             NtStatus = 0xC00000B5
	StatusFileForcedClosed                                      NtStatus = 0xC00000B6
	StatusProfilingNotStarted                                   NtStatus = 0xC00000B7
	StatusProfilingNotStopped                                   NtStatus = 0xC00000B8
	StatusCouldNotInterpret                                     NtStatus = 0xC00000B9
	StatusFileIsADirectory                                      NtStatus = 0xC00000BA
	StatusNotSupported                                          NtStatus = 0xC00000BB
	StatusRemoteNotListening                                    NtStatus = 0xC00000BC
	StatusDuplicateName                                         NtStatus = 0xC00000BD
	StatusBadNetworkPath                                        NtStatus = 0xC00000BE
	StatusNetworkBusy                                           NtStatus = 0xC00000BF
	StatusDeviceDoesNotExist                                    NtStatus = 0xC00000C0
	StatusTooManyCommands                                       NtStatus = 0xC00000C1
	StatusAdapterHardwareError                                  NtStatus = 0xC00000C2
	StatusInvalidNetworkResponse                                NtStatus = 0xC00000C3
	StatusUnexpectedNetworkError                                NtStatus = 0xC00000C4
	StatusBadRemoteAdapter                                      NtStatus = 0xC00000C5
	StatusPrintQueueFull                                        NtStatus = 0xC00000C6
	StatusNoSpoolSpace                                          NtStatus = 0xC00000C7
	StatusPrintCancelled                                        NtStatus = 0xC00000C8
	StatusNetworkNameDeleted                                    NtStatus = 0xC00000C9
	StatusNetworkAccessDenied                                   NtStatus = 0xC00000CA
	StatusBadDeviceType                                         NtStatus = 0xC00000CB
	StatusBadNetworkName                                        NtStatus = 0xC00000CC
	StatusTooManyNames                                          NtStatus = 0xC00000CD
	StatusTooManySessions                                       NtStatus = 0xC00000CE
	StatusSharingPaused                                         NtStatus = 0xC00000CF
	StatusRequestNotAccepted                                    NtStatus = 0xC00000D0
	StatusRedirectorPaused                                      NtStatus = 0xC00000D1
	StatusNetWriteFault                                         NtStatus = 0xC00000D2
	StatusProfilingAtLimit                                      NtStatus = 0xC00000D3
	StatusNotSameDevice                                         NtStatus = 0xC00000D4
	StatusFileRenamed                                           NtStatus = 0xC00000D5
	StatusVirtualCircuitClosed                                  NtStatus = 0xC00000D6
	StatusNoSecurityOnObject                                    NtStatus = 0xC00000D7
	StatusCantWait                                              NtStatus = 0xC00000D8
	StatusPipeEmpty                                             NtStatus = 0xC00000D9
	StatusCantAccessDomainInfo                                  NtStatus = 0xC00000DA
	StatusCantTerminateSelf                                     NtStatus = 0xC00000DB
	StatusInvalidServerState                                    NtStatus = 0xC00000DC
	StatusInvalidDomainState                                    NtStatus = 0xC00000DD
	StatusInvalidDomainRole                                     NtStatus = 0xC00000DE
	StatusNoSuchDomain                                          NtStatus = 0xC00000DF
	StatusDomainExists                                          NtStatus = 0xC00000E0
	StatusDomainLimitExceeded                                   NtStatus = 0xC00000E1
	StatusOplockNotGranted                                      NtStatus = 0xC00000E2
	StatusInvalidOplockProtocol                                 NtStatus = 0xC00000E3
	StatusInternalDbCorruption                                  NtStatus = 0xC00000E4
	StatusInternalError                                         NtStatus = 0xC00000E5
	StatusGenericNotMapped                                      NtStatus = 0xC00000E6
	StatusBadDescriptorFormat                                   NtStatus = 0xC00000E7
	StatusInvalidUserBuffer                                     NtStatus = 0xC00000E8
	StatusUnexpectedIoError                                     NtStatus = 0xC00000E9
	StatusUnexpectedMmCreateErr                                 NtStatus = 0xC00000EA
	StatusUnexpectedMmMapError                                  NtStatus = 0xC00000EB
	StatusUnexpectedMmExtendErr                                 NtStatus = 0xC00000EC
	StatusNotLogonProcess                                       NtStatus = 0xC00000ED
	StatusLogonSessionExists                                    NtStatus = 0xC00000EE
	StatusInvalidParameter1                                     NtStatus = 0xC00000EF
	StatusInvalidParameter2                                     NtStatus = 0xC00000F0
	StatusInvalidParameter3                                     NtStatus = 0xC00000F1
	StatusInvalidParameter4                                     NtStatus = 0xC00000F2
	StatusInvalidParameter5                                     NtStatus = 0xC00000F3
	StatusInvalidParameter6                                     NtStatus = 0xC00000F4
	StatusInvalidParameter7                                     NtStatus = 0xC00000F5
	StatusInvalidParameter8                                     NtStatus = 0xC00000F6
	StatusInvalidParameter9                                     NtStatus = 0xC00000F7
	StatusInvalidParameter10                                    NtStatus = 0xC00000F8
	StatusInvalidParameter11                                    NtStatus = 0xC00000F9
	StatusInvalidParameter12                                    NtStatus = 0xC00000FA
	StatusRedirectorNotStarted                                  NtStatus = 0xC00000FB
	StatusRedirectorStarted                                     NtStatus = 0xC00000FC
	StatusStackOverflow                                         NtStatus = 0xC00000FD
	StatusNoSuchPackage                                         NtStatus = 0xC00000FE
	StatusBadFunctionTable                                      NtStatus = 0xC00000FF
	StatusVariableNotFound                                      NtStatus = 0xC0000100
	StatusDirectoryNotEmpty                                     NtStatus = 0xC0000101
	StatusFileCorruptError                                      NtStatus = 0xC0000102
	StatusNotADirectory                                         NtStatus = 0xC0000103
	StatusBadLogonSessionState                                  NtStatus = 0xC0000104
	StatusLogonSessionCollision                                 NtStatus = 0xC0000105
	StatusNameTooLong                                           NtStatus = 0xC0000106
	StatusFilesOpen                                             NtStatus = 0xC0000107
	StatusConnectionInUse                                       NtStatus = 0xC0000108
	StatusMessageNotFound                                       NtStatus = 0xC0000109
	StatusProcessIsTerminating                                  NtStatus = 0xC000010A
	StatusInvalidLogonType                                      NtStatus = 0xC000010B
	StatusNoGuidTranslation                                     NtStatus = 0xC000010C
	StatusCannotImpersonate                                     NtStatus = 0xC000010D
	StatusImageAlreadyLoaded                                    NtStatus = 0xC000010E
	StatusNoLdt                                                 NtStatus = 0xC0000117
	StatusInvalidLdtSize                                        NtStatus = 0xC0000118
	StatusInvalidLdtOffset                                      NtStatus = 0xC0000119
	StatusInvalidLdtDescriptor                                  NtStatus = 0xC000011A
	StatusInvalidImageNeFormat                                  NtStatus = 0xC000011B
	StatusRxactInvalidState                                     NtStatus = 0xC000011C
	StatusRxactCommitFailure                                    NtStatus = 0xC000011D
	StatusMappedFileSizeZero                                    NtStatus = 0xC000011E
	StatusTooManyOpenedFiles                                    NtStatus = 0xC000011F
	StatusCancelled                                             NtStatus = 0xC0000120
	StatusCannotDelete                                          NtStatus = 0xC0000121
	StatusInvalidComputerName                                   NtStatus = 0xC0000122
	StatusFileDeleted                                           NtStatus = 0xC0000123
	StatusSpecialAccount                                        NtStatus = 0xC0000124
	StatusSpecialGroup                                          NtStatus = 0xC0000125
	StatusSpecialUser                                           NtStatus = 0xC0000126
	StatusMembersPrimaryGroup                                   NtStatus = 0xC0000127
	StatusFileClosed                                            NtStatus = 0xC0000128
	StatusTooManyThreads                                        NtStatus = 0xC0000129
	StatusThreadNotInProcess                                    NtStatus = 0xC000012A
	StatusTokenAlreadyInUse                                     NtStatus = 0xC000012B
	StatusPagefileQuotaExceeded                                 NtStatus = 0xC000012C
	StatusCommitmentLimit                                       NtStatus = 0xC000012D
	StatusInvalidImageLeFormat                                  NtStatus = 0xC000012E
	StatusInvalidImageNotMz                                     NtStatus = 0xC000012F
	StatusInvalidImageProtect                                   NtStatus = 0xC0000130
	StatusInvalidImageWin16                                     NtStatus = 0xC0000131
	StatusLogonServerConflict                                   NtStatus = 0xC0000132
	StatusTimeDifferenceAtDc                                    NtStatus = 0xC0000133
	StatusSynchronizationRequired                               NtStatus = 0xC0000134
	StatusDllNotFound                                           NtStatus = 0xC0000135
	StatusOpenFailed                                            NtStatus = 0xC0000136
	StatusIoPrivilegeFailed                                     NtStatus = 0xC0000137
	StatusOrdinalNotFound                                       NtStatus = 0xC0000138
	StatusEntrypointNotFound                                    NtStatus = 0xC0000139
	StatusControlCExit                                          NtStatus = 0xC000013A
	StatusLocalDisconnect                                       NtStatus = 0xC000013B
	StatusRemoteDisconnect                                      NtStatus = 0xC000013C
	StatusRemoteResources                                       NtStatus = 0xC000013D
	StatusLinkFailed                                            NtStatus = 0xC000013E
	StatusLinkTimeout                                           NtStatus = 0xC000013F
	StatusInvalidConnection                                     NtStatus = 0xC0000140
	StatusInvalidAddress                                        NtStatus = 0xC0000141
	StatusDllInitFailed                                         NtStatus = 0xC0000142
	StatusMissingSystemfile                                     NtStatus = 0xC0000143
	StatusUnhandledException                                    NtStatus = 0xC0000144
	StatusAppInitFailure                                        NtStatus = 0xC0000145
	StatusPagefileCreateFailed                                  NtStatus = 0xC0000146
	StatusNoPagefile                                            NtStatus = 0xC0000147
	StatusInvalidLevel                                          NtStatus = 0xC0000148
	StatusWrongPasswordCore                                     NtStatus = 0xC0000149
	StatusIllegalFloatContext                                   NtStatus = 0xC000014A
	StatusPipeBroken                                            NtStatus = 0xC000014B
	StatusRegistryCorrupt                                       NtStatus = 0xC000014C
	StatusRegistryIoFailed                                      NtStatus = 0xC000014D
	StatusNoEventPair                                           NtStatus = 0xC000014E
	StatusUnrecognizedVolume                                    NtStatus = 0xC000014F
	StatusSerialNoDeviceInited                                  NtStatus = 0xC0000150
	StatusNoSuchAlias                                           NtStatus = 0xC0000151
	StatusMemberNotInAlias                                      NtStatus = 0xC0000152
	StatusMemberInAlias                                         NtStatus = 0xC0000153
	StatusAliasExists                                           NtStatus = 0xC0000154
	StatusLogonNotGranted                                       NtStatus = 0xC0000155
	StatusTooManySecrets                                        NtStatus = 0xC0000156
	StatusSecretTooLong                                         NtStatus = 0xC0000157
	StatusInternalDbError                                       NtStatus = 0xC0000158
	StatusFullscreenMode                                        NtStatus = 0xC0000159
	StatusTooManyContextIds                                     NtStatus = 0xC000015A
	StatusLogonTypeNotGranted                                   NtStatus = 0xC000015B
	StatusNotRegistryFile                                       NtStatus = 0xC000015C
	StatusNtCrossEncryptionRequired                             NtStatus = 0xC000015D
	StatusDomainCtrlrConfigError                                NtStatus = 0xC000015E
	StatusFtMissingMember                                       NtStatus = 0xC000015F
	StatusIllFormedServiceEntry                                 NtStatus = 0xC0000160
	StatusIllegalCharacter                                      NtStatus = 0xC0000161
	StatusUnmappableCharacter                                   NtStatus = 0xC0000162
	StatusUndefinedCharacter                                    NtStatus = 0xC0000163
	StatusFloppyVolume                                          NtStatus = 0xC0000164
	StatusFloppyIdMarkNotFound                                  NtStatus = 0xC0000165
	StatusFloppyWrongCylinder                                   NtStatus = 0xC0000166
	StatusFloppyUnknownError                                    NtStatus = 0xC0000167
	StatusFloppyBadRegisters                                    NtStatus = 0xC0000168
	StatusDiskRecalibrateFailed                                 NtStatus = 0xC0000169
	StatusDiskOperationFailed                                   NtStatus = 0xC000016A
	StatusDiskResetFailed                                       NtStatus = 0xC000016B
	StatusSharedIrqBusy                                         NtStatus = 0xC000016C
	StatusFtOrphaning                                           NtStatus = 0xC000016D
	StatusBiosFailedToConnectInterrupt                          NtStatus = 0xC000016E
	StatusPartitionFailure                                      NtStatus = 0xC0000172
	StatusInvalidBlockLength                                    NtStatus = 0xC0000173
	StatusDeviceNotPartitioned                                  NtStatus = 0xC0000174
	StatusUnableToLockMedia                                     NtStatus = 0xC0000175
	StatusUnableToUnloadMedia                                   NtStatus = 0xC0000176
	StatusEomOverflow                                           NtStatus = 0xC0000177
	StatusNoMedia                                               NtStatus = 0xC0000178
	StatusNoSuchMember                                          NtStatus = 0xC000017A
	StatusInvalidMember                                         NtStatus = 0xC000017B
	StatusKeyDeleted                                            NtStatus = 0xC000017C
	StatusNoLogSpace                                            NtStatus = 0xC000017D
	StatusTooManySids                                           NtStatus = 0xC000017E
	StatusLmCrossEncryptionRequired                             NtStatus = 0xC000017F
	StatusKeyHasChildren                                        NtStatus = 0xC0000180
	StatusChildMustBeVolatile                                   NtStatus = 0xC0000181
	StatusDeviceConfigurationError                              NtStatus = 0xC0000182
	StatusDriverInternalError                                   NtStatus = 0xC0000183
	StatusInvalidDeviceState                                    NtStatus = 0xC0000184
	StatusIoDeviceError                                         NtStatus = 0xC0000185
	StatusDeviceProtocolError                                   NtStatus = 0xC0000186
	StatusBackupController                                      NtStatus = 0xC0000187
	StatusLogFileFull                                           NtStatus = 0xC0000188
	StatusTooLate                                               NtStatus = 0xC0000189
	StatusNoTrustLsaSecret                                      NtStatus = 0xC000018A
	StatusNoTrustSamAccount                                     NtStatus = 0xC000018B
	StatusTrustedDomainFailure                                  NtStatus = 0xC000018C
	StatusTrustedRelationshipFailure                            NtStatus = 0xC000018D
	StatusEventlogFileCorrupt                                   NtStatus = 0xC000018E
	StatusEventlogCantStart                                     NtStatus = 0xC000018F
	StatusTrustFailure                                          NtStatus = 0xC0000190
	StatusMutantLimitExceeded                                   NtStatus = 0xC0000191
	StatusNetlogonNotStarted                                    NtStatus = 0xC0000192
	StatusAccountExpired                                        NtStatus = 0xC0000193
	StatusPossibleDeadlock                                      NtStatus = 0xC0000194
	StatusNetworkCredentialConflict                             NtStatus = 0xC0000195
	StatusRemoteSessionLimit                                    NtStatus = 0xC0000196
	StatusEventlogFileChanged                                   NtStatus = 0xC0000197
	StatusNologonInterdomainTrustAccount                        NtStatus = 0xC0000198
	StatusNologonWorkstationTrustAccount                        NtStatus = 0xC0000199
	StatusNologonServerTrustAccount                             NtStatus = 0xC000019A
	StatusDomainTrustInconsistent                               NtStatus = 0xC000019B
	StatusFsDriverRequired                                      NtStatus = 0xC000019C
	StatusImageAlreadyLoadedAsDll                               NtStatus = 0xC000019D
	StatusIncompatibleWithGlobalShortNameRegistrySetting        NtStatus = 0xC000019E
	StatusShortNamesNotEnabledOnVolume                          NtStatus = 0xC000019F
	StatusSecurityStreamIsInconsistent                          NtStatus = 0xC00001A0
	StatusInvalidLockRange                                      NtStatus = 0xC00001A1
	StatusInvalidAceCondition                                   NtStatus = 0xC00001A2
	StatusImageSubsystemNotPresent                              NtStatus = 0xC00001A3
	StatusNotificationGuidAlreadyDefined                        NtStatus = 0xC00001A4
	StatusNetworkOpenRestriction                                NtStatus = 0xC0000201
	StatusNoUserSessionKey                                      NtStatus = 0xC0000202
	StatusUserSessionDeleted                                    NtStatus = 0xC0000203
	StatusResourceLangNotFound                                  NtStatus = 0xC0000204
	StatusInsuffServerResources                                 NtStatus = 0xC0000205
	StatusInvalidBufferSize                                     NtStatus = 0xC0000206
	StatusInvalidAddressComponent                               NtStatus = 0xC0000207
	StatusInvalidAddressWildcard                                NtStatus = 0xC0000208
	StatusTooManyAddresses                                      NtStatus = 0xC0000209
	StatusAddressAlreadyExists                                  NtStatus = 0xC000020A
	StatusAddressClosed                                         NtStatus = 0xC000020B
	StatusConnectionDisconnected                                NtStatus = 0xC000020C
	StatusConnectionReset                                       NtStatus = 0xC000020D
	StatusTooManyNodes                                          NtStatus = 0xC000020E
	StatusTransactionAborted                                    NtStatus = 0xC000020F
	StatusTransactionTimedOut                                   NtStatus = 0xC0000210
	StatusTransactionNoRelease                                  NtStatus = 0xC0000211
	StatusTransactionNoMatch                                    NtStatus = 0xC0000212
	StatusTransactionResponded                                  NtStatus = 0xC0000213
	StatusTransactionInvalidId                                  NtStatus = 0xC0000214
	StatusTransactionInvalidType                                NtStatus = 0xC0000215
	StatusNotServerSession                                      NtStatus = 0xC0000216
	StatusNotClientSession                                      NtStatus = 0xC0000217
	StatusCannotLoadRegistryFile                                NtStatus = 0xC0000218
	StatusDebugAttachFailed                                     NtStatus = 0xC0000219
	StatusSystemProcessTerminated                               NtStatus = 0xC000021A
	StatusDataNotAccepted                                       NtStatus = 0xC000021B
	StatusNoBrowserServersFound                                 NtStatus = 0xC000021C
	StatusVdmHardError                                          NtStatus = 0xC000021D
	StatusDriverCancelTimeout                                   NtStatus = 0xC000021E
	StatusReplyMessageMismatch                                  NtStatus = 0xC000021F
	StatusMappedAlignment                                       NtStatus = 0xC0000220
	StatusImageChecksumMismatch                                 NtStatus = 0xC0000221
	StatusLostWritebehindData                                   NtStatus = 0xC0000222
	StatusClientServerParametersInvalid                         NtStatus = 0xC0000223
	StatusPasswordMustChange                                    NtStatus = 0xC0000224
	StatusNotFound                                              NtStatus = 0xC0000225
	StatusNotTinyStream                                         NtStatus = 0xC0000226
	StatusRecoveryFailure                                       NtStatus = 0xC0000227
	StatusStackOverflowRead                                     NtStatus = 0xC0000228
	StatusFailCheck                                             NtStatus = 0xC0000229
	StatusDuplicateObjectid                                     NtStatus = 0xC000022A
	StatusObjectidExists                                        NtStatus = 0xC000022B
	StatusConvertToLarge                                        NtStatus = 0xC000022C
	StatusRetry                                                 NtStatus = 0xC000022D
	StatusFoundOutOfScope                                       NtStatus = 0xC000022E
	StatusAllocateBucket                                        NtStatus = 0xC000022F
	StatusPropsetNotFound                                       NtStatus = 0xC0000230
	StatusMarshallOverflow                                      NtStatus = 0xC0000231
	StatusInvalidVariant                                        NtStatus = 0xC0000232
	StatusDomainControllerNotFound                              NtStatus = 0xC0000233
	StatusAccountLockedOut                                      NtStatus = 0xC0000234
	StatusHandleNotClosable                                     NtStatus = 0xC0000235
	StatusConnectionRefused                                     NtStatus = 0xC0000236
	StatusGracefulDisconnect                                    NtStatus = 0xC0000237
	StatusAddressAlreadyAssociated                              NtStatus = 0xC0000238
	StatusAddressNotAssociated                                  NtStatus = 0xC0000239
	StatusConnectionInvalid                                     NtStatus = 0xC000023A
	StatusConnectionActive                                      NtStatus = 0xC000023B
	StatusNetworkUnreachable                                    NtStatus = 0xC000023C
	StatusHostUnreachable                                       NtStatus = 0xC000023D
	StatusProtocolUnreachable                                   NtStatus = 0xC000023E
	StatusPortUnreachable                                       NtStatus = 0xC000023F
	StatusRequestAborted                                        NtStatus = 0xC0000240
	StatusConnectionAborted                                     NtStatus = 0xC0000241
	StatusBadCompressionBuffer                                  NtStatus = 0xC0000242
	StatusUserMappedFile                                        NtStatus = 0xC0000243
	StatusAuditFailed                                           NtStatus = 0xC0000244
	StatusTimerResolutionNotSet                                 NtStatus = 0xC0000245
	StatusConnectionCountLimit                                  NtStatus = 0xC0000246
	StatusLoginTimeRestriction                                  NtStatus = 0xC0000247
	StatusLoginWkstaRestriction                                 NtStatus = 0xC0000248
	StatusImageMpUpMismatch                                     NtStatus = 0xC0000249
	StatusInsufficientLogonInfo                                 NtStatus = 0xC0000250
	StatusBadDllEntrypoint                                      NtStatus = 0xC0000251
	StatusBadServiceEntrypoint                                  NtStatus = 0xC0000252
	StatusLpcReplyLost                                          NtStatus = 0xC0000253
	StatusIpAddressConflict1                                    NtStatus = 0xC0000254
	StatusIpAddressConflict2                                    NtStatus = 0xC0000255
	StatusRegistryQuotaLimit                                    NtStatus = 0xC0000256
	StatusPathNotCovered                                        NtStatus = 0xC0000257
	StatusNoCallbackActive                                      NtStatus = 0xC0000258
	StatusLicenseQuotaExceeded                                  NtStatus = 0xC0000259
	StatusPwdTooShort                                           NtStatus = 0xC000025A
	StatusPwdTooRecent                                          NtStatus = 0xC000025B
	StatusPwdHistoryConflict                                    NtStatus = 0xC000025C
	StatusPlugplayNoDevice                                      NtStatus = 0xC000025E
	StatusUnsupportedCompression                                NtStatus = 0xC000025F
	StatusInvalidHwProfile                                      NtStatus = 0xC0000260
	StatusInvalidPlugplayDevicePath                             NtStatus = 0xC0000261
	StatusDriverOrdinalNotFound                                 NtStatus = 0xC0000262
	StatusDriverEntrypointNotFound                              NtStatus = 0xC0000263
	StatusResourceNotOwned                                      NtStatus = 0xC0000264
	StatusTooManyLinks                                          NtStatus = 0xC0000265
	StatusQuotaListInconsistent                                 NtStatus = 0xC0000266
	StatusFileIsOffline                                         NtStatus = 0xC0000267
	StatusEvaluationExpiration                                  NtStatus = 0xC0000268
	StatusIllegalDllRelocation                                  NtStatus = 0xC0000269
	StatusLicenseViolation                                      NtStatus = 0xC000026A
	StatusDllInitFailedLogoff                                   NtStatus = 0xC000026B
	StatusDriverUnableToLoad                                    NtStatus = 0xC000026C
	StatusDfsUnavailable                                        NtStatus = 0xC000026D
	StatusVolumeDismounted                                      NtStatus = 0xC000026E
	StatusWx86InternalError                                     NtStatus = 0xC000026F
	StatusWx86FloatStackCheck                                   NtStatus = 0xC0000270
	StatusValidateContinue                                      NtStatus = 0xC0000271
	StatusNoMatch                                               NtStatus = 0xC0000272
	StatusNoMoreMatches                                         NtStatus = 0xC0000273
	StatusNotAReparsePoint                                      NtStatus = 0xC0000275
	StatusIoReparseTagInvalid                                   NtStatus = 0xC0000276
	StatusIoReparseTagMismatch                                  NtStatus = 0xC0000277
	StatusIoReparseDataInvalid                                  NtStatus = 0xC0000278
	StatusIoReparseTagNotHandled                                NtStatus = 0xC0000279
	StatusReparsePointNotResolved                               NtStatus = 0xC0000280
	StatusDirectoryIsAReparsePoint                              NtStatus = 0xC0000281
	StatusRangeListConflict                                     NtStatus = 0xC0000282
	StatusSourceElementEmpty                                    NtStatus = 0xC0000283
	StatusDestinationElementFull                                NtStatus = 0xC0000284
	StatusIllegalElementAddress                                 NtStatus = 0xC0000285
	StatusMagazineNotPresent                                    NtStatus = 0xC0000286
	StatusReinitializationNeeded                                NtStatus = 0xC0000287
	StatusEncryptionFailed                                      NtStatus = 0xC000028A
	StatusDecryptionFailed                                      NtStatus = 0xC000028B
	StatusRangeNotFound                                         NtStatus = 0xC000028C
	StatusNoRecoveryPolicy                                      NtStatus = 0xC000028D
	StatusNoEfs                                                 NtStatus = 0xC000028E
	StatusWrongEfs                                              NtStatus = 0xC000028F
	StatusNoUserKeys                                            NtStatus = 0xC0000290
	StatusFileNotEncrypted                                      NtStatus = 0xC0000291
	StatusNotExportFormat                                       NtStatus = 0xC0000292
	StatusFileEncrypted                                         NtStatus = 0xC0000293
	StatusWmiGuidNotFound                                       NtStatus = 0xC0000295
	StatusWmiInstanceNotFound                                   NtStatus = 0xC0000296
	StatusWmiItemidNotFound                                     NtStatus = 0xC0000297
	StatusWmiTryAgain                                           NtStatus = 0xC0000298
	StatusSharedPolicy                                          NtStatus = 0xC0000299
	StatusPolicyObjectNotFound                                  NtStatus = 0xC000029A
	StatusPolicyOnlyInDs                                        NtStatus = 0xC000029B
	StatusVolumeNotUpgraded                                     NtStatus = 0xC000029C
	StatusRemoteStorageNotActive                                NtStatus = 0xC000029D
	StatusRemoteStorageMediaError                               NtStatus = 0xC000029E
	StatusNoTrackingService                                     NtStatus = 0xC000029F
	StatusServerSidMismatch                                     NtStatus = 0xC00002A0
	StatusDsNoAttributeOrValue                                  NtStatus = 0xC00002A1
	StatusDsInvalidAttributeSyntax                              NtStatus = 0xC00002A2
	StatusDsAttributeTypeUndefined                              NtStatus = 0xC00002A3
	StatusDsAttributeOrValueExists                              NtStatus = 0xC00002A4
	StatusDsBusy                                                NtStatus = 0xC00002A5
	StatusDsUnavailable                                         NtStatus = 0xC00002A6
	StatusDsNoRidsAllocated                                     NtStatus = 0xC00002A7
	StatusDsNoMoreRids                                          NtStatus = 0xC00002A8
	StatusDsIncorrectRoleOwner                                  NtStatus = 0xC00002A9
	StatusDsRidmgrInitError                                     NtStatus = 0xC00002AA
	StatusDsObjClassViolation                                   NtStatus = 0xC00002AB
	StatusDsCantOnNonLeaf                                       NtStatus = 0xC00002AC
	StatusDsCantOnRdn                                           NtStatus = 0xC00002AD
	StatusDsCantModObjClass                                     NtStatus = 0xC00002AE
	StatusDsCrossDomMoveFailed                                  NtStatus = 0xC00002AF
	StatusDsGcNotAvailable                                      NtStatus = 0xC00002B0
	StatusDirectoryServiceRequired                              NtStatus = 0xC00002B1
	StatusReparseAttributeConflict                              NtStatus = 0xC00002B2
	StatusCantEnableDenyOnly                                    NtStatus = 0xC00002B3
	StatusFloatMultipleFaults                                   NtStatus = 0xC00002B4
	StatusFloatMultipleTraps                                    NtStatus = 0xC00002B5
	StatusDeviceRemoved                                         NtStatus = 0xC00002B6
	StatusJournalDeleteInProgress                               NtStatus = 0xC00002B7
	StatusJournalNotActive                                      NtStatus = 0xC00002B8
	StatusNointerface                                           NtStatus = 0xC00002B9
	StatusDsAdminLimitExceeded                                  NtStatus = 0xC00002C1
	StatusDriverFailedSleep                                     NtStatus = 0xC00002C2
	StatusMutualAuthenticationFailed                            NtStatus = 0xC00002C3
	StatusCorruptSystemFile                                     NtStatus = 0xC00002C4
	StatusDatatypeMisalignmentError                             NtStatus = 0xC00002C5
	StatusWmiReadOnly                                           NtStatus = 0xC00002C6
	StatusWmiSetFailure                                         NtStatus = 0xC00002C7
	StatusCommitmentMinimum                                     NtStatus = 0xC00002C8
	StatusRegNatConsumption                                     NtStatus = 0xC00002C9
	StatusTransportFull                                         NtStatus = 0xC00002CA
	StatusDsSamInitFailure                                      NtStatus = 0xC00002CB
	StatusOnlyIfConnected                                       NtStatus = 0xC00002CC
	StatusDsSensitiveGroupViolation                             NtStatus = 0xC00002CD
	StatusPnpRestartEnumeration                                 NtStatus = 0xC00002CE
	StatusJournalEntryDeleted                                   NtStatus = 0xC00002CF
	StatusDsCantModPrimarygroupid                               NtStatus = 0xC00002D0
	StatusSystemImageBadSignature                               NtStatus = 0xC00002D1
	StatusPnpRebootRequired                                     NtStatus = 0xC00002D2
	StatusPowerStateInvalid                                     NtStatus = 0xC00002D3
	StatusDsInvalidGroupType                                    NtStatus = 0xC00002D4
	StatusDsNoNestGlobalgroupInMixeddomain                      NtStatus = 0xC00002D5
	StatusDsNoNestLocalgroupInMixeddomain                       NtStatus = 0xC00002D6
	StatusDsGlobalCantHaveLocalMember                           NtStatus = 0xC00002D7
	StatusDsGlobalCantHaveUniversalMember                       NtStatus = 0xC00002D8
	StatusDsUniversalCantHaveLocalMember                        NtStatus = 0xC00002D9
	StatusDsGlobalCantHaveCrossdomainMember                     NtStatus = 0xC00002DA
	StatusDsLocalCantHaveCrossdomainLocalMember                 NtStatus = 0xC00002DB
	StatusDsHavePrimaryMembers                                  NtStatus = 0xC00002DC
	StatusWmiNotSupported                                       NtStatus = 0xC00002DD
	StatusInsufficientPower                                     NtStatus = 0xC00002DE
	StatusSamNeedBootkeyPassword                                NtStatus = 0xC00002DF
	StatusSamNeedBootkeyFloppy                                  NtStatus = 0xC00002E0
	StatusDsCantStart                                           NtStatus = 0xC00002E1
	StatusDsInitFailure                                         NtStatus = 0xC00002E2
	StatusSamInitFailure                                        NtStatus = 0xC00002E3
	StatusDsGcRequired                                          NtStatus = 0xC00002E4
	StatusDsLocalMemberOfLocalOnly                              NtStatus = 0xC00002E5
	StatusDsNoFpoInUniversalGroups                              NtStatus = 0xC00002E6
	StatusDsMachineAccountQuotaExceeded                         NtStatus = 0xC00002E7
	StatusCurrentDomainNotAllowed                               NtStatus = 0xC00002E9
	StatusCannotMake                                            NtStatus = 0xC00002EA
	StatusSystemShutdown                                        NtStatus = 0xC00002EB
	StatusDsInitFailureConsole                                  NtStatus = 0xC00002EC
	StatusDsSamInitFailureConsole                               NtStatus = 0xC00002ED
	StatusUnfinishedContextDeleted                              NtStatus = 0xC00002EE
	StatusNoTgtReply                                            NtStatus = 0xC00002EF
	StatusObjectidNotFound                                      NtStatus = 0xC00002F0
	StatusNoIpAddresses                                         NtStatus = 0xC00002F1
	StatusWrongCredentialHandle                                 NtStatus = 0xC00002F2
	StatusCryptoSystemInvalid                                   NtStatus = 0xC00002F3
	StatusMaxReferralsExceeded                                  NtStatus = 0xC00002F4
	StatusMustBeKdc                                             NtStatus = 0xC00002F5
	StatusStrongCryptoNotSupported                              NtStatus = 0xC00002F6
	StatusTooManyPrincipals                                     NtStatus = 0xC00002F7
	StatusNoPaData                                              NtStatus = 0xC00002F8
	StatusPkinitNameMismatch                                    NtStatus = 0xC00002F9
	StatusSmartcardLogonRequired                                NtStatus = 0xC00002FA
	StatusKdcInvalidRequest                                     NtStatus = 0xC00002FB
	StatusKdcUnableToRefer                                      NtStatus = 0xC00002FC
	StatusKdcUnknownEtype                                       NtStatus = 0xC00002FD
	StatusShutdownInProgress                                    NtStatus = 0xC00002FE
	StatusServerShutdownInProgress                              NtStatus = 0xC00002FF
	StatusNotSupportedOnSbs                                     NtStatus = 0xC0000300
	StatusWmiGuidDisconnected                                   NtStatus = 0xC0000301
	StatusWmiAlreadyDisabled                                    NtStatus = 0xC0000302
	StatusWmiAlreadyEnabled                                     NtStatus = 0xC0000303
	StatusMftTooFragmented                                      NtStatus = 0xC0000304
	StatusCopyProtectionFailure                                 NtStatus = 0xC0000305
	StatusCssAuthenticationFailure                              NtStatus = 0xC0000306
	StatusCssKeyNotPresent                                      NtStatus = 0xC0000307
	StatusCssKeyNotEstablished                                  NtStatus = 0xC0000308
	StatusCssScrambledSector                                    NtStatus = 0xC0000309
	StatusCssRegionMismatch                                     NtStatus = 0xC000030A
	StatusCssResetsExhausted                                    NtStatus = 0xC000030B
	StatusPkinitFailure                                         NtStatus = 0xC0000320
	StatusSmartcardSubsystemFailure                             NtStatus = 0xC0000321
	StatusNoKerbKey                                             NtStatus = 0xC0000322
	StatusHostDown                                              NtStatus = 0xC0000350
	StatusUnsupportedPreauth                                    NtStatus = 0xC0000351
	StatusEfsAlgBlobTooBig                                      NtStatus = 0xC0000352
	StatusPortNotSet                                            NtStatus = 0xC0000353
	StatusDebuggerInactive                                      NtStatus = 0xC0000354
	StatusDsVersionCheckFailure                                 NtStatus = 0xC0000355
	StatusAuditingDisabled                                      NtStatus = 0xC0000356
	StatusPrent4MachineAccount                                  NtStatus = 0xC0000357
	StatusDsAgCantHaveUniversalMember                           NtStatus = 0xC0000358
	StatusInvalidImageWin32                                     NtStatus = 0xC0000359
	StatusInvalidImageWin64                                     NtStatus = 0xC000035A
	StatusBadBindings                                           NtStatus = 0xC000035B
	StatusNetworkSessionExpired                                 NtStatus = 0xC000035C
	StatusApphelpBlock                                          NtStatus = 0xC000035D
	StatusAllSidsFiltered                                       NtStatus = 0xC000035E
	StatusNotSafeModeDriver                                     NtStatus = 0xC000035F
	StatusAccessDisabledByPolicyDefault                         NtStatus = 0xC0000361
	StatusAccessDisabledByPolicyPath                            NtStatus = 0xC0000362
	StatusAccessDisabledByPolicyPublisher                       NtStatus = 0xC0000363
	StatusAccessDisabledByPolicyOther                           NtStatus = 0xC0000364
	StatusFailedDriverEntry                                     NtStatus = 0xC0000365
	StatusDeviceEnumerationError                                NtStatus = 0xC0000366
	StatusMountPointNotResolved                                 NtStatus = 0xC0000368
	StatusInvalidDeviceObjectParameter                          NtStatus = 0xC0000369
	StatusMcaOccured                                            NtStatus = 0xC000036A
	StatusDriverBlockedCritical                                 NtStatus = 0xC000036B
	StatusDriverBlocked                                         NtStatus = 0xC000036C
	StatusDriverDatabaseError                                   NtStatus = 0xC000036D
	StatusSystemHiveTooLarge                                    NtStatus = 0xC000036E
	StatusInvalidImportOfNonDll                                 NtStatus = 0xC000036F
	StatusNoSecrets                                             NtStatus = 0xC0000371
	StatusAccessDisabledNoSaferUiByPolicy                       NtStatus = 0xC0000372
	StatusFailedStackSwitch                                     NtStatus = 0xC0000373
	StatusHeapCorruption                                        NtStatus = 0xC0000374
	StatusSmartcardWrongPin                                     NtStatus = 0xC0000380
	StatusSmartcardCardBlocked                                  NtStatus = 0xC0000381
	StatusSmartcardCardNotAuthenticated                         NtStatus = 0xC0000382
	StatusSmartcardNoCard                                       NtStatus = 0xC0000383
	StatusSmartcardNoKeyContainer                               NtStatus = 0xC0000384
	StatusSmartcardNoCertificate                                NtStatus = 0xC0000385
	StatusSmartcardNoKeyset                                     NtStatus = 0xC0000386
	StatusSmartcardIoError                                      NtStatus = 0xC0000387
	StatusDowngradeDetected                                     NtStatus = 0xC0000388
	StatusSmartcardCertRevoked                                  NtStatus = 0xC0000389
	StatusIssuingCaUntrusted                                    NtStatus = 0xC000038A
	StatusRevocationOfflineC                                    NtStatus = 0xC000038B
	StatusPkinitClientFailure                                   NtStatus = 0xC000038C
	StatusSmartcardCertExpired                                  NtStatus = 0xC000038D
	StatusDriverFailedPriorUnload                               NtStatus = 0xC000038E
	StatusSmartcardSilentContext                                NtStatus = 0xC000038F
	StatusPerUserTrustQuotaExceeded                             NtStatus = 0xC0000401
	StatusAllUserTrustQuotaExceeded                             NtStatus = 0xC0000402
	StatusUserDeleteTrustQuotaExceeded                          NtStatus = 0xC0000403
	StatusDsNameNotUnique                                       NtStatus = 0xC0000404
	StatusDsDuplicateIdFound                                    NtStatus = 0xC0000405
	StatusDsGroupConversionError                                NtStatus = 0xC0000406
	StatusVolsnapPrepareHibernate                               NtStatus = 0xC0000407
	StatusUser2userRequired                                     NtStatus = 0xC0000408
	StatusStackBufferOverrun                                    NtStatus = 0xC0000409
	StatusNoS4uProtSupport                                      NtStatus = 0xC000040A
	StatusCrossrealmDelegationFailure                           NtStatus = 0xC000040B
	StatusRevocationOfflineKdc                                  NtStatus = 0xC000040C
	StatusIssuingCaUntrustedKdc                                 NtStatus = 0xC000040D
	StatusKdcCertExpired                                        NtStatus = 0xC000040E
	StatusKdcCertRevoked                                        NtStatus = 0xC000040F
	StatusParameterQuotaExceeded                                NtStatus = 0xC0000410
	StatusHibernationFailure                                    NtStatus = 0xC0000411
	StatusDelayLoadFailed                                       NtStatus = 0xC0000412
	StatusAuthenticationFirewallFailed                          NtStatus = 0xC0000413
	StatusVdmDisallowed                                         NtStatus = 0xC0000414
	StatusHungDisplayDriverThread                               NtStatus = 0xC0000415
	StatusInsufficientResourceForSpecifiedSharedSectionSize     NtStatus = 0xC0000416
	StatusInvalidCruntimeParameter                              NtStatus = 0xC0000417
	StatusNtlmBlocked                                           NtStatus = 0xC0000418
	StatusDsSrcSidExistsInForest                                NtStatus = 0xC0000419
	StatusDsDomainNameExistsInForest                            NtStatus = 0xC000041A
	StatusDsFlatNameExistsInForest                              NtStatus = 0xC000041B
	StatusInvalidUserPrincipalName                              NtStatus = 0xC000041C
	StatusAssertionFailure                                      NtStatus = 0xC0000420
	StatusVerifierStop                                          NtStatus = 0xC0000421
	StatusCallbackPopStack                                      NtStatus = 0xC0000423
	StatusIncompatibleDriverBlocked                             NtStatus = 0xC0000424
	StatusHiveUnloaded                                          NtStatus = 0xC0000425
	StatusCompressionDisabled                                   NtStatus = 0xC0000426
	StatusFileSystemLimitation                                  NtStatus = 0xC0000427
	StatusInvalidImageHash                                      NtStatus = 0xC0000428
	StatusNotCapable                                            NtStatus = 0xC0000429
	StatusRequestOutOfSequence                                  NtStatus = 0xC000042A
	StatusImplementationLimit                                   NtStatus = 0xC000042B
	StatusElevationRequired                                     NtStatus = 0xC000042C
	StatusNoSecurityContext                                     NtStatus = 0xC000042D
	StatusPku2uCertFailure                                      NtStatus = 0xC000042E
	StatusBeyondVdl                                             NtStatus = 0xC0000432
	StatusEncounteredWriteInProgress                            NtStatus = 0xC0000433
	StatusPteChanged                                            NtStatus = 0xC0000434
	StatusPurgeFailed                                           NtStatus = 0xC0000435
	StatusCredRequiresConfirmation                              NtStatus = 0xC0000440
	StatusCsEncryptionInvalidServerResponse                     NtStatus = 0xC0000441
	StatusCsEncryptionUnsupportedServer                         NtStatus = 0xC0000442
	StatusCsEncryptionExistingEncryptedFile                     NtStatus = 0xC0000443
	StatusCsEncryptionNewEncryptedFile                          NtStatus = 0xC0000444
	StatusCsEncryptionFileNotCse                                NtStatus = 0xC0000445
	StatusInvalidLabel                                          NtStatus = 0xC0000446
	StatusDriverProcessTerminated                               NtStatus = 0xC0000450
	StatusAmbiguousSystemDevice                                 NtStatus = 0xC0000451
	StatusSystemDeviceNotFound                                  NtStatus = 0xC0000452
	StatusRestartBootApplication                                NtStatus = 0xC0000453
	StatusInsufficientNvramResources                            NtStatus = 0xC0000454
	StatusNoRangesProcessed                                     NtStatus = 0xC0000460
	StatusDeviceFeatureNotSupported                             NtStatus = 0xC0000463
	StatusDeviceUnreachable                                     NtStatus = 0xC0000464
	StatusInvalidToken                                          NtStatus = 0xC0000465
	StatusServerUnavailable                                     NtStatus = 0xC0000466
	StatusInvalidTaskName                                       NtStatus = 0xC0000500
	StatusInvalidTaskIndex                                      NtStatus = 0xC0000501
	StatusThreadAlreadyInTask                                   NtStatus = 0xC0000502
	StatusCallbackBypass                                        NtStatus = 0xC0000503
	StatusFailFastException                                     NtStatus = 0xC0000602
	StatusImageCertRevoked                                      NtStatus = 0xC0000603
	StatusPortClosed                                            NtStatus = 0xC0000700
	StatusMessageLost                                           NtStatus = 0xC0000701
	StatusInvalidMessage                                        NtStatus = 0xC0000702
	StatusRequestCanceled                                       NtStatus = 0xC0000703
	StatusRecursiveDispatch                                     NtStatus = 0xC0000704
	StatusLpcReceiveBufferExpected                              NtStatus = 0xC0000705
	StatusLpcInvalidConnectionUsage                             NtStatus = 0xC0000706
	StatusLpcRequestsNotAllowed                                 NtStatus = 0xC0000707
	StatusResourceInUse                                         NtStatus = 0xC0000708
	StatusHardwareMemoryError                                   NtStatus = 0xC0000709
	StatusThreadpoolHandleException                             NtStatus = 0xC000070A
	StatusThreadpoolSetEventOnCompletionFailed                  NtStatus = 0xC000070B
	StatusThreadpoolReleaseSemaphoreOnCompletionFailed          NtStatus = 0xC000070C
	StatusThreadpoolReleaseMutexOnCompletionFailed              NtStatus = 0xC000070D
	StatusThreadpoolFreeLibraryOnCompletionFailed               NtStatus = 0xC000070E
	StatusThreadpoolReleasedDuringOperation                     NtStatus = 0xC000070F
	StatusCallbackReturnedWhileImpersonating                    NtStatus = 0xC0000710
	StatusApcReturnedWhileImpersonating                         NtStatus = 0xC0000711
	StatusProcessIsProtected                                    NtStatus = 0xC0000712
	StatusMcaException                                          NtStatus = 0xC0000713
	StatusCertificateMappingNotUnique                           NtStatus = 0xC0000714
	StatusSymlinkClassDisabled                                  NtStatus = 0xC0000715
	StatusInvalidIdnNormalization                               NtStatus = 0xC0000716
	StatusNoUnicodeTranslation                                  NtStatus = 0xC0000717
	StatusAlreadyRegistered                                     NtStatus = 0xC0000718
	StatusContextMismatch                                       NtStatus = 0xC0000719
	StatusPortAlreadyHasCompletionList                          NtStatus = 0xC000071A
	StatusCallbackReturnedThreadPriority                        NtStatus = 0xC000071B
	StatusInvalidThread                                         NtStatus = 0xC000071C
	StatusCallbackReturnedTransaction                           NtStatus = 0xC000071D
	StatusCallbackReturnedLdrLock                               NtStatus = 0xC000071E
	StatusCallbackReturnedLang                                  NtStatus = 0xC000071F
	StatusCallbackReturnedPriBack                               NtStatus = 0xC0000720
	StatusDiskRepairDisabled                                    NtStatus = 0xC0000800
	StatusDsDomainRenameInProgress                              NtStatus = 0xC0000801
	StatusDiskQuotaExceeded                                     NtStatus = 0xC0000802
	StatusContentBlocked                                        NtStatus = 0xC0000804
	StatusBadClusters                                           NtStatus = 0xC0000805
	StatusVolumeDirty                                           NtStatus = 0xC0000806
	StatusFileCheckedOut                                        NtStatus = 0xC0000901
	StatusCheckoutRequired                                      NtStatus = 0xC0000902
	StatusBadFileType                                           NtStatus = 0xC0000903
	StatusFileTooLarge                                          NtStatus = 0xC0000904
	StatusFormsAuthRequired                                     NtStatus = 0xC0000905
	StatusVirusInfected                                         NtStatus = 0xC0000906
	StatusVirusDeleted                                          NtStatus = 0xC0000907
	StatusBadMcfgTable                                          NtStatus = 0xC0000908
	StatusCannotBreakOplock                                     NtStatus = 0xC0000909
	StatusWowAssertion                                          NtStatus = 0xC0009898
	StatusInvalidSignature                                      NtStatus = 0xC000A000
	StatusHmacNotSupported                                      NtStatus = 0xC000A001
	StatusIpsecQueueOverflow                                    NtStatus = 0xC000A010
	StatusNdQueueOverflow                                       NtStatus = 0xC000A011
	StatusHoplimitExceeded                                      NtStatus = 0xC000A012
	StatusProtocolNotSupported                                  NtStatus = 0xC000A013
	StatusLostWritebehindDataNetworkDisconnected                NtStatus = 0xC000A080
	StatusLostWritebehindDataNetworkServerError                 NtStatus = 0xC000A081
	StatusLostWritebehindDataLocalDiskError                     NtStatus = 0xC000A082
	StatusXmlParseError                                         NtStatus = 0xC000A083
	StatusXmldsigError                                          NtStatus = 0xC000A084
	StatusWrongCompartment                                      NtStatus = 0xC000A085
	StatusAuthipFailure                                         NtStatus = 0xC000A086
	StatusDsOidMappedGroupCantHaveMembers                       NtStatus = 0xC000A087
	StatusDsOidNotFound                                         NtStatus = 0xC000A088
	StatusHashNotSupported                                      NtStatus = 0xC000A100
	StatusHashNotPresent                                        NtStatus = 0xC000A101
	StatusOffloadReadFltNotSupported                            NtStatus = 0xC000A2A1
	StatusOffloadWriteFltNotSupported                           NtStatus = 0xC000A2A2
	StatusOffloadReadFileNotSupported                           NtStatus = 0xC000A2A3
	StatusOffloadWriteFileNotSupported                          NtStatus = 0xC000A2A4
	DbgNoStateChange                                            NtStatus = 0xC0010001
	DbgAppNotIdle                                               NtStatus = 0xC0010002
	RpcNtInvalidStringBinding                                   NtStatus = 0xC0020001
	RpcNtWrongKindOfBinding                                     NtStatus = 0xC0020002
	RpcNtInvalidBinding                                         NtStatus = 0xC0020003
	RpcNtProtseqNotSupported                                    NtStatus = 0xC0020004
	RpcNtInvalidRpcProtseq                                      NtStatus = 0xC0020005
	RpcNtInvalidStringUuid                                      NtStatus = 0xC0020006
	RpcNtInvalidEndpointFormat                                  NtStatus = 0xC0020007
	RpcNtInvalidNetAddr                                         NtStatus = 0xC0020008
	RpcNtNoEndpointFound                                        NtStatus = 0xC0020009
	RpcNtInvalidTimeout                                         NtStatus = 0xC002000A
	RpcNtObjectNotFound                                         NtStatus = 0xC002000B
	RpcNtAlreadyRegistered                                      NtStatus = 0xC002000C
	RpcNtTypeAlreadyRegistered                                  NtStatus = 0xC002000D
	RpcNtAlreadyListening                                       NtStatus = 0xC002000E
	RpcNtNoProtseqsRegistered                                   NtStatus = 0xC002000F
	RpcNtNotListening                                           NtStatus = 0xC0020010
	RpcNtUnknownMgrType                                         NtStatus = 0xC0020011
	RpcNtUnknownIf                                              NtStatus = 0xC0020012
	RpcNtNoBindings                                             NtStatus = 0xC0020013
	RpcNtNoProtseqs                                             NtStatus = 0xC0020014
	RpcNtCantCreateEndpoint                                     NtStatus = 0xC0020015
	RpcNtOutOfResources                                         NtStatus = 0xC0020016
	RpcNtServerUnavailable                                      NtStatus = 0xC0020017
	RpcNtServerTooBusy                                          NtStatus = 0xC0020018
	RpcNtInvalidNetworkOptions                                  NtStatus = 0xC0020019
	RpcNtNoCallActive                                           NtStatus = 0xC002001A
	RpcNtCallFailed                                             NtStatus = 0xC002001B
	RpcNtCallFailedDne                                          NtStatus = 0xC002001C
	RpcNtProtocolError                                          NtStatus = 0xC002001D
	RpcNtUnsupportedTransSyn                                    NtStatus = 0xC002001F
	RpcNtUnsupportedType                                        NtStatus = 0xC0020021
	RpcNtInvalidTag                                             NtStatus = 0xC0020022
	RpcNtInvalidBound                                           NtStatus = 0xC0020023
	RpcNtNoEntryName                                            NtStatus = 0xC0020024
	RpcNtInvalidNameSyntax                                      NtStatus = 0xC0020025
	RpcNtUnsupportedNameSyntax                                  NtStatus = 0xC0020026
	RpcNtUuidNoAddress                                          NtStatus = 0xC0020028
	RpcNtDuplicateEndpoint                                      NtStatus = 0xC0020029
	RpcNtUnknownAuthnType                                       NtStatus = 0xC002002A
	RpcNtMaxCallsTooSmall                                       NtStatus = 0xC002002B
	RpcNtStringTooLong                                          NtStatus = 0xC002002C
	RpcNtProtseqNotFound                                        NtStatus = 0xC002002D
	RpcNtProcnumOutOfRange                                      NtStatus = 0xC002002E
	RpcNtBindingHasNoAuth                                       NtStatus = 0xC002002F
	RpcNtUnknownAuthnService                                    NtStatus = 0xC0020030
	RpcNtUnknownAuthnLevel                                      NtStatus = 0xC0020031
	RpcNtInvalidAuthIdentity                                    NtStatus = 0xC0020032
	RpcNtUnknownAuthzService                                    NtStatus = 0xC0020033
	EptNtInvalidEntry                                           NtStatus = 0xC0020034
	EptNtCantPerformOp                                          NtStatus = 0xC0020035
	EptNtNotRegistered                                          NtStatus = 0xC0020036
	RpcNtNothingToExport                                        NtStatus = 0xC0020037
	RpcNtIncompleteName                                         NtStatus = 0xC0020038
	RpcNtInvalidVersOption                                      NtStatus = 0xC0020039
	RpcNtNoMoreMembers                                          NtStatus = 0xC002003A
	RpcNtNotAllObjsUnexported                                   NtStatus = 0xC002003B
	RpcNtInterfaceNotFound                                      NtStatus = 0xC002003C
	RpcNtEntryAlreadyExists                                     NtStatus = 0xC002003D
	RpcNtEntryNotFound                                          NtStatus = 0xC002003E
	RpcNtNameServiceUnavailable                                 NtStatus = 0xC002003F
	RpcNtInvalidNafId                                           NtStatus = 0xC0020040
	RpcNtCannotSupport                                          NtStatus = 0xC0020041
	RpcNtNoContextAvailable                                     NtStatus = 0xC0020042
	RpcNtInternalError                                          NtStatus = 0xC0020043
	RpcNtZeroDivide                                             NtStatus = 0xC0020044
	RpcNtAddressError                                           NtStatus = 0xC0020045
	RpcNtFpDivZero                                              NtStatus = 0xC0020046
	RpcNtFpUnderflow                                            NtStatus = 0xC0020047
	RpcNtFpOverflow                                             NtStatus = 0xC0020048
	RpcNtCallInProgress                                         NtStatus = 0xC0020049
	RpcNtNoMoreBindings                                         NtStatus = 0xC002004A
	RpcNtGroupMemberNotFound                                    NtStatus = 0xC002004B
	EptNtCantCreate                                             NtStatus = 0xC002004C
	RpcNtInvalidObject                                          NtStatus = 0xC002004D
	RpcNtNoInterfaces                                           NtStatus = 0xC002004F
	RpcNtCallCancelled                                          NtStatus = 0xC0020050
	RpcNtBindingIncomplete                                      NtStatus = 0xC0020051
	RpcNtCommFailure                                            NtStatus = 0xC0020052
	RpcNtUnsupportedAuthnLevel                                  NtStatus = 0xC0020053
	RpcNtNoPrincName                                            NtStatus = 0xC0020054
	RpcNtNotRpcError                                            NtStatus = 0xC0020055
	RpcNtSecPkgError                                            NtStatus = 0xC0020057
	RpcNtNotCancelled                                           NtStatus = 0xC0020058
	RpcNtInvalidAsyncHandle                                     NtStatus = 0xC0020062
	RpcNtInvalidAsyncCall                                       NtStatus = 0xC0020063
	RpcNtProxyAccessDenied                                      NtStatus = 0xC0020064
	RpcNtNoMoreEntries                                          NtStatus = 0xC0030001
	RpcNtSsCharTransOpenFail                                    NtStatus = 0xC0030002
	RpcNtSsCharTransShortFile                                   NtStatus = 0xC0030003
	RpcNtSsInNullContext                                        NtStatus = 0xC0030004
	RpcNtSsContextMismatch                                      NtStatus = 0xC0030005
	RpcNtSsContextDamaged                                       NtStatus = 0xC0030006
	RpcNtSsHandlesMismatch                                      NtStatus = 0xC0030007
	RpcNtSsCannotGetCallHandle                                  NtStatus = 0xC0030008
	RpcNtNullRefPointer                                         NtStatus = 0xC0030009
	RpcNtEnumValueOutOfRange                                    NtStatus = 0xC003000A
	RpcNtByteCountTooSmall                                      NtStatus = 0xC003000B
	RpcNtBadStubData                                            NtStatus = 0xC003000C
	RpcNtInvalidEsAction                                        NtStatus = 0xC0030059
	RpcNtWrongEsVersion                                         NtStatus = 0xC003005A
	RpcNtWrongStubVersion                                       NtStatus = 0xC003005B
	RpcNtInvalidPipeObject                                      NtStatus = 0xC003005C
	RpcNtInvalidPipeOperation                                   NtStatus = 0xC003005D
	RpcNtWrongPipeVersion                                       NtStatus = 0xC003005E
	RpcNtPipeClosed                                             NtStatus = 0xC003005F
	RpcNtPipeDisciplineError                                    NtStatus = 0xC0030060
	RpcNtPipeEmpty                                              NtStatus = 0xC0030061
	StatusPnpBadMpsTable                                        NtStatus = 0xC0040035
	StatusPnpTranslationFailed                                  NtStatus = 0xC0040036
	StatusPnpIrqTranslationFailed                               NtStatus = 0xC0040037
	StatusPnpInvalidId                                          NtStatus = 0xC0040038
	StatusIoReissueAsCached                                     NtStatus = 0xC0040039
	StatusCtxWinstationNameInvalid                              NtStatus = 0xC00A0001
	StatusCtxInvalidPd                                          NtStatus = 0xC00A0002
	StatusCtxPdNotFound                                         NtStatus = 0xC00A0003
	StatusCtxClosePending                                       NtStatus = 0xC00A0006
	StatusCtxNoOutbuf                                           NtStatus = 0xC00A0007
	StatusCtxModemInfNotFound                                   NtStatus = 0xC00A0008
	StatusCtxInvalidModemname                                   NtStatus = 0xC00A0009
	StatusCtxResponseError                                      NtStatus = 0xC00A000A
	StatusCtxModemResponseTimeout                               NtStatus = 0xC00A000B
	StatusCtxModemResponseNoCarrier                             NtStatus = 0xC00A000C
	StatusCtxModemResponseNoDialtone                            NtStatus = 0xC00A000D
	StatusCtxModemResponseBusy                                  NtStatus = 0xC00A000E
	StatusCtxModemResponseVoice                                 NtStatus = 0xC00A000F
	StatusCtxTdError                                            NtStatus = 0xC00A0010
	StatusCtxLicenseClientInvalid                               NtStatus = 0xC00A0012
	StatusCtxLicenseNotAvailable                                NtStatus = 0xC00A0013
	StatusCtxLicenseExpired                                     NtStatus = 0xC00A0014
	StatusCtxWinstationNotFound                                 NtStatus = 0xC00A0015
	StatusCtxWinstationNameCollision                            NtStatus = 0xC00A0016
	StatusCtxWinstationBusy                                     NtStatus = 0xC00A0017
	StatusCtxBadVideoMode                                       NtStatus = 0xC00A0018
	StatusCtxGraphicsInvalid                                    NtStatus = 0xC00A0022
	StatusCtxNotConsole                                         NtStatus = 0xC00A0024
	StatusCtxClientQueryTimeout                                 NtStatus = 0xC00A0026
	StatusCtxConsoleDisconnect                                  NtStatus = 0xC00A0027
	StatusCtxConsoleConnect                                     NtStatus = 0xC00A0028
	StatusCtxShadowDenied                                       NtStatus = 0xC00A002A
	StatusCtxWinstationAccessDenied                             NtStatus = 0xC00A002B
	StatusCtxInvalidWd                                          NtStatus = 0xC00A002E
	StatusCtxWdNotFound                                         NtStatus = 0xC00A002F
	StatusCtxShadowInvalid                                      NtStatus = 0xC00A0030
	StatusCtxShadowDisabled                                     NtStatus = 0xC00A0031
	StatusRdpProtocolError                                      NtStatus = 0xC00A0032
	StatusCtxClientLicenseNotSet                                NtStatus = 0xC00A0033
	StatusCtxClientLicenseInUse                                 NtStatus = 0xC00A0034
	StatusCtxShadowEndedByModeChange                            NtStatus = 0xC00A0035
	StatusCtxShadowNotRunning                                   NtStatus = 0xC00A0036
	StatusCtxLogonDisabled                                      NtStatus = 0xC00A0037
	StatusCtxSecurityLayerError                                 NtStatus = 0xC00A0038
	StatusTsIncompatibleSessions                                NtStatus = 0xC00A0039
	StatusMuiFileNotFound                                       NtStatus = 0xC00B0001
	StatusMuiInvalidFile                                        NtStatus = 0xC00B0002
	StatusMuiInvalidRcConfig                                    NtStatus = 0xC00B0003
	StatusMuiInvalidLocaleName                                  NtStatus = 0xC00B0004
	StatusMuiInvalidUltimatefallbackName                        NtStatus = 0xC00B0005
	StatusMuiFileNotLoaded                                      NtStatus = 0xC00B0006
	StatusResourceEnumUserStop                                  NtStatus = 0xC00B0007
	StatusClusterInvalidNode                                    NtStatus = 0xC0130001
	StatusClusterNodeExists                                     NtStatus = 0xC0130002
	StatusClusterJoinInProgress                                 NtStatus = 0xC0130003
	StatusClusterNodeNotFound                                   NtStatus = 0xC0130004
	StatusClusterLocalNodeNotFound                              NtStatus = 0xC0130005
	StatusClusterNetworkExists                                  NtStatus = 0xC0130006
	StatusClusterNetworkNotFound                                NtStatus = 0xC0130007
	StatusClusterNetinterfaceExists                             NtStatus = 0xC0130008
	StatusClusterNetinterfaceNotFound                           NtStatus = 0xC0130009
	StatusClusterInvalidRequest                                 NtStatus = 0xC013000A
	StatusClusterInvalidNetworkProvider                         NtStatus = 0xC013000B
	StatusClusterNodeDown                                       NtStatus = 0xC013000C
	StatusClusterNodeUnreachable                                NtStatus = 0xC013000D
	StatusClusterNodeNotMember                                  NtStatus = 0xC013000E
	StatusClusterJoinNotInProgress                              NtStatus = 0xC013000F
	StatusClusterInvalidNetwork                                 NtStatus = 0xC0130010
	StatusClusterNoNetAdapters                                  NtStatus = 0xC0130011
	StatusClusterNodeUp                                         NtStatus = 0xC0130012
	StatusClusterNodePaused                                     NtStatus = 0xC0130013
	StatusClusterNodeNotPaused                                  NtStatus = 0xC0130014
	StatusClusterNoSecurityContext                              NtStatus = 0xC0130015
	StatusClusterNetworkNotInternal                             NtStatus = 0xC0130016
	StatusClusterPoisoned                                       NtStatus = 0xC0130017
	StatusAcpiInvalidOpcode                                     NtStatus = 0xC0140001
	StatusAcpiStackOverflow                                     NtStatus = 0xC0140002
	StatusAcpiAssertFailed                                      NtStatus = 0xC0140003
	StatusAcpiInvalidIndex                                      NtStatus = 0xC0140004
	StatusAcpiInvalidArgument                                   NtStatus = 0xC0140005
	StatusAcpiFatal                                             NtStatus = 0xC0140006
	StatusAcpiInvalidSupername                                  NtStatus = 0xC0140007
	StatusAcpiInvalidArgtype                                    NtStatus = 0xC0140008
	StatusAcpiInvalidObjtype                                    NtStatus = 0xC0140009
	StatusAcpiInvalidTargettype                                 NtStatus = 0xC014000A
	StatusAcpiIncorrectArgumentCount                            NtStatus = 0xC014000B
	StatusAcpiAddressNotMapped                                  NtStatus = 0xC014000C
	StatusAcpiInvalidEventtype                                  NtStatus = 0xC014000D
	StatusAcpiHandlerCollision                                  NtStatus = 0xC014000E
	StatusAcpiInvalidData                                       NtStatus = 0xC014000F
	StatusAcpiInvalidRegion                                     NtStatus = 0xC0140010
	StatusAcpiInvalidAccessSize                                 NtStatus = 0xC0140011
	StatusAcpiAcquireGlobalLock                                 NtStatus = 0xC0140012
	StatusAcpiAlreadyInitialized                                NtStatus = 0xC0140013
	StatusAcpiNotInitialized                                    NtStatus = 0xC0140014
	StatusAcpiInvalidMutexLevel                                 NtStatus = 0xC0140015
	StatusAcpiMutexNotOwned                                     NtStatus = 0xC0140016
	StatusAcpiMutexNotOwner                                     NtStatus = 0xC0140017
	StatusAcpiRsAccess                                          NtStatus = 0xC0140018
	StatusAcpiInvalidTable                                      NtStatus = 0xC0140019
	StatusAcpiRegHandlerFailed                                  NtStatus = 0xC0140020
	StatusAcpiPowerRequestFailed                                NtStatus = 0xC0140021
	StatusSxsSectionNotFound                                    NtStatus = 0xC0150001
	StatusSxsCantGenActctx                                      NtStatus = 0xC0150002
	StatusSxsInvalidActctxdataFormat                            NtStatus = 0xC0150003
	StatusSxsAssemblyNotFound                                   NtStatus = 0xC0150004
	StatusSxsManifestFormatError                                NtStatus = 0xC0150005
	StatusSxsManifestParseError                                 NtStatus = 0xC0150006
	StatusSxsActivationContextDisabled                          NtStatus = 0xC0150007
	StatusSxsKeyNotFound                                        NtStatus = 0xC0150008
	StatusSxsVersionConflict                                    NtStatus = 0xC0150009
	StatusSxsWrongSectionType                                   NtStatus = 0xC015000A
	StatusSxsThreadQueriesDisabled                              NtStatus = 0xC015000B
	StatusSxsAssemblyMissing                                    NtStatus = 0xC015000C
	StatusSxsProcessDefaultAlreadySet                           NtStatus = 0xC015000E
	StatusSxsEarlyDeactivation                                  NtStatus = 0xC015000F
	StatusSxsInvalidDeactivation                                NtStatus = 0xC0150010
	StatusSxsMultipleDeactivation                               NtStatus = 0xC0150011
	StatusSxsSystemDefaultActivationContextEmpty                NtStatus = 0xC0150012
	StatusSxsProcessTerminationRequested                        NtStatus = 0xC0150013
	StatusSxsCorruptActivationStack                             NtStatus = 0xC0150014
	StatusSxsCorruption                                         NtStatus = 0xC0150015
	StatusSxsInvalidIdentityAttributeValue                      NtStatus = 0xC0150016
	StatusSxsInvalidIdentityAttributeName                       NtStatus = 0xC0150017
	StatusSxsIdentityDuplicateAttribute                         NtStatus = 0xC0150018
	StatusSxsIdentityParseError                                 NtStatus = 0xC0150019
	StatusSxsComponentStoreCorrupt                              NtStatus = 0xC015001A
	StatusSxsFileHashMismatch                                   NtStatus = 0xC015001B
	StatusSxsManifestIdentitySameButContentsDifferent           NtStatus = 0xC015001C
	StatusSxsIdentitiesDifferent                                NtStatus = 0xC015001D
	StatusSxsAssemblyIsNotADeployment                           NtStatus = 0xC015001E
	StatusSxsFileNotPartOfAssembly                              NtStatus = 0xC015001F
	StatusAdvancedInstallerFailed                               NtStatus = 0xC0150020
	StatusXmlEncodingMismatch                                   NtStatus = 0xC0150021
	StatusSxsManifestTooBig                                     NtStatus = 0xC0150022
	StatusSxsSettingNotRegistered                               NtStatus = 0xC0150023
	StatusSxsTransactionClosureIncomplete                       NtStatus = 0xC0150024
	StatusSmiPrimitiveInstallerFailed                           NtStatus = 0xC0150025
	StatusGenericCommandFailed                                  NtStatus = 0xC0150026
	StatusSxsFileHashMissing                                    NtStatus = 0xC0150027
	StatusTransactionalConflict                                 NtStatus = 0xC0190001
	StatusInvalidTransaction                                    NtStatus = 0xC0190002
	StatusTransactionNotActive                                  NtStatus = 0xC0190003
	StatusTmInitializationFailed                                NtStatus = 0xC0190004
	StatusRmNotActive                                           NtStatus = 0xC0190005
	StatusRmMetadataCorrupt                                     NtStatus = 0xC0190006
	StatusTransactionNotJoined                                  NtStatus = 0xC0190007
	StatusDirectoryNotRm                                        NtStatus = 0xC0190008
	StatusTransactionsUnsupportedRemote                         NtStatus = 0xC019000A
	StatusLogResizeInvalidSize                                  NtStatus = 0xC019000B
	StatusRemoteFileVersionMismatch                             NtStatus = 0xC019000C
	StatusCrmProtocolAlreadyExists                              NtStatus = 0xC019000F
	StatusTransactionPropagationFailed                          NtStatus = 0xC0190010
	StatusCrmProtocolNotFound                                   NtStatus = 0xC0190011
	StatusTransactionSuperiorExists                             NtStatus = 0xC0190012
	StatusTransactionRequestNotValid                            NtStatus = 0xC0190013
	StatusTransactionNotRequested                               NtStatus = 0xC0190014
	StatusTransactionAlreadyAborted                             NtStatus = 0xC0190015
	StatusTransactionAlreadyCommitted                           NtStatus = 0xC0190016
	StatusTransactionInvalidMarshallBuffer                      NtStatus = 0xC0190017
	StatusCurrentTransactionNotValid                            NtStatus = 0xC0190018
	StatusLogGrowthFailed                                       NtStatus = 0xC0190019
	StatusObjectNoLongerExists                                  NtStatus = 0xC0190021
	StatusStreamMiniversionNotFound                             NtStatus = 0xC0190022
	StatusStreamMiniversionNotValid                             NtStatus = 0xC0190023
	StatusMiniversionInaccessibleFromSpecifiedTransaction       NtStatus = 0xC0190024
	StatusCantOpenMiniversionWithModifyIntent                   NtStatus = 0xC0190025
	StatusCantCreateMoreStreamMiniversions                      NtStatus = 0xC0190026
	StatusHandleNoLongerValid                                   NtStatus = 0xC0190028
	StatusLogCorruptionDetected                                 NtStatus = 0xC0190030
	StatusRmDisconnected                                        NtStatus = 0xC0190032
	StatusEnlistmentNotSuperior                                 NtStatus = 0xC0190033
	StatusFileIdentityNotPersistent                             NtStatus = 0xC0190036
	StatusCantBreakTransactionalDependency                      NtStatus = 0xC0190037
	StatusCantCrossRmBoundary                                   NtStatus = 0xC0190038
	StatusTxfDirNotEmpty                                        NtStatus = 0xC0190039
	StatusIndoubtTransactionsExist                              NtStatus = 0xC019003A
	StatusTmVolatile                                            NtStatus = 0xC019003B
	StatusRollbackTimerExpired                                  NtStatus = 0xC019003C
	StatusTxfAttributeCorrupt                                   NtStatus = 0xC019003D
	StatusEfsNotAllowedInTransaction                            NtStatus = 0xC019003E
	StatusTransactionalOpenNotAllowed                           NtStatus = 0xC019003F
	StatusTransactedMappingUnsupportedRemote                    NtStatus = 0xC0190040
	StatusTransactionRequiredPromotion                          NtStatus = 0xC0190043
	StatusCannotExecuteFileInTransaction                        NtStatus = 0xC0190044
	StatusTransactionsNotFrozen                                 NtStatus = 0xC0190045
	StatusTransactionFreezeInProgress                           NtStatus = 0xC0190046
	StatusNotSnapshotVolume                                     NtStatus = 0xC0190047
	StatusNoSavepointWithOpenFiles                              NtStatus = 0xC0190048
	StatusSparseNotAllowedInTransaction                         NtStatus = 0xC0190049
	StatusTmIdentityMismatch                                    NtStatus = 0xC019004A
	StatusFloatedSection                                        NtStatus = 0xC019004B
	StatusCannotAcceptTransactedWork                            NtStatus = 0xC019004C
	StatusCannotAbortTransactions                               NtStatus = 0xC019004D
	StatusTransactionNotFound                                   NtStatus = 0xC019004E
	StatusResourcemanagerNotFound                               NtStatus = 0xC019004F
	StatusEnlistmentNotFound                                    NtStatus = 0xC0190050
	StatusTransactionmanagerNotFound                            NtStatus = 0xC0190051
	StatusTransactionmanagerNotOnline                           NtStatus = 0xC0190052
	StatusTransactionmanagerRecoveryNameCollision               NtStatus = 0xC0190053
	StatusTransactionNotRoot                                    NtStatus = 0xC0190054
	StatusTransactionObjectExpired                              NtStatus = 0xC0190055
	StatusCompressionNotAllowedInTransaction                    NtStatus = 0xC0190056
	StatusTransactionResponseNotEnlisted                        NtStatus = 0xC0190057
	StatusTransactionRecordTooLong                              NtStatus = 0xC0190058
	StatusNoLinkTrackingInTransaction                           NtStatus = 0xC0190059
	StatusOperationNotSupportedInTransaction                    NtStatus = 0xC019005A
	StatusTransactionIntegrityViolated                          NtStatus = 0xC019005B
	StatusExpiredHandle                                         NtStatus = 0xC0190060
	StatusTransactionNotEnlisted                                NtStatus = 0xC0190061
	StatusLogSectorInvalid                                      NtStatus = 0xC01A0001
	StatusLogSectorParityInvalid                                NtStatus = 0xC01A0002
	StatusLogSectorRemapped                                     NtStatus = 0xC01A0003
	StatusLogBlockIncomplete                                    NtStatus = 0xC01A0004
	StatusLogInvalidRange                                       NtStatus = 0xC01A0005
	StatusLogBlocksExhausted                                    NtStatus = 0xC01A0006
	StatusLogReadContextInvalid                                 NtStatus = 0xC01A0007
	StatusLogRestartInvalid                                     NtStatus = 0xC01A0008
	StatusLogBlockVersion                                       NtStatus = 0xC01A0009
	StatusLogBlockInvalid                                       NtStatus = 0xC01A000A
	StatusLogReadModeInvalid                                    NtStatus = 0xC01A000B
	StatusLogMetadataCorrupt                                    NtStatus = 0xC01A000D
	StatusLogMetadataInvalid                                    NtStatus = 0xC01A000E
	StatusLogMetadataInconsistent                               NtStatus = 0xC01A000F
	StatusLogReservationInvalid                                 NtStatus = 0xC01A0010
	StatusLogCantDelete                                         NtStatus = 0xC01A0011
	StatusLogContainerLimitExceeded                             NtStatus = 0xC01A0012
	StatusLogStartOfLog                                         NtStatus = 0xC01A0013
	StatusLogPolicyAlreadyInstalled                             NtStatus = 0xC01A0014
	StatusLogPolicyNotInstalled                                 NtStatus = 0xC01A0015
	StatusLogPolicyInvalid                                      NtStatus = 0xC01A0016
	StatusLogPolicyConflict                                     NtStatus = 0xC01A0017
	StatusLogPinnedArchiveTail                                  NtStatus = 0xC01A0018
	StatusLogRecordNonexistent                                  NtStatus = 0xC01A0019
	StatusLogRecordsReservedInvalid                             NtStatus = 0xC01A001A
	StatusLogSpaceReservedInvalid                               NtStatus = 0xC01A001B
	StatusLogTailInvalid                                        NtStatus = 0xC01A001C
	StatusLogFull                                               NtStatus = 0xC01A001D
	StatusLogMultiplexed                                        NtStatus = 0xC01A001E
	StatusLogDedicated                                          NtStatus = 0xC01A001F
	StatusLogArchiveNotInProgress                               NtStatus = 0xC01A0020
	StatusLogArchiveInProgress                                  NtStatus = 0xC01A0021
	StatusLogEphemeral                                          NtStatus = 0xC01A0022
	StatusLogNotEnoughContainers                                NtStatus = 0xC01A0023
	StatusLogClientAlreadyRegistered                            NtStatus = 0xC01A0024
	StatusLogClientNotRegistered                                NtStatus = 0xC01A0025
	StatusLogFullHandlerInProgress                              NtStatus = 0xC01A0026
	StatusLogContainerReadFailed                                NtStatus = 0xC01A0027
	StatusLogContainerWriteFailed                               NtStatus = 0xC01A0028
	StatusLogContainerOpenFailed                                NtStatus = 0xC01A0029
	StatusLogContainerStateInvalid                              NtStatus = 0xC01A002A
	StatusLogStateInvalid                                       NtStatus = 0xC01A002B
	StatusLogPinned                                             NtStatus = 0xC01A002C
	StatusLogMetadataFlushFailed                                NtStatus = 0xC01A002D
	StatusLogInconsistentSecurity                               NtStatus = 0xC01A002E
	StatusLogAppendedFlushFailed                                NtStatus = 0xC01A002F
	StatusLogPinnedReservation                                  NtStatus = 0xC01A0030
	StatusVideoHungDisplayDriverThread                          NtStatus = 0xC01B00EA
	StatusFltNoHandlerDefined                                   NtStatus = 0xC01C0001
	StatusFltContextAlreadyDefined                              NtStatus = 0xC01C0002
	StatusFltInvalidAsynchronousRequest                         NtStatus = 0xC01C0003
	StatusFltDisallowFastIo                                     NtStatus = 0xC01C0004
	StatusFltInvalidNameRequest                                 NtStatus = 0xC01C0005
	StatusFltNotSafeToPostOperation                             NtStatus = 0xC01C0006
	StatusFltNotInitialized                                     NtStatus = 0xC01C0007
	StatusFltFilterNotReady                                     NtStatus = 0xC01C0008
	StatusFltPostOperationCleanup                               NtStatus = 0xC01C0009
	StatusFltInternalError                                      NtStatus = 0xC01C000A
	StatusFltDeletingObject                                     NtStatus = 0xC01C000B
	StatusFltMustBeNonpagedPool                                 NtStatus = 0xC01C000C
	StatusFltDuplicateEntry                                     NtStatus = 0xC01C000D
	StatusFltCbdqDisabled                                       NtStatus = 0xC01C000E
	StatusFltDoNotAttach                                        NtStatus = 0xC01C000F
	StatusFltDoNotDetach                                        NtStatus = 0xC01C0010
	StatusFltInstanceAltitudeCollision                          NtStatus = 0xC01C0011
	StatusFltInstanceNameCollision                              NtStatus = 0xC01C0012
	StatusFltFilterNotFound                                     NtStatus = 0xC01C0013
	StatusFltVolumeNotFound                                     NtStatus = 0xC01C0014
	StatusFltInstanceNotFound                                   NtStatus = 0xC01C0015
	StatusFltContextAllocationNotFound                          NtStatus = 0xC01C0016
	StatusFltInvalidContextRegistration                         NtStatus = 0xC01C0017
	StatusFltNameCacheMiss                                      NtStatus = 0xC01C0018
	StatusFltNoDeviceObject                                     NtStatus = 0xC01C0019
	StatusFltVolumeAlreadyMounted                               NtStatus = 0xC01C001A
	StatusFltAlreadyEnlisted                                    NtStatus = 0xC01C001B
	StatusFltContextAlreadyLinked                               NtStatus = 0xC01C001C
	StatusFltNoWaiterForReply                                   NtStatus = 0xC01C0020
	StatusMonitorNoDescriptor                                   NtStatus = 0xC01D0001
	StatusMonitorUnknownDescriptorFormat                        NtStatus = 0xC01D0002
	StatusMonitorInvalidDescriptorChecksum                      NtStatus = 0xC01D0003
	StatusMonitorInvalidStandardTimingBlock                     NtStatus = 0xC01D0004
	StatusMonitorWmiDatablockRegistrationFailed                 NtStatus = 0xC01D0005
	StatusMonitorInvalidSerialNumberMondscBlock                 NtStatus = 0xC01D0006
	StatusMonitorInvalidUserFriendlyMondscBlock                 NtStatus = 0xC01D0007
	StatusMonitorNoMoreDescriptorData                           NtStatus = 0xC01D0008
	StatusMonitorInvalidDetailedTimingBlock                     NtStatus = 0xC01D0009
	StatusMonitorInvalidManufactureDate                         NtStatus = 0xC01D000A
	StatusGraphicsNotExclusiveModeOwner                         NtStatus = 0xC01E0000
	StatusGraphicsInsufficientDmaBuffer                         NtStatus = 0xC01E0001
	StatusGraphicsInvalidDisplayAdapter                         NtStatus = 0xC01E0002
	StatusGraphicsAdapterWasReset                               NtStatus = 0xC01E0003
	StatusGraphicsInvalidDriverModel                            NtStatus = 0xC01E0004
	StatusGraphicsPresentModeChanged                            NtStatus = 0xC01E0005
	StatusGraphicsPresentOccluded                               NtStatus = 0xC01E0006
	StatusGraphicsPresentDenied                                 NtStatus = 0xC01E0007
	StatusGraphicsCannotcolorconvert                            NtStatus = 0xC01E0008
	StatusGraphicsPresentRedirectionDisabled                    NtStatus = 0xC01E000B
	StatusGraphicsPresentUnoccluded                             NtStatus = 0xC01E000C
	StatusGraphicsNoVideoMemory                                 NtStatus = 0xC01E0100
	StatusGraphicsCantLockMemory                                NtStatus = 0xC01E0101
	StatusGraphicsAllocationBusy                                NtStatus = 0xC01E0102
	StatusGraphicsTooManyReferences                             NtStatus = 0xC01E0103
	StatusGraphicsTryAgainLater                                 NtStatus = 0xC01E0104
	StatusGraphicsTryAgainNow                                   NtStatus = 0xC01E0105
	StatusGraphicsAllocationInvalid                             NtStatus = 0xC01E0106
	StatusGraphicsUnswizzlingApertureUnavailable                NtStatus = 0xC01E0107
	StatusGraphicsUnswizzlingApertureUnsupported                NtStatus = 0xC01E0108
	StatusGraphicsCantEvictPinnedAllocation                     NtStatus = 0xC01E0109
	StatusGraphicsInvalidAllocationUsage                        NtStatus = 0xC01E0110
	StatusGraphicsCantRenderLockedAllocation                    NtStatus = 0xC01E0111
	StatusGraphicsAllocationClosed                              NtStatus = 0xC01E0112
	StatusGraphicsInvalidAllocationInstance                     NtStatus = 0xC01E0113
	StatusGraphicsInvalidAllocationHandle                       NtStatus = 0xC01E0114
	StatusGraphicsWrongAllocationDevice                         NtStatus = 0xC01E0115
	StatusGraphicsAllocationContentLost                         NtStatus = 0xC01E0116
	StatusGraphicsGpuExceptionOnDevice                          NtStatus = 0xC01E0200
	StatusGraphicsInvalidVidpnTopology                          NtStatus = 0xC01E0300
	StatusGraphicsVidpnTopologyNotSupported                     NtStatus = 0xC01E0301
	StatusGraphicsVidpnTopologyCurrentlyNotSupported            NtStatus = 0xC01E0302
	StatusGraphicsInvalidVidpn                                  NtStatus = 0xC01E0303
	StatusGraphicsInvalidVideoPresentSource                     NtStatus = 0xC01E0304
	StatusGraphicsInvalidVideoPresentTarget                     NtStatus = 0xC01E0305
	StatusGraphicsVidpnModalityNotSupported                     NtStatus = 0xC01E0306
	StatusGraphicsInvalidVidpnSourcemodeset                     NtStatus = 0xC01E0308
	StatusGraphicsInvalidVidpnTargetmodeset                     NtStatus = 0xC01E0309
	StatusGraphicsInvalidFrequency                              NtStatus = 0xC01E030A
	StatusGraphicsInvalidActiveRegion                           NtStatus = 0xC01E030B
	StatusGraphicsInvalidTotalRegion                            NtStatus = 0xC01E030C
	StatusGraphicsInvalidVideoPresentSourceMode                 NtStatus = 0xC01E0310
	StatusGraphicsInvalidVideoPresentTargetMode                 NtStatus = 0xC01E0311
	StatusGraphicsPinnedModeMustRemainInSet                     NtStatus = 0xC01E0312
	StatusGraphicsPathAlreadyInTopology                         NtStatus = 0xC01E0313
	StatusGraphicsModeAlreadyInModeset                          NtStatus = 0xC01E0314
	StatusGraphicsInvalidVideopresentsourceset                  NtStatus = 0xC01E0315
	StatusGraphicsInvalidVideopresenttargetset                  NtStatus = 0xC01E0316
	StatusGraphicsSourceAlreadyInSet                            NtStatus = 0xC01E0317
	StatusGraphicsTargetAlreadyInSet                            NtStatus = 0xC01E0318
	StatusGraphicsInvalidVidpnPresentPath                       NtStatus = 0xC01E0319
	StatusGraphicsNoRecommendedVidpnTopology                    NtStatus = 0xC01E031A
	StatusGraphicsInvalidMonitorFrequencyrangeset               NtStatus = 0xC01E031B
	StatusGraphicsInvalidMonitorFrequencyrange                  NtStatus = 0xC01E031C
	StatusGraphicsFrequencyrangeNotInSet                        NtStatus = 0xC01E031D
	StatusGraphicsFrequencyrangeAlreadyInSet                    NtStatus = 0xC01E031F
	StatusGraphicsStaleModeset                                  NtStatus = 0xC01E0320
	StatusGraphicsInvalidMonitorSourcemodeset                   NtStatus = 0xC01E0321
	StatusGraphicsInvalidMonitorSourceMode                      NtStatus = 0xC01E0322
	StatusGraphicsNoRecommendedFunctionalVidpn                  NtStatus = 0xC01E0323
	StatusGraphicsModeIdMustBeUnique                            NtStatus = 0xC01E0324
	StatusGraphicsEmptyAdapterMonitorModeSupportIntersection    NtStatus = 0xC01E0325
	StatusGraphicsVideoPresentTargetsLessThanSources            NtStatus = 0xC01E0326
	StatusGraphicsPathNotInTopology                             NtStatus = 0xC01E0327
	StatusGraphicsAdapterMustHaveAtLeastOneSource               NtStatus = 0xC01E0328
	StatusGraphicsAdapterMustHaveAtLeastOneTarget               NtStatus = 0xC01E0329
	StatusGraphicsInvalidMonitordescriptorset                   NtStatus = 0xC01E032A
	StatusGraphicsInvalidMonitordescriptor                      NtStatus = 0xC01E032B
	StatusGraphicsMonitordescriptorNotInSet                     NtStatus = 0xC01E032C
	StatusGraphicsMonitordescriptorAlreadyInSet                 NtStatus = 0xC01E032D
	StatusGraphicsMonitordescriptorIdMustBeUnique               NtStatus = 0xC01E032E
	StatusGraphicsInvalidVidpnTargetSubsetType                  NtStatus = 0xC01E032F
	StatusGraphicsResourcesNotRelated                           NtStatus = 0xC01E0330
	StatusGraphicsSourceIdMustBeUnique                          NtStatus = 0xC01E0331
	StatusGraphicsTargetIdMustBeUnique                          NtStatus = 0xC01E0332
	StatusGraphicsNoAvailableVidpnTarget                        NtStatus = 0xC01E0333
	StatusGraphicsMonitorCouldNotBeAssociatedWithAdapter        NtStatus = 0xC01E0334
	StatusGraphicsNoVidpnmgr                                    NtStatus = 0xC01E0335
	StatusGraphicsNoActiveVidpn                                 NtStatus = 0xC01E0336
	StatusGraphicsStaleVidpnTopology                            NtStatus = 0xC01E0337
	StatusGraphicsMonitorNotConnected                           NtStatus = 0xC01E0338
	StatusGraphicsSourceNotInTopology                           NtStatus = 0xC01E0339
	StatusGraphicsInvalidPrimarysurfaceSize                     NtStatus = 0xC01E033A
	StatusGraphicsInvalidVisibleregionSize                      NtStatus = 0xC01E033B
	StatusGraphicsInvalidStride                                 NtStatus = 0xC01E033C
	StatusGraphicsInvalidPixelformat                            NtStatus = 0xC01E033D
	StatusGraphicsInvalidColorbasis                             NtStatus = 0xC01E033E
	StatusGraphicsInvalidPixelvalueaccessmode                   NtStatus = 0xC01E033F
	StatusGraphicsTargetNotInTopology                           NtStatus = 0xC01E0340
	StatusGraphicsNoDisplayModeManagementSupport                NtStatus = 0xC01E0341
	StatusGraphicsVidpnSourceInUse                              NtStatus = 0xC01E0342
	StatusGraphicsCantAccessActiveVidpn                         NtStatus = 0xC01E0343
	StatusGraphicsInvalidPathImportanceOrdinal                  NtStatus = 0xC01E0344
	StatusGraphicsInvalidPathContentGeometryTransformation      NtStatus = 0xC01E0345
	StatusGraphicsPathContentGeometryTransformationNotSupported NtStatus = 0xC01E0346
	StatusGraphicsInvalidGammaRamp                              NtStatus = 0xC01E0347
	StatusGraphicsGammaRampNotSupported                         NtStatus = 0xC01E0348
	StatusGraphicsMultisamplingNotSupported                     NtStatus = 0xC01E0349
	StatusGraphicsModeNotInModeset                              NtStatus = 0xC01E034A
	StatusGraphicsInvalidVidpnTopologyRecommendationReason      NtStatus = 0xC01E034D
	StatusGraphicsInvalidPathContentType                        NtStatus = 0xC01E034E
	StatusGraphicsInvalidCopyprotectionType                     NtStatus = 0xC01E034F
	StatusGraphicsUnassignedModesetAlreadyExists                NtStatus = 0xC01E0350
	StatusGraphicsInvalidScanlineOrdering                       NtStatus = 0xC01E0352
	StatusGraphicsTopologyChangesNotAllowed                     NtStatus = 0xC01E0353
	StatusGraphicsNoAvailableImportanceOrdinals                 NtStatus = 0xC01E0354
	StatusGraphicsIncompatiblePrivateFormat                     NtStatus = 0xC01E0355
	StatusGraphicsInvalidModePruningAlgorithm                   NtStatus = 0xC01E0356
	StatusGraphicsInvalidMonitorCapabilityOrigin                NtStatus = 0xC01E0357
	StatusGraphicsInvalidMonitorFrequencyrangeConstraint        NtStatus = 0xC01E0358
	StatusGraphicsMaxNumPathsReached                            NtStatus = 0xC01E0359
	StatusGraphicsCancelVidpnTopologyAugmentation               NtStatus = 0xC01E035A
	StatusGraphicsInvalidClientType                             NtStatus = 0xC01E035B
	StatusGraphicsClientvidpnNotSet                             NtStatus = 0xC01E035C
	StatusGraphicsSpecifiedChildAlreadyConnected                NtStatus = 0xC01E0400
	StatusGraphicsChildDescriptorNotSupported                   NtStatus = 0xC01E0401
	StatusGraphicsNotALinkedAdapter                             NtStatus = 0xC01E0430
	StatusGraphicsLeadlinkNotEnumerated                         NtStatus = 0xC01E0431
	StatusGraphicsChainlinksNotEnumerated                       NtStatus = 0xC01E0432
	StatusGraphicsAdapterChainNotReady                          NtStatus = 0xC01E0433
	StatusGraphicsChainlinksNotStarted                          NtStatus = 0xC01E0434
	StatusGraphicsChainlinksNotPoweredOn                        NtStatus = 0xC01E0435
	StatusGraphicsInconsistentDeviceLinkState                   NtStatus = 0xC01E0436
	StatusGraphicsNotPostDeviceDriver                           NtStatus = 0xC01E0438
	StatusGraphicsAdapterAccessNotExcluded                      NtStatus = 0xC01E043B
	StatusGraphicsOpmNotSupported                               NtStatus = 0xC01E0500
	StatusGraphicsCoppNotSupported                              NtStatus = 0xC01E0501
	StatusGraphicsUabNotSupported                               NtStatus = 0xC01E0502
	StatusGraphicsOpmInvalidEncryptedParameters                 NtStatus = 0xC01E0503
	StatusGraphicsOpmParameterArrayTooSmall                     NtStatus = 0xC01E0504
	StatusGraphicsOpmNoProtectedOutputsExist                    NtStatus = 0xC01E0505
	StatusGraphicsPvpNoDisplayDeviceCorrespondsToName           NtStatus = 0xC01E0506
	StatusGraphicsPvpDisplayDeviceNotAttachedToDesktop          NtStatus = 0xC01E0507
	StatusGraphicsPvpMirroringDevicesNotSupported               NtStatus = 0xC01E0508
	StatusGraphicsOpmInvalidPointer                             NtStatus = 0xC01E050A
	StatusGraphicsOpmInternalError                              NtStatus = 0xC01E050B
	StatusGraphicsOpmInvalidHandle                              NtStatus = 0xC01E050C
	StatusGraphicsPvpNoMonitorsCorrespondToDisplayDevice        NtStatus = 0xC01E050D
	StatusGraphicsPvpInvalidCertificateLength                   NtStatus = 0xC01E050E
	StatusGraphicsOpmSpanningModeEnabled                        NtStatus = 0xC01E050F
	StatusGraphicsOpmTheaterModeEnabled                         NtStatus = 0xC01E0510
	StatusGraphicsPvpHfsFailed                                  NtStatus = 0xC01E0511
	StatusGraphicsOpmInvalidSrm                                 NtStatus = 0xC01E0512
	StatusGraphicsOpmOutputDoesNotSupportHdcp                   NtStatus = 0xC01E0513
	StatusGraphicsOpmOutputDoesNotSupportAcp                    NtStatus = 0xC01E0514
	StatusGraphicsOpmOutputDoesNotSupportCgmsa                  NtStatus = 0xC01E0515
	StatusGraphicsOpmHdcpSrmNeverSet                            NtStatus = 0xC01E0516
	StatusGraphicsOpmResolutionTooHigh                          NtStatus = 0xC01E0517
	StatusGraphicsOpmAllHdcpHardwareAlreadyInUse                NtStatus = 0xC01E0518
	StatusGraphicsOpmProtectedOutputNoLongerExists              NtStatus = 0xC01E051A
	StatusGraphicsOpmSessionTypeChangeInProgress                NtStatus = 0xC01E051B
	StatusGraphicsOpmProtectedOutputDoesNotHaveCoppSemantics    NtStatus = 0xC01E051C
	StatusGraphicsOpmInvalidInformationRequest                  NtStatus = 0xC01E051D
	StatusGraphicsOpmDriverInternalError                        NtStatus = 0xC01E051E
	StatusGraphicsOpmProtectedOutputDoesNotHaveOpmSemantics     NtStatus = 0xC01E051F
	StatusGraphicsOpmSignalingNotSupported                      NtStatus = 0xC01E0520
	StatusGraphicsOpmInvalidConfigurationRequest                NtStatus = 0xC01E0521
	StatusGraphicsI2cNotSupported                               NtStatus = 0xC01E0580
	StatusGraphicsI2cDeviceDoesNotExist                         NtStatus = 0xC01E0581
	StatusGraphicsI2cErrorTransmittingData                      NtStatus = 0xC01E0582
	StatusGraphicsI2cErrorReceivingData                         NtStatus = 0xC01E0583
	StatusGraphicsDdcciVcpNotSupported                          NtStatus = 0xC01E0584
	StatusGraphicsDdcciInvalidData                              NtStatus = 0xC01E0585
	StatusGraphicsDdcciMonitorReturnedInvalidTimingStatusByte   NtStatus = 0xC01E0586
	StatusGraphicsDdcciInvalidCapabilitiesString                NtStatus = 0xC01E0587
	StatusGraphicsMcaInternalError                              NtStatus = 0xC01E0588
	StatusGraphicsDdcciInvalidMessageCommand                    NtStatus = 0xC01E0589
	StatusGraphicsDdcciInvalidMessageLength                     NtStatus = 0xC01E058A
	StatusGraphicsDdcciInvalidMessageChecksum                   NtStatus = 0xC01E058B
	StatusGraphicsInvalidPhysicalMonitorHandle                  NtStatus = 0xC01E058C
	StatusGraphicsMonitorNoLongerExists                         NtStatus = 0xC01E058D
	StatusGraphicsOnlyConsoleSessionSupported                   NtStatus = 0xC01E05E0
	StatusGraphicsNoDisplayDeviceCorrespondsToName              NtStatus = 0xC01E05E1
	StatusGraphicsDisplayDeviceNotAttachedToDesktop             NtStatus = 0xC01E05E2
	StatusGraphicsMirroringDevicesNotSupported                  NtStatus = 0xC01E05E3
	StatusGraphicsInvalidPointer                                NtStatus = 0xC01E05E4
	StatusGraphicsNoMonitorsCorrespondToDisplayDevice           NtStatus = 0xC01E05E5
	StatusGraphicsParameterArrayTooSmall                        NtStatus = 0xC01E05E6
	StatusGraphicsInternalError                                 NtStatus = 0xC01E05E7
	StatusGraphicsSessionTypeChangeInProgress                   NtStatus = 0xC01E05E8
	StatusFveLockedVolume                                       NtStatus = 0xC0210000
	StatusFveNotEncrypted                                       NtStatus = 0xC0210001
	StatusFveBadInformation                                     NtStatus = 0xC0210002
	StatusFveTooSmall                                           NtStatus = 0xC0210003
	StatusFveFailedWrongFs                                      NtStatus = 0xC0210004
	StatusFveFailedBadFs                                        NtStatus = 0xC0210005
	StatusFveFsNotExtended                                      NtStatus = 0xC0210006
	StatusFveFsMounted                                          NtStatus = 0xC0210007
	StatusFveNoLicense                                          NtStatus = 0xC0210008
	StatusFveActionNotAllowed                                   NtStatus = 0xC0210009
	StatusFveBadData                                            NtStatus = 0xC021000A
	StatusFveVolumeNotBound                                     NtStatus = 0xC021000B
	StatusFveNotDataVolume                                      NtStatus = 0xC021000C
	StatusFveConvReadError                                      NtStatus = 0xC021000D
	StatusFveConvWriteError                                     NtStatus = 0xC021000E
	StatusFveOverlappedUpdate                                   NtStatus = 0xC021000F
	StatusFveFailedSectorSize                                   NtStatus = 0xC0210010
	StatusFveFailedAuthentication                               NtStatus = 0xC0210011
	StatusFveNotOsVolume                                        NtStatus = 0xC0210012
	StatusFveKeyfileNotFound                                    NtStatus = 0xC0210013
	StatusFveKeyfileInvalid                                     NtStatus = 0xC0210014
	StatusFveKeyfileNoVmk                                       NtStatus = 0xC0210015
	StatusFveTpmDisabled                                        NtStatus = 0xC0210016
	StatusFveTpmSrkAuthNotZero                                  NtStatus = 0xC0210017
	StatusFveTpmInvalidPcr                                      NtStatus = 0xC0210018
	StatusFveTpmNoVmk                                           NtStatus = 0xC0210019
	StatusFvePinInvalid                                         NtStatus = 0xC021001A
	StatusFveAuthInvalidApplication                             NtStatus = 0xC021001B
	StatusFveAuthInvalidConfig                                  NtStatus = 0xC021001C
	StatusFveDebuggerEnabled                                    NtStatus = 0xC021001D
	StatusFveDryRunFailed                                       NtStatus = 0xC021001E
	StatusFveBadMetadataPointer                                 NtStatus = 0xC021001F
	StatusFveOldMetadataCopy                                    NtStatus = 0xC0210020
	StatusFveRebootRequired                                     NtStatus = 0xC0210021
	StatusFveRawAccess                                          NtStatus = 0xC0210022
	StatusFveRawBlocked                                         NtStatus = 0xC0210023
	StatusFveNoFeatureLicense                                   NtStatus = 0xC0210026
	StatusFvePolicyUserDisableRdvNotAllowed                     NtStatus = 0xC0210027
	StatusFveConvRecoveryFailed                                 NtStatus = 0xC0210028
	StatusFveVirtualizedSpaceTooBig                             NtStatus = 0xC0210029
	StatusFveVolumeTooSmall                                     NtStatus = 0xC0210030
	StatusFwpCalloutNotFound                                    NtStatus = 0xC0220001
	StatusFwpConditionNotFound                                  NtStatus = 0xC0220002
	StatusFwpFilterNotFound                                     NtStatus = 0xC0220003
	StatusFwpLayerNotFound                                      NtStatus = 0xC0220004
	StatusFwpProviderNotFound                                   NtStatus = 0xC0220005
	StatusFwpProviderContextNotFound                            NtStatus = 0xC0220006
	StatusFwpSublayerNotFound                                   NtStatus = 0xC0220007
	StatusFwpNotFound                                           NtStatus = 0xC0220008
	StatusFwpAlreadyExists                                      NtStatus = 0xC0220009
	StatusFwpInUse                                              NtStatus = 0xC022000A
	StatusFwpDynamicSessionInProgress                           NtStatus = 0xC022000B
	StatusFwpWrongSession                                       NtStatus = 0xC022000C
	StatusFwpNoTxnInProgress                                    NtStatus = 0xC022000D
	StatusFwpTxnInProgress                                      NtStatus = 0xC022000E
	StatusFwpTxnAborted                                         NtStatus = 0xC022000F
	StatusFwpSessionAborted                                     NtStatus = 0xC0220010
	StatusFwpIncompatibleTxn                                    NtStatus = 0xC0220011
	StatusFwpTimeout                                            NtStatus = 0xC0220012
	StatusFwpNetEventsDisabled                                  NtStatus = 0xC0220013
	StatusFwpIncompatibleLayer                                  NtStatus = 0xC0220014
	StatusFwpKmClientsOnly                                      NtStatus = 0xC0220015
	StatusFwpLifetimeMismatch                                   NtStatus = 0xC0220016
	StatusFwpBuiltinObject                                      NtStatus = 0xC0220017
	StatusFwpTooManyBoottimeFilters                             NtStatus = 0xC0220018
	StatusFwpTooManyCallouts                                    NtStatus = 0xC0220018
	StatusFwpNotificationDropped                                NtStatus = 0xC0220019
	StatusFwpTrafficMismatch                                    NtStatus = 0xC022001A
	StatusFwpIncompatibleSaState                                NtStatus = 0xC022001B
	StatusFwpNullPointer                                        NtStatus = 0xC022001C
	StatusFwpInvalidEnumerator                                  NtStatus = 0xC022001D
	StatusFwpInvalidFlags                                       NtStatus = 0xC022001E
	StatusFwpInvalidNetMask                                     NtStatus = 0xC022001F
	StatusFwpInvalidRange                                       NtStatus = 0xC0220020
	StatusFwpInvalidInterval                                    NtStatus = 0xC0220021
	StatusFwpZeroLengthArray                                    NtStatus = 0xC0220022
	StatusFwpNullDisplayName                                    NtStatus = 0xC0220023
	StatusFwpInvalidActionType                                  NtStatus = 0xC0220024
	StatusFwpInvalidWeight                                      NtStatus = 0xC0220025
	StatusFwpMatchTypeMismatch                                  NtStatus = 0xC0220026
	StatusFwpTypeMismatch                                       NtStatus = 0xC0220027
	StatusFwpOutOfBounds                                        NtStatus = 0xC0220028
	StatusFwpReserved                                           NtStatus = 0xC0220029
	StatusFwpDuplicateCondition                                 NtStatus = 0xC022002A
	StatusFwpDuplicateKeymod                                    NtStatus = 0xC022002B
	StatusFwpActionIncompatibleWithLayer                        NtStatus = 0xC022002C
	StatusFwpActionIncompatibleWithSublayer                     NtStatus = 0xC022002D
	StatusFwpContextIncompatibleWithLayer                       NtStatus = 0xC022002E
	StatusFwpContextIncompatibleWithCallout                     NtStatus = 0xC022002F
	StatusFwpIncompatibleAuthMethod                             NtStatus = 0xC0220030
	StatusFwpIncompatibleDhGroup                                NtStatus = 0xC0220031
	StatusFwpEmNotSupported                                     NtStatus = 0xC0220032
	StatusFwpNeverMatch                                         NtStatus = 0xC0220033
	StatusFwpProviderContextMismatch                            NtStatus = 0xC0220034
	StatusFwpInvalidParameter                                   NtStatus = 0xC0220035
	StatusFwpTooManySublayers                                   NtStatus = 0xC0220036
	StatusFwpCalloutNotificationFailed                          NtStatus = 0xC0220037
	StatusFwpIncompatibleAuthConfig                             NtStatus = 0xC0220038
	StatusFwpIncompatibleCipherConfig                           NtStatus = 0xC0220039
	StatusFwpDuplicateAuthMethod                                NtStatus = 0xC022003C
	StatusFwpTcpipNotReady                                      NtStatus = 0xC0220100
	StatusFwpInjectHandleClosing                                NtStatus = 0xC0220101
	StatusFwpInjectHandleStale                                  NtStatus = 0xC0220102
	StatusFwpCannotPend                                         NtStatus = 0xC0220103
	StatusNdisClosing                                           NtStatus = 0xC0230002
	StatusNdisBadVersion                                        NtStatus = 0xC0230004
	StatusNdisBadCharacteristics                                NtStatus = 0xC0230005
	StatusNdisAdapterNotFound                                   NtStatus = 0xC0230006
	StatusNdisOpenFailed                                        NtStatus = 0xC0230007
	StatusNdisDeviceFailed                                      NtStatus = 0xC0230008
	StatusNdisMulticastFull                                     NtStatus = 0xC0230009
	StatusNdisMulticastExists                                   NtStatus = 0xC023000A
	StatusNdisMulticastNotFound                                 NtStatus = 0xC023000B
	StatusNdisRequestAborted                                    NtStatus = 0xC023000C
	StatusNdisResetInProgress                                   NtStatus = 0xC023000D
	StatusNdisInvalidPacket                                     NtStatus = 0xC023000F
	StatusNdisInvalidDeviceRequest                              NtStatus = 0xC0230010
	StatusNdisAdapterNotReady                                   NtStatus = 0xC0230011
	StatusNdisInvalidLength                                     NtStatus = 0xC0230014
	StatusNdisInvalidData                                       NtStatus = 0xC0230015
	StatusNdisBufferTooShort                                    NtStatus = 0xC0230016
	StatusNdisInvalidOid                                        NtStatus = 0xC0230017
	StatusNdisAdapterRemoved                                    NtStatus = 0xC0230018
	StatusNdisUnsupportedMedia                                  NtStatus = 0xC0230019
	StatusNdisGroupAddressInUse                                 NtStatus = 0xC023001A
	StatusNdisFileNotFound                                      NtStatus = 0xC023001B
	StatusNdisErrorReadingFile                                  NtStatus = 0xC023001C
	StatusNdisAlreadyMapped                                     NtStatus = 0xC023001D
	StatusNdisResourceConflict                                  NtStatus = 0xC023001E
	StatusNdisMediaDisconnected                                 NtStatus = 0xC023001F
	StatusNdisInvalidAddress                                    NtStatus = 0xC0230022
	StatusNdisPaused                                            NtStatus = 0xC023002A
	StatusNdisInterfaceNotFound                                 NtStatus = 0xC023002B
	StatusNdisUnsupportedRevision                               NtStatus = 0xC023002C
	StatusNdisInvalidPort                                       NtStatus = 0xC023002D
	StatusNdisInvalidPortState                                  NtStatus = 0xC023002E
	StatusNdisLowPowerState                                     NtStatus = 0xC023002F
	StatusNdisNotSupported                                      NtStatus = 0xC02300BB
	StatusNdisOffloadPolicy                                     NtStatus = 0xC023100F
	StatusNdisOffloadConnectionRejected                         NtStatus = 0xC0231012
	StatusNdisOffloadPathRejected                               NtStatus = 0xC0231013
	StatusNdisDot11AutoConfigEnabled                            NtStatus = 0xC0232000
	StatusNdisDot11MediaInUse                                   NtStatus = 0xC0232001
	StatusNdisDot11PowerStateInvalid                            NtStatus = 0xC0232002
	StatusNdisPmWolPatternListFull                              NtStatus = 0xC0232003
	StatusNdisPmProtocolOffloadListFull                         NtStatus = 0xC0232004
	StatusIpsecBadSpi                                           NtStatus = 0xC0360001
	StatusIpsecSaLifetimeExpired                                NtStatus = 0xC0360002
	StatusIpsecWrongSa                                          NtStatus = 0xC0360003
	StatusIpsecReplayCheckFailed                                NtStatus = 0xC0360004
	StatusIpsecInvalidPacket                                    NtStatus = 0xC0360005
	StatusIpsecIntegrityCheckFailed                             NtStatus = 0xC0360006
	StatusIpsecClearTextDrop                                    NtStatus = 0xC0360007
	StatusIpsecAuthFirewallDrop                                 NtStatus = 0xC0360008
	StatusIpsecThrottleDrop                                     NtStatus = 0xC0360009
	StatusIpsecDospBlock                                        NtStatus = 0xC0368000
	StatusIpsecDospReceivedMulticast                            NtStatus = 0xC0368001
	StatusIpsecDospInvalidPacket                                NtStatus = 0xC0368002
	StatusIpsecDospStateLookupFailed                            NtStatus = 0xC0368003
	StatusIpsecDospMaxEntries                                   NtStatus = 0xC0368004
	StatusIpsecDospKeymodNotAllowed                             NtStatus = 0xC0368005
	StatusIpsecDospMaxPerIpRatelimitQueues                      NtStatus = 0xC0368006
	StatusVolmgrMirrorNotSupported                              NtStatus = 0xC038005B
	StatusVolmgrRaid5NotSupported                               NtStatus = 0xC038005C
	StatusVirtdiskProviderNotFound                              NtStatus = 0xC03A0014
	StatusVirtdiskNotVirtualDisk                                NtStatus = 0xC03A0015
	StatusVhdParentVhdAccessDenied                              NtStatus = 0xC03A0016
	StatusVhdChildParentSizeMismatch                            NtStatus = 0xC03A0017
	StatusVhdDifferencingChainCycleDetected                     NtStatus = 0xC03A0018
	StatusVhdDifferencingChainErrorInParent                     NtStatus = 0xC03A0019
)

var ntStatusStrings = map[NtStatus]string{
	StatusSuccess:                           "The operation completed successfully. ",
	StatusWait1:                             "The caller specified WaitAny for WaitType and one of the dispatcher objects in the Object array has been set to the signaled state.",
	StatusWait2:                             "The caller specified WaitAny for WaitType and one of the dispatcher objects in the Object array has been set to the signaled state.",
	StatusWait3:                             "The caller specified WaitAny for WaitType and one of the dispatcher objects in the Object array has been set to the signaled state.",
	StatusWait63:                            "The caller specified WaitAny for WaitType and one of the dispatcher objects in the Object array has been set to the signaled state.",
	StatusAbandoned:                         "The caller attempted to wait for a mutex that has been abandoned.",
	StatusAbandonedWait63:                   "The caller attempted to wait for a mutex that has been abandoned.",
	StatusUserApc:                           "A user-mode APC was delivered before the given Interval expired.",
	StatusAlerted:                           "The delay completed because the thread was alerted.",
	StatusTimeout:                           "The given Timeout interval expired.",
	StatusPending:                           "The operation that was requested is pending completion.",
	StatusReparse:                           "A reparse should be performed by the Object Manager because the name of the file resulted in a symbolic link.",
	StatusMoreEntries:                       "Returned by enumeration APIs to indicate more information is available to successive calls.",
	StatusNotAllAssigned:                    "Indicates not all privileges or groups that are referenced are assigned to the caller. This allows, for example, all privileges to be disabled without having to know exactly which privileges are assigned.",
	StatusSomeNotMapped:                     "Some of the information to be translated has not been translated.",
	StatusOplockBreakInProgress:             "An open/create operation completed while an opportunistic lock (oplock) break is underway.",
	StatusVolumeMounted:                     "A new volume has been mounted by a file system.",
	StatusRxactCommitted:                    "This success level status indicates that the transaction state already exists for the registry subtree but that a transaction commit was previously aborted. The commit has now been completed.",
	StatusNotifyCleanup:                     "Indicates that a notify change request has been completed due to closing the handle that made the notify change request.",
	StatusNotifyEnumDir:                     "Indicates that a notify change request is being completed and that the information is not being returned in the caller's buffer. The caller now needs to enumerate the files to find the changes.",
	StatusNoQuotasForAccount:                "{No Quotas} No system quota limits are specifically set for this account.",
	StatusPrimaryTransportConnectFailed:     "{Connect Failure on Primary Transport} An attempt was made to connect to the remote server %hs on the primary transport, but the connection failed. The computer WAS able to connect on a secondary transport.",
	StatusPageFaultTransition:               "The page fault was a transition fault.",
	StatusPageFaultDemandZero:               "The page fault was a demand zero fault.",
	StatusPageFaultCopyOnWrite:              "The page fault was a demand zero fault.",
	StatusPageFaultGuardPage:                "The page fault was a demand zero fault.",
	StatusPageFaultPagingFile:               "The page fault was satisfied by reading from a secondary storage device.",
	StatusCachePageLocked:                   "The cached page was locked during operation.",
	StatusCrashDump:                         "The crash dump exists in a paging file.",
	StatusBufferAllZeros:                    "The specified buffer contains all zeros.",
	StatusReparseObject:                     "A reparse should be performed by the Object Manager because the name of the file resulted in a symbolic link.",
	StatusResourceRequirementsChanged:       "The device has succeeded a query-stop and its resource requirements have changed.",
	StatusTranslationComplete:               "The translator has translated these resources into the global space and no additional translations should be performed.",
	StatusDsMembershipEvaluatedLocally:      "The directory service evaluated group memberships locally, because it was unable to contact a global catalog server.",
	StatusNothingToTerminate:                "A process being terminated has no threads to terminate.",
	StatusProcessNotInJob:                   "The specified process is not part of a job.",
	StatusProcessInJob:                      "The specified process is part of a job.",
	StatusVolsnapHibernateReady:             "{Volume Shadow Copy Service} The system is now ready for hibernation.",
	StatusFsfilterOpCompletedSuccessfully:   "A file system or file system filter driver has successfully completed an FsFilter operation.",
	StatusInterruptVectorAlreadyConnected:   "The specified interrupt vector was already connected.",
	StatusInterruptStillConnected:           "The specified interrupt vector is still connected.",
	StatusProcessCloned:                     "The current process is a cloned process.",
	StatusFileLockedWithOnlyReaders:         "The file was locked and all users of the file can only read.",
	StatusFileLockedWithWriters:             "The file was locked and at least one user of the file can write.",
	StatusResourcemanagerReadOnly:           "The specified ResourceManager made no changes or updates to the resource under this transaction.",
	StatusWaitForOplock:                     "An operation is blocked and waiting for an oplock.",
	DbgExceptionHandled:                     "Debugger handled the exception.",
	DbgContinue:                             "The debugger continued.",
	StatusFltIoComplete:                     "The IO was completed by a filter.",
	StatusFileNotAvailable:                  "The file is temporarily unavailable.",
	StatusCallbackReturnedThreadAffinity:    "A threadpool worker thread entered a callback at thread affinity %p and exited at affinity %p.This is unexpected, indicating that the callback missed restoring the priority.",
	StatusObjectNameExists:                  "{Object Exists} An attempt was made to create an object but the object name already exists.",
	StatusThreadWasSuspended:                "{Thread Suspended} A thread termination occurred while the thread was suspended. The thread resumed, and termination proceeded.",
	StatusWorkingSetLimitRange:              "{Working Set Range Error} An attempt was made to set the working set minimum or maximum to values that are outside the allowable range.",
	StatusImageNotAtBase:                    "{Image Relocated} An image file could not be mapped at the address that is specified in the image file. Local fixes must be performed on this image.",
	StatusRxactStateCreated:                 "This informational level status indicates that a specified registry subtree transaction state did not yet exist and had to be created.",
	StatusSegmentNotification:               "{Segment Load} A virtual DOS machine (VDM) is loading, unloading, or moving an MS-DOS or Win16 program segment image. An exception is raised so that a debugger can load, unload, or track symbols and breakpoints within these 16-bit segments.",
	StatusLocalUserSessionKey:               "{Local Session Key} A user session key was requested for a local remote procedure call (RPC) connection. The session key that is returned is a constant value and not unique to this connection.",
	StatusBadCurrentDirectory:               "{Invalid Current Directory} The process cannot switch to the startup current directory %hs. Select OK to set the current directory to %hs, or select CANCEL to exit.",
	StatusSerialMoreWrites:                  "{Serial IOCTL Complete} A serial I/O operation was completed by another write to a serial port. (The IOCTL_SERIAL_XOFF_COUNTER reached zero.)",
	StatusRegistryRecovered:                 "{Registry Recovery} One of the files that contains the system registry data had to be recovered by using a log or alternate copy. The recovery was successful.",
	StatusFtReadRecoveryFromBackup:          "{Redundant Read} To satisfy a read request, the Windows NT operating system fault-tolerant file system successfully read the requested data from a redundant copy. This was done because the file system encountered a failure on a member of the fault-tolerant volume but was unable to reassign the failing area of the device.",
	StatusFtWriteRecovery:                   "{Redundant Write} To satisfy a write request, the Windows NT fault-tolerant file system successfully wrote a redundant copy of the information. This was done because the file system encountered a failure on a member of the fault-tolerant volume but was unable to reassign the failing area of the device.",
	StatusSerialCounterTimeout:              "{Serial IOCTL Timeout} A serial I/O operation completed because the time-out period expired. (The IOCTL_SERIAL_XOFF_COUNTER had not reached zero.)",
	StatusNullLmPassword:                    "{Password Too Complex} The Windows password is too complex to be converted to a LAN Manager password. The LAN Manager password that returned is a NULL string.",
	StatusImageMachineTypeMismatch:          "{Machine Type Mismatch} The image file %hs is valid but is for a machine type other than the current machine. Select OK to continue, or CANCEL to fail the DLL load.",
	StatusReceivePartial:                    "{Partial Data Received} The network transport returned partial data to its client. The remaining data will be sent later.",
	StatusReceiveExpedited:                  "{Expedited Data Received} The network transport returned data to its client that was marked as expedited by the remote system.",
	StatusReceivePartialExpedited:           "{Partial Expedited Data Received} The network transport returned partial data to its client and this data was marked as expedited by the remote system. The remaining data will be sent later.",
	StatusEventDone:                         "{TDI Event Done} The TDI indication has completed successfully.",
	StatusEventPending:                      "{TDI Event Pending} The TDI indication has entered the pending state.",
	StatusCheckingFileSystem:                "Checking file system on %wZ.",
	StatusFatalAppExit:                      "{Fatal Application Exit} %hs",
	StatusPredefinedHandle:                  "The specified registry key is referenced by a predefined handle.",
	StatusWasUnlocked:                       "{Page Unlocked} The page protection of a locked page was changed to 'No Access' and the page was unlocked from memory and from the process.",
	StatusServiceNotification:               "%hs",
	StatusWasLocked:                         "{Page Locked} One of the pages to lock was already locked.",
	StatusLogHardError:                      "Application popup: %1 : %2",
	StatusAlreadyWin32:                      "A Win32 process already exists.",
	StatusWx86Unsimulate:                    "An exception status code that is used by the Win32 x86 emulation subsystem.",
	StatusWx86Continue:                      "An exception status code that is used by the Win32 x86 emulation subsystem.",
	StatusWx86SingleStep:                    "An exception status code that is used by the Win32 x86 emulation subsystem.",
	StatusWx86Breakpoint:                    "An exception status code that is used by the Win32 x86 emulation subsystem.",
	StatusWx86ExceptionContinue:             "An exception status code that is used by the Win32 x86 emulation subsystem.",
	StatusWx86ExceptionLastchance:           "An exception status code that is used by the Win32 x86 emulation subsystem.",
	StatusWx86ExceptionChain:                "An exception status code that is used by the Win32 x86 emulation subsystem.",
	StatusImageMachineTypeMismatchExe:       "{Machine Type Mismatch} The image file %hs is valid but is for a machine type other than the current machine.",
	StatusNoYieldPerformed:                  "A yield execution was performed and no thread was available to run.",
	StatusTimerResumeIgnored:                "The resume flag to a timer API was ignored.",
	StatusArbitrationUnhandled:              "The arbiter has deferred arbitration of these resources to its parent.",
	StatusCardbusNotSupported:               "The device has detected a CardBus card in its slot.",
	StatusWx86Createwx86tib:                 "An exception status code that is used by the Win32 x86 emulation subsystem.",
	StatusMpProcessorMismatch:               "The CPUs in this multiprocessor system are not all the same revision level. To use all processors, the operating system restricts itself to the features of the least capable processor in the system. If problems occur with this system, contact the CPU manufacturer to see if this mix of processors is supported.",
	StatusHibernated:                        "The system was put into hibernation.",
	StatusResumeHibernation:                 "The system was resumed from hibernation.",
	StatusFirmwareUpdated:                   "Windows has detected that the system firmware (BIOS) was updated [previous firmware date = %2, current firmware date %3].",
	StatusDriversLeakingLockedPages:         "A device driver is leaking locked I/O pages and is causing system degradation. The system has automatically enabled the tracking code to try and catch the culprit.",
	StatusMessageRetrieved:                  "The ALPC message being canceled has already been retrieved from the queue on the other side.",
	StatusSystemPowerstateTransition:        "The system power state is transitioning from %2 to %3.",
	StatusAlpcCheckCompletionList:           "The receive operation was successful. Check the ALPC completion list for the received message.",
	StatusSystemPowerstateComplexTransition: "The system power state is transitioning from %2 to %3 but could enter %4.",
	StatusAccessAuditByPolicy:               "Access to %1 is monitored by policy rule %2.",
	StatusAbandonHiberfile:                  "A valid hibernation file has been invalidated and should be abandoned.",
	StatusBizrulesNotEnabled:                "Business rule scripts are disabled for the calling application.",
	StatusWakeSystem:                        "The system has awoken.",
	StatusDsShuttingDown:                    "The directory service is shutting down.",
	DbgReplyLater:                           "Debugger will reply later.",
	DbgUnableToProvideHandle:                "Debugger cannot provide a handle.",
	DbgTerminateThread:                      "Debugger terminated the thread.",
	DbgTerminateProcess:                     "Debugger terminated the process.",
	DbgControlC:                             "Debugger obtained control of C.",
	DbgPrintexceptionC:                      "Debugger printed an exception on control C.",
	DbgRipexception:                         "Debugger received a RIP exception.",
	DbgControlBreak:                         "Debugger received a control break.",
	DbgCommandException:                     "Debugger command communication exception.",
	RpcNtUuidLocalOnly:                      "A UUID that is valid only on this computer has been allocated.",
	RpcNtSendIncomplete:                     "Some data remains to be sent in the request buffer.",
	StatusCtxCdmConnect:                     "The Client Drive Mapping Service has connected on Terminal Connection.",
	StatusCtxCdmDisconnect:                  "The Client Drive Mapping Service has disconnected on Terminal Connection.",
	StatusSxsReleaseActivationContext:       "A kernel mode component is releasing a reference on an activation context.",
	StatusRecoveryNotNeeded:                 "The transactional resource manager is already consistent. Recovery is not needed.",
	StatusRmAlreadyStarted:                  "The transactional resource manager has already been started.",
	StatusLogNoRestart:                      "The log service encountered a log stream with no restart area.",
	StatusVideoDriverDebugReportRequest:     "{Display Driver Recovered From Failure} The %hs display driver has detected a failure and recovered from it. Some graphical operations may have failed. The next time you restart the machine, a dialog box appears, giving you an opportunity to upload data about this failure to Microsoft.",
	StatusGraphicsPartialDataPopulated:      "The specified buffer is not big enough to contain the entire requested dataset. Partial data is populated up to the size of the buffer.The caller needs to provide a buffer of the size as specified in the partially populated buffer's content (interface specific).",
	StatusGraphicsDriverMismatch:            "The kernel driver detected a version mismatch between it and the user mode driver.",
	StatusGraphicsModeNotPinned:             "No mode is pinned on the specified VidPN source/target.",
	StatusGraphicsNoPreferredMode:           "The specified mode set does not specify a preference for one of its modes.",
	StatusGraphicsDatasetIsEmpty:            "The specified dataset (for example, mode set, frequency range set, descriptor set, or topology) is empty.",
	StatusGraphicsNoMoreElementsInDataset:   "The specified dataset (for example, mode set, frequency range set, descriptor set, or topology) does not contain any more elements.",
	StatusGraphicsPathContentGeometryTransformationNotPinned:    "The specified content transformation is not pinned on the specified VidPN present path.",
	StatusGraphicsUnknownChildStatus:                            "The child device presence was not reliably detected.",
	StatusGraphicsLeadlinkStartDeferred:                         "Starting the lead adapter in a linked configuration has been temporarily deferred.",
	StatusGraphicsPollingTooFrequently:                          "The display adapter is being polled for children too frequently at the same polling level.",
	StatusGraphicsStartDeferred:                                 "Starting the adapter has been temporarily deferred.",
	StatusNdisIndicationRequired:                                "The request will be completed later by an NDIS status indication.",
	StatusGuardPageViolation:                                    "{EXCEPTION} Guard Page Exception A page of memory that marks the end of a data structure, such as a stack or an array, has been accessed.",
	StatusDatatypeMisalignment:                                  "{EXCEPTION} Alignment Fault A data type misalignment was detected in a load or store instruction.",
	StatusBreakpoint:                                            "{EXCEPTION} Breakpoint A breakpoint has been reached.",
	StatusSingleStep:                                            "{EXCEPTION} Single Step A single step or trace operation has just been completed.",
	StatusBufferOverflow:                                        "{Buffer Overflow} The data was too large to fit into the specified buffer.",
	StatusNoMoreFiles:                                           "{No More Files} No more files were found which match the file specification.",
	StatusWakeSystemDebugger:                                    "{Kernel Debugger Awakened} The system debugger was awakened by an interrupt.",
	StatusHandlesClosed:                                         "{Handles Closed} Handles to objects have been automatically closed because of the requested operation.",
	StatusNoInheritance:                                         "{Non-Inheritable ACL} An access control list (ACL) contains no components that can be inherited.",
	StatusGuidSubstitutionMade:                                  "{GUID Substitution} During the translation of a globally unique identifier (GUID) to a Windows security ID (SID), no administratively defined GUID prefix was found. A substitute prefix was used, which will not compromise system security. However, this may provide a more restrictive access than intended.",
	StatusPartialCopy:                                           "Because of protection conflicts, not all the requested bytes could be copied.",
	StatusDevicePaperEmpty:                                      "{Out of Paper} The printer is out of paper.",
	StatusDevicePoweredOff:                                      "{Device Power Is Off} The printer power has been turned off.",
	StatusDeviceOffLine:                                         "{Device Offline} The printer has been taken offline.",
	StatusDeviceBusy:                                            "{Device Busy} The device is currently busy.",
	StatusNoMoreEas:                                             "{No More EAs} No more extended attributes (EAs) were found for the file.",
	StatusInvalidEaName:                                         "{Illegal EA} The specified extended attribute (EA) name contains at least one illegal character.",
	StatusEaListInconsistent:                                    "{Inconsistent EA List} The extended attribute (EA) list is inconsistent.",
	StatusInvalidEaFlag:                                         "{Invalid EA Flag} An invalid extended attribute (EA) flag was set.",
	StatusVerifyRequired:                                        "{Verifying Disk} The media has changed and a verify operation is in progress; therefore, no reads or writes may be performed to the device, except those that are used in the verify operation.",
	StatusExtraneousInformation:                                 "{Too Much Information} The specified access control list (ACL) contained more information than was expected.",
	StatusRxactCommitNecessary:                                  "This warning level status indicates that the transaction state already exists for the registry subtree, but that a transaction commit was previously aborted. The commit has NOT been completed but has not been rolled back either; therefore, it may still be committed, if needed.",
	StatusNoMoreEntries:                                         "{No More Entries} No more entries are available from an enumeration operation.",
	StatusFilemarkDetected:                                      "{Filemark Found} A filemark was detected.",
	StatusMediaChanged:                                          "{Media Changed} The media may have changed.",
	StatusBusReset:                                              "{I/O Bus Reset} An I/O bus reset was detected.",
	StatusEndOfMedia:                                            "{End of Media} The end of the media was encountered.",
	StatusBeginningOfMedia:                                      "The beginning of a tape or partition has been detected.",
	StatusMediaCheck:                                            "{Media Changed} The media may have changed.",
	StatusSetmarkDetected:                                       "A tape access reached a set mark.",
	StatusNoDataDetected:                                        "During a tape access, the end of the data written is reached.",
	StatusRedirectorHasOpenHandles:                              "The redirector is in use and cannot be unloaded.",
	StatusServerHasOpenHandles:                                  "The server is in use and cannot be unloaded.",
	StatusAlreadyDisconnected:                                   "The specified connection has already been disconnected.",
	StatusLongjump:                                              "A long jump has been executed.",
	StatusCleanerCartridgeInstalled:                             "A cleaner cartridge is present in the tape library.",
	StatusPlugplayQueryVetoed:                                   "The Plug and Play query operation was not successful.",
	StatusUnwindConsolidate:                                     "A frame consolidation has been executed.",
	StatusRegistryHiveRecovered:                                 "{Registry Hive Recovered} The registry hive (file): %hs was corrupted and it has been recovered. Some data might have been lost.",
	StatusDllMightBeInsecure:                                    "The application is attempting to run executable code from the module %hs. This may be insecure. An alternative, %hs, is available. Should the application use the secure module %hs?",
	StatusDllMightBeIncompatible:                                "The application is loading executable code from the module %hs. This is secure but may be incompatible with previous releases of the operating system. An alternative, %hs, is available. Should the application use the secure module %hs?",
	StatusStoppedOnSymlink:                                      "The create operation stopped after reaching a symbolic link.",
	StatusDeviceRequiresCleaning:                                "The device has indicated that cleaning is necessary.",
	StatusDeviceDoorOpen:                                        "The device has indicated that its door is open. Further operations require it closed and secured.",
	StatusDataLostRepair:                                        "Windows discovered a corruption in the file %hs. This file has now been repaired. Check if any data in the file was lost because of the corruption.",
	DbgExceptionNotHandled:                                      "Debugger did not handle the exception.",
	StatusClusterNodeAlreadyUp:                                  "The cluster node is already up.",
	StatusClusterNodeAlreadyDown:                                "The cluster node is already down.",
	StatusClusterNetworkAlreadyOnline:                           "The cluster network is already online.",
	StatusClusterNetworkAlreadyOffline:                          "The cluster network is already offline.",
	StatusClusterNodeAlreadyMember:                              "The cluster node is already a member of the cluster.",
	StatusCouldNotResizeLog:                                     "The log could not be set to the requested size.",
	StatusNoTxfMetadata:                                         "There is no transaction metadata on the file.",
	StatusCantRecoverWithHandleOpen:                             "The file cannot be recovered because there is a handle still open on it.",
	StatusTxfMetadataAlreadyPresent:                             "Transaction metadata is already present on this file and cannot be superseded.",
	StatusTransactionScopeCallbacksNotSet:                       "A transaction scope could not be entered because the scope handler has not been initialized.",
	StatusVideoHungDisplayDriverThreadRecovered:                 "{Display Driver Stopped Responding and recovered} The %hs display driver has stopped working normally. The recovery had been performed.",
	StatusFltBufferTooSmall:                                     "{Buffer too small} The buffer is too small to contain the entry. No information has been written to the buffer.",
	StatusFvePartialMetadata:                                    "Volume metadata read or write is incomplete.",
	StatusFveTransientState:                                     "BitLocker encryption keys were ignored because the volume was in a transient state.",
	StatusUnsuccessful:                                          "{Operation Failed} The requested operation was unsuccessful.",
	StatusNotImplemented:                                        "{Not Implemented} The requested operation is not implemented.",
	StatusInvalidInfoClass:                                      "{Invalid Parameter} The specified information class is not a valid information class for the specified object.",
	StatusInfoLengthMismatch:                                    "The specified information record length does not match the length that is required for the specified information class.",
	StatusAccessViolation:                                       "The instruction at 0x%08lx referenced memory at 0x%08lx. The memory could not be %s.",
	StatusInPageError:                                           "The instruction at 0x%08lx referenced memory at 0x%08lx. The required data was not placed into memory because of an I/O error status of 0x%08lx.",
	StatusPagefileQuota:                                         "The page file quota for the process has been exhausted.",
	StatusInvalidHandle:                                         "An invalid HANDLE was specified.",
	StatusBadInitialStack:                                       "An invalid initial stack was specified in a call to NtCreateThread.",
	StatusBadInitialPc:                                          "An invalid initial start address was specified in a call to NtCreateThread.",
	StatusInvalidCid:                                            "An invalid client ID was specified.",
	StatusTimerNotCanceled:                                      "An attempt was made to cancel or set a timer that has an associated APC and the specified thread is not the thread that originally set the timer with an associated APC routine.",
	StatusInvalidParameter:                                      "An invalid parameter was passed to a service or function.",
	StatusNoSuchDevice:                                          "A device that does not exist was specified.",
	StatusNoSuchFile:                                            "{File Not Found} The file %hs does not exist.",
	StatusInvalidDeviceRequest:                                  "The specified request is not a valid operation for the target device.",
	StatusEndOfFile:                                             "The end-of-file marker has been reached. There is no valid data in the file beyond this marker.",
	StatusWrongVolume:                                           "{Wrong Volume} The wrong volume is in the drive. Insert volume %hs into drive %hs.",
	StatusNoMediaInDevice:                                       "{No Disk} There is no disk in the drive. Insert a disk into drive %hs.",
	StatusUnrecognizedMedia:                                     "{Unknown Disk Format} The disk in drive %hs is not formatted properly. Check the disk, and reformat it, if needed.",
	StatusNonexistentSector:                                     "{Sector Not Found} The specified sector does not exist.",
	StatusMoreProcessingRequired:                                "{Still Busy} The specified I/O request packet (IRP) cannot be disposed of because the I/O operation is not complete.",
	StatusNoMemory:                                              "{Not Enough Quota} Not enough virtual memory or paging file quota is available to complete the specified operation.",
	StatusConflictingAddresses:                                  "{Conflicting Address Range} The specified address range conflicts with the address space.",
	StatusNotMappedView:                                         "The address range to unmap is not a mapped view.",
	StatusUnableToFreeVm:                                        "The virtual memory cannot be freed.",
	StatusUnableToDeleteSection:                                 "The specified section cannot be deleted.",
	StatusInvalidSystemService:                                  "An invalid system service was specified in a system service call.",
	StatusIllegalInstruction:                                    "{EXCEPTION} Illegal Instruction An attempt was made to execute an illegal instruction.",
	StatusInvalidLockSequence:                                   "{Invalid Lock Sequence} An attempt was made to execute an invalid lock sequence.",
	StatusInvalidViewSize:                                       "{Invalid Mapping} An attempt was made to create a view for a section that is bigger than the section.",
	StatusInvalidFileForSection:                                 "{Bad File} The attributes of the specified mapping file for a section of memory cannot be read.",
	StatusAlreadyCommitted:                                      "{Already Committed} The specified address range is already committed.",
	StatusAccessDenied:                                          "{Access Denied} A process has requested access to an object but has not been granted those access rights.",
	StatusBufferTooSmall:                                        "{Buffer Too Small} The buffer is too small to contain the entry. No information has been written to the buffer.",
	StatusObjectTypeMismatch:                                    "{Wrong Type} There is a mismatch between the type of object that is required by the requested operation and the type of object that is specified in the request.",
	StatusNoncontinuableException:                               "{EXCEPTION} Cannot Continue Windows cannot continue from this exception.",
	StatusInvalidDisposition:                                    "An invalid exception disposition was returned by an exception handler.",
	StatusUnwind:                                                "Unwind exception code.",
	StatusBadStack:                                              "An invalid or unaligned stack was encountered during an unwind operation.",
	StatusInvalidUnwindTarget:                                   "An invalid unwind target was encountered during an unwind operation.",
	StatusNotLocked:                                             "An attempt was made to unlock a page of memory that was not locked.",
	StatusParityError:                                           "A device parity error on an I/O operation.",
	StatusUnableToDecommitVm:                                    "An attempt was made to decommit uncommitted virtual memory.",
	StatusNotCommitted:                                          "An attempt was made to change the attributes on memory that has not been committed.",
	StatusInvalidPortAttributes:                                 "Invalid object attributes specified to NtCreatePort or invalid port attributes specified to NtConnectPort.",
	StatusPortMessageTooLong:                                    "The length of the message that was passed to NtRequestPort or NtRequestWaitReplyPort is longer than the maximum message that is allowed by the port.",
	StatusInvalidParameterMix:                                   "An invalid combination of parameters was specified.",
	StatusInvalidQuotaLower:                                     "An attempt was made to lower a quota limit below the current usage.",
	StatusDiskCorruptError:                                      "{Corrupt Disk} The file system structure on the disk is corrupt and unusable. Run the Chkdsk utility on the volume %hs.",
	StatusObjectNameInvalid:                                     "The object name is invalid.",
	StatusObjectNameNotFound:                                    "The object name is not found.",
	StatusObjectNameCollision:                                   "The object name already exists.",
	StatusPortDisconnected:                                      "An attempt was made to send a message to a disconnected communication port.",
	StatusDeviceAlreadyAttached:                                 "An attempt was made to attach to a device that was already attached to another device.",
	StatusObjectPathInvalid:                                     "The object path component was not a directory object.",
	StatusObjectPathNotFound:                                    "{Path Not Found} The path %hs does not exist.",
	StatusObjectPathSyntaxBad:                                   "The object path component was not a directory object.",
	StatusDataOverrun:                                           "{Data Overrun} A data overrun error occurred.",
	StatusDataLateError:                                         "{Data Late} A data late error occurred.",
	StatusDataError:                                             "{Data Error} An error occurred in reading or writing data.",
	StatusCrcError:                                              "{Bad CRC} A cyclic redundancy check (CRC) checksum error occurred.",
	StatusSectionTooBig:                                         "{Section Too Large} The specified section is too big to map the file.",
	StatusPortConnectionRefused:                                 "The NtConnectPort request is refused.",
	StatusInvalidPortHandle:                                     "The type of port handle is invalid for the operation that is requested.",
	StatusSharingViolation:                                      "A file cannot be opened because the share access flags are incompatible.",
	StatusQuotaExceeded:                                         "Insufficient quota exists to complete the operation.",
	StatusInvalidPageProtection:                                 "The specified page protection was not valid.",
	StatusMutantNotOwned:                                        "An attempt to release a mutant object was made by a thread that was not the owner of the mutant object.",
	StatusSemaphoreLimitExceeded:                                "An attempt was made to release a semaphore such that its maximum count would have been exceeded.",
	StatusPortAlreadySet:                                        "An attempt was made to set the DebugPort or ExceptionPort of a process, but a port already exists in the process, or an attempt was made to set the CompletionPort of a file but a port was already set in the file, or an attempt was made to set the associated completion port of an ALPC port but it is already set.",
	StatusSectionNotImage:                                       "An attempt was made to query image information on a section that does not map an image.",
	StatusSuspendCountExceeded:                                  "An attempt was made to suspend a thread whose suspend count was at its maximum.",
	StatusThreadIsTerminating:                                   "An attempt was made to suspend a thread that has begun termination.",
	StatusBadWorkingSetLimit:                                    "An attempt was made to set the working set limit to an invalid value (for example, the minimum greater than maximum).",
	StatusIncompatibleFileMap:                                   "A section was created to map a file that is not compatible with an already existing section that maps the same file.",
	StatusSectionProtection:                                     "A view to a section specifies a protection that is incompatible with the protection of the initial view.",
	StatusEasNotSupported:                                       "An operation involving EAs failed because the file system does not support EAs.",
	StatusEaTooLarge:                                            "An EA operation failed because the EA set is too large.",
	StatusNonexistentEaEntry:                                    "An EA operation failed because the name or EA index is invalid.",
	StatusNoEasOnFile:                                           "The file for which EAs were requested has no EAs.",
	StatusEaCorruptError:                                        "The EA is corrupt and cannot be read.",
	StatusFileLockConflict:                                      "A requested read/write cannot be granted due to a conflicting file lock.",
	StatusLockNotGranted:                                        "A requested file lock cannot be granted due to other existing locks.",
	StatusDeletePending:                                         "A non-close operation has been requested of a file object that has a delete pending.",
	StatusCtlFileNotSupported:                                   "An attempt was made to set the control attribute on a file. This attribute is not supported in the destination file system.",
	StatusUnknownRevision:                                       "Indicates a revision number that was encountered or specified is not one that is known by the service. It may be a more recent revision than the service is aware of.",
	StatusRevisionMismatch:                                      "Indicates that two revision levels are incompatible.",
	StatusInvalidOwner:                                          "Indicates a particular security ID may not be assigned as the owner of an object.",
	StatusInvalidPrimaryGroup:                                   "Indicates a particular security ID may not be assigned as the primary group of an object.",
	StatusNoImpersonationToken:                                  "An attempt has been made to operate on an impersonation token by a thread that is not currently impersonating a client.",
	StatusCantDisableMandatory:                                  "A mandatory group may not be disabled.",
	StatusNoLogonServers:                                        "No logon servers are currently available to service the logon request.",
	StatusNoSuchLogonSession:                                    "A specified logon session does not exist. It may already have been terminated.",
	StatusNoSuchPrivilege:                                       "A specified privilege does not exist.",
	StatusPrivilegeNotHeld:                                      "A required privilege is not held by the client.",
	StatusInvalidAccountName:                                    "The name provided is not a properly formed account name.",
	StatusUserExists:                                            "The specified account already exists.",
	StatusNoSuchUser:                                            "The specified account does not exist.",
	StatusGroupExists:                                           "The specified group already exists.",
	StatusNoSuchGroup:                                           "The specified group does not exist.",
	StatusMemberInGroup:                                         "The specified user account is already in the specified group account. Also used to indicate a group cannot be deleted because it contains a member.",
	StatusMemberNotInGroup:                                      "The specified user account is not a member of the specified group account.",
	StatusLastAdmin:                                             "Indicates the requested operation would disable or delete the last remaining administration account. This is not allowed to prevent creating a situation in which the system cannot be administrated.",
	StatusWrongPassword:                                         "When trying to update a password, this return status indicates that the value provided as the current password is not correct.",
	StatusIllFormedPassword:                                     "When trying to update a password, this return status indicates that the value provided for the new password contains values that are not allowed in passwords.",
	StatusPasswordRestriction:                                   "When trying to update a password, this status indicates that some password update rule has been violated. For example, the password may not meet length criteria.",
	StatusLogonFailure:                                          "The attempted logon is invalid. This is either due to a bad username or authentication information.",
	StatusAccountRestriction:                                    "Indicates a referenced user name and authentication information are valid, but some user account restriction has prevented successful authentication (such as time-of-day restrictions).",
	StatusInvalidLogonHours:                                     "The user account has time restrictions and may not be logged onto at this time.",
	StatusInvalidWorkstation:                                    "The user account is restricted so that it may not be used to log on from the source workstation.",
	StatusPasswordExpired:                                       "The user account password has expired.",
	StatusAccountDisabled:                                       "The referenced account is currently disabled and may not be logged on to.",
	StatusNoneMapped:                                            "None of the information to be translated has been translated.",
	StatusTooManyLuidsRequested:                                 "The number of LUIDs requested may not be allocated with a single allocation.",
	StatusLuidsExhausted:                                        "Indicates there are no more LUIDs to allocate.",
	StatusInvalidSubAuthority:                                   "Indicates the sub-authority value is invalid for the particular use.",
	StatusInvalidAcl:                                            "Indicates the ACL structure is not valid.",
	StatusInvalidSid:                                            "Indicates the SID structure is not valid.",
	StatusInvalidSecurityDescr:                                  "Indicates the SECURITY_DESCRIPTOR structure is not valid.",
	StatusProcedureNotFound:                                     "Indicates the specified procedure address cannot be found in the DLL.",
	StatusInvalidImageFormat:                                    "{Bad Image} %hs is either not designed to run on Windows or it contains an error. Try installing the program again using the original installation media or contact your system administrator or the software vendor for support.",
	StatusNoToken:                                               "An attempt was made to reference a token that does not exist. This is typically done by referencing the token that is associated with a thread when the thread is not impersonating a client.",
	StatusBadInheritanceAcl:                                     "Indicates that an attempt to build either an inherited ACL or ACE was not successful. This can be caused by a number of things. One of the more probable causes is the replacement of a CreatorId with a SID that did not fit into the ACE or ACL.",
	StatusRangeNotLocked:                                        "The range specified in NtUnlockFile was not locked.",
	StatusDiskFull:                                              "An operation failed because the disk was full.",
	StatusServerDisabled:                                        "The GUID allocation server is disabled at the moment.",
	StatusServerNotDisabled:                                     "The GUID allocation server is enabled at the moment.",
	StatusTooManyGuidsRequested:                                 "Too many GUIDs were requested from the allocation server at once.",
	StatusGuidsExhausted:                                        "The GUIDs could not be allocated because the Authority Agent was exhausted.",
	StatusInvalidIdAuthority:                                    "The value provided was an invalid value for an identifier authority.",
	StatusAgentsExhausted:                                       "No more authority agent values are available for the particular identifier authority value.",
	StatusInvalidVolumeLabel:                                    "An invalid volume label has been specified.",
	StatusSectionNotExtended:                                    "A mapped section could not be extended.",
	StatusNotMappedData:                                         "Specified section to flush does not map a data file.",
	StatusResourceDataNotFound:                                  "Indicates the specified image file did not contain a resource section.",
	StatusResourceTypeNotFound:                                  "Indicates the specified resource type cannot be found in the image file.",
	StatusResourceNameNotFound:                                  "Indicates the specified resource name cannot be found in the image file.",
	StatusArrayBoundsExceeded:                                   "{EXCEPTION} Array bounds exceeded.",
	StatusFloatDenormalOperand:                                  "{EXCEPTION} Floating-point denormal operand.",
	StatusFloatDivideByZero:                                     "{EXCEPTION} Floating-point division by zero.",
	StatusFloatInexactResult:                                    "{EXCEPTION} Floating-point inexact result.",
	StatusFloatInvalidOperation:                                 "{EXCEPTION} Floating-point invalid operation.",
	StatusFloatOverflow:                                         "{EXCEPTION} Floating-point overflow.",
	StatusFloatStackCheck:                                       "{EXCEPTION} Floating-point stack check.",
	StatusFloatUnderflow:                                        "{EXCEPTION} Floating-point underflow.",
	StatusIntegerDivideByZero:                                   "{EXCEPTION} Integer division by zero.",
	StatusIntegerOverflow:                                       "{EXCEPTION} Integer overflow.",
	StatusPrivilegedInstruction:                                 "{EXCEPTION} Privileged instruction.",
	StatusTooManyPagingFiles:                                    "An attempt was made to install more paging files than the system supports.",
	StatusFileInvalid:                                           "The volume for a file has been externally altered such that the opened file is no longer valid.",
	StatusAllottedSpaceExceeded:                                 "When a block of memory is allotted for future updates, such as the memory allocated to hold discretionary access control and primary group information, successive updates may exceed the amount of memory originally allotted. Because a quota may already have been charged to several processes that have handles to the object, it is not reasonable to alter the size of the allocated memory. Instead, a request that requires more memory than has been allotted must fail and the STATUS_ALLOTTED_SPACE_EXCEEDED error returned.",
	StatusInsufficientResources:                                 "Insufficient system resources exist to complete the API.",
	StatusDfsExitPathFound:                                      "An attempt has been made to open a DFS exit path control file.",
	StatusDeviceDataError:                                       "There are bad blocks (sectors) on the hard disk.",
	StatusDeviceNotConnected:                                    "There is bad cabling, non-termination, or the controller is not able to obtain access to the hard disk.",
	StatusFreeVmNotAtBase:                                       "Virtual memory cannot be freed because the base address is not the base of the region and a region size of zero was specified.",
	StatusMemoryNotAllocated:                                    "An attempt was made to free virtual memory that is not allocated.",
	StatusWorkingSetQuota:                                       "The working set is not big enough to allow the requested pages to be locked.",
	StatusMediaWriteProtected:                                   "{Write Protect Error} The disk cannot be written to because it is write-protected. Remove the write protection from the volume %hs in drive %hs.",
	StatusDeviceNotReady:                                        "{Drive Not Ready} The drive is not ready for use; its door may be open. Check drive %hs and make sure that a disk is inserted and that the drive door is closed.",
	StatusInvalidGroupAttributes:                                "The specified attributes are invalid or are incompatible with the attributes for the group as a whole.",
	StatusBadImpersonationLevel:                                 "A specified impersonation level is invalid. Also used to indicate that a required impersonation level was not provided.",
	StatusCantOpenAnonymous:                                     "An attempt was made to open an anonymous-level token. Anonymous tokens may not be opened.",
	StatusBadValidationClass:                                    "The validation information class requested was invalid.",
	StatusBadTokenType:                                          "The type of a token object is inappropriate for its attempted use.",
	StatusBadMasterBootRecord:                                   "The type of a token object is inappropriate for its attempted use.",
	StatusInstructionMisalignment:                               "An attempt was made to execute an instruction at an unaligned address and the host system does not support unaligned instruction references.",
	StatusInstanceNotAvailable:                                  "The maximum named pipe instance count has been reached.",
	StatusPipeNotAvailable:                                      "An instance of a named pipe cannot be found in the listening state.",
	StatusInvalidPipeState:                                      "The named pipe is not in the connected or closing state.",
	StatusPipeBusy:                                              "The specified pipe is set to complete operations and there are current I/O operations queued so that it cannot be changed to queue operations.",
	StatusIllegalFunction:                                       "The specified handle is not open to the server end of the named pipe.",
	StatusPipeDisconnected:                                      "The specified named pipe is in the disconnected state.",
	StatusPipeClosing:                                           "The specified named pipe is in the closing state.",
	StatusPipeConnected:                                         "The specified named pipe is in the connected state.",
	StatusPipeListening:                                         "The specified named pipe is in the listening state.",
	StatusInvalidReadMode:                                       "The specified named pipe is not in message mode.",
	StatusIoTimeout:                                             "{Device Timeout} The specified I/O operation on %hs was not completed before the time-out period expired.",
	StatusFileForcedClosed:                                      "The specified file has been closed by another process.",
	StatusProfilingNotStarted:                                   "Profiling is not started.",
	StatusProfilingNotStopped:                                   "Profiling is not stopped.",
	StatusCouldNotInterpret:                                     "The passed ACL did not contain the minimum required information.",
	StatusFileIsADirectory:                                      "The file that was specified as a target is a directory, and the caller specified that it could be anything but a directory.",
	StatusNotSupported:                                          "The request is not supported.",
	StatusRemoteNotListening:                                    "This remote computer is not listening.",
	StatusDuplicateName:                                         "A duplicate name exists on the network.",
	StatusBadNetworkPath:                                        "The network path cannot be located.",
	StatusNetworkBusy:                                           "The network is busy.",
	StatusDeviceDoesNotExist:                                    "This device does not exist.",
	StatusTooManyCommands:                                       "The network BIOS command limit has been reached.",
	StatusAdapterHardwareError:                                  "An I/O adapter hardware error has occurred.",
	StatusInvalidNetworkResponse:                                "The network responded incorrectly.",
	StatusUnexpectedNetworkError:                                "An unexpected network error occurred.",
	StatusBadRemoteAdapter:                                      "The remote adapter is not compatible.",
	StatusPrintQueueFull:                                        "The print queue is full.",
	StatusNoSpoolSpace:                                          "Space to store the file that is waiting to be printed is not available on the server.",
	StatusPrintCancelled:                                        "The requested print file has been canceled.",
	StatusNetworkNameDeleted:                                    "The network name was deleted.",
	StatusNetworkAccessDenied:                                   "Network access is denied.",
	StatusBadDeviceType:                                         "{Incorrect Network Resource Type} The specified device type (LPT, for example) conflicts with the actual device type on the remote resource.",
	StatusBadNetworkName:                                        "{Network Name Not Found} The specified share name cannot be found on the remote server.",
	StatusTooManyNames:                                          "The name limit for the network adapter card of the local computer was exceeded.",
	StatusTooManySessions:                                       "The network BIOS session limit was exceeded.",
	StatusSharingPaused:                                         "File sharing has been temporarily paused.",
	StatusRequestNotAccepted:                                    "No more connections can be made to this remote computer at this time because the computer has already accepted the maximum number of connections.",
	StatusRedirectorPaused:                                      "Print or disk redirection is temporarily paused.",
	StatusNetWriteFault:                                         "A network data fault occurred.",
	StatusProfilingAtLimit:                                      "The number of active profiling objects is at the maximum and no more may be started.",
	StatusNotSameDevice:                                         "{Incorrect Volume} The destination file of a rename request is located on a different device than the source of the rename request.",
	StatusFileRenamed:                                           "The specified file has been renamed and thus cannot be modified.",
	StatusVirtualCircuitClosed:                                  "{Network Request Timeout} The session with a remote server has been disconnected because the time-out interval for a request has expired.",
	StatusNoSecurityOnObject:                                    "Indicates an attempt was made to operate on the security of an object that does not have security associated with it.",
	StatusCantWait:                                              "Used to indicate that an operation cannot continue without blocking for I/O.",
	StatusPipeEmpty:                                             "Used to indicate that a read operation was done on an empty pipe.",
	StatusCantAccessDomainInfo:                                  "Configuration information could not be read from the domain controller, either because the machine is unavailable or access has been denied.",
	StatusCantTerminateSelf:                                     "Indicates that a thread attempted to terminate itself by default (called NtTerminateThread with NULL) and it was the last thread in the current process.",
	StatusInvalidServerState:                                    "Indicates the Sam Server was in the wrong state to perform the desired operation.",
	StatusInvalidDomainState:                                    "Indicates the domain was in the wrong state to perform the desired operation.",
	StatusInvalidDomainRole:                                     "This operation is only allowed for the primary domain controller of the domain.",
	StatusNoSuchDomain:                                          "The specified domain did not exist.",
	StatusDomainExists:                                          "The specified domain already exists.",
	StatusDomainLimitExceeded:                                   "An attempt was made to exceed the limit on the number of domains per server for this release.",
	StatusOplockNotGranted:                                      "An error status returned when the opportunistic lock (oplock) request is denied.",
	StatusInvalidOplockProtocol:                                 "An error status returned when an invalid opportunistic lock (oplock) acknowledgment is received by a file system.",
	StatusInternalDbCorruption:                                  "This error indicates that the requested operation cannot be completed due to a catastrophic media failure or an on-disk data structure corruption.",
	StatusInternalError:                                         "An internal error occurred.",
	StatusGenericNotMapped:                                      "Indicates generic access types were contained in an access mask which should already be mapped to non-generic access types.",
	StatusBadDescriptorFormat:                                   "Indicates a security descriptor is not in the necessary format (absolute or self-relative).",
	StatusInvalidUserBuffer:                                     "An access to a user buffer failed at an expected point in time. This code is defined because the caller does not want to accept STATUS_ACCESS_VIOLATION in its filter.",
	StatusUnexpectedIoError:                                     "If an I/O error that is not defined in the standard FsRtl filter is returned, it is converted to the following error, which is guaranteed to be in the filter. In this case, information is lost; however, the filter correctly handles the exception.",
	StatusUnexpectedMmCreateErr:                                 "If an MM error that is not defined in the standard FsRtl filter is returned, it is converted to one of the following errors, which are guaranteed to be in the filter. In this case, information is lost; however, the filter correctly handles the exception.",
	StatusUnexpectedMmMapError:                                  "If an MM error that is not defined in the standard FsRtl filter is returned, it is converted to one of the following errors, which are guaranteed to be in the filter. In this case, information is lost; however, the filter correctly handles the exception.",
	StatusUnexpectedMmExtendErr:                                 "If an MM error that is not defined in the standard FsRtl filter is returned, it is converted to one of the following errors, which are guaranteed to be in the filter. In this case, information is lost; however, the filter correctly handles the exception.",
	StatusNotLogonProcess:                                       "The requested action is restricted for use by logon processes only. The calling process has not registered as a logon process.",
	StatusLogonSessionExists:                                    "An attempt has been made to start a new session manager or LSA logon session by using an ID that is already in use.",
	StatusInvalidParameter1:                                     "An invalid parameter was passed to a service or function as the first argument.",
	StatusInvalidParameter2:                                     "An invalid parameter was passed to a service or function as the second argument.",
	StatusInvalidParameter3:                                     "An invalid parameter was passed to a service or function as the third argument.",
	StatusInvalidParameter4:                                     "An invalid parameter was passed to a service or function as the fourth argument.",
	StatusInvalidParameter5:                                     "An invalid parameter was passed to a service or function as the fifth argument.",
	StatusInvalidParameter6:                                     "An invalid parameter was passed to a service or function as the sixth argument.",
	StatusInvalidParameter7:                                     "An invalid parameter was passed to a service or function as the seventh argument.",
	StatusInvalidParameter8:                                     "An invalid parameter was passed to a service or function as the eighth argument.",
	StatusInvalidParameter9:                                     "An invalid parameter was passed to a service or function as the ninth argument.",
	StatusInvalidParameter10:                                    "An invalid parameter was passed to a service or function as the tenth argument.",
	StatusInvalidParameter11:                                    "An invalid parameter was passed to a service or function as the eleventh argument.",
	StatusInvalidParameter12:                                    "An invalid parameter was passed to a service or function as the twelfth argument.",
	StatusRedirectorNotStarted:                                  "An attempt was made to access a network file, but the network software was not yet started.",
	StatusRedirectorStarted:                                     "An attempt was made to start the redirector, but the redirector has already been started.",
	StatusStackOverflow:                                         "A new guard page for the stack cannot be created.",
	StatusNoSuchPackage:                                         "A specified authentication package is unknown.",
	StatusBadFunctionTable:                                      "A malformed function table was encountered during an unwind operation.",
	StatusVariableNotFound:                                      "Indicates the specified environment variable name was not found in the specified environment block.",
	StatusDirectoryNotEmpty:                                     "Indicates that the directory trying to be deleted is not empty.",
	StatusFileCorruptError:                                      "{Corrupt File} The file or directory %hs is corrupt and unreadable. Run the Chkdsk utility.",
	StatusNotADirectory:                                         "A requested opened file is not a directory.",
	StatusBadLogonSessionState:                                  "The logon session is not in a state that is consistent with the requested operation.",
	StatusLogonSessionCollision:                                 "An internal LSA error has occurred. An authentication package has requested the creation of a logon session but the ID of an already existing logon session has been specified.",
	StatusNameTooLong:                                           "A specified name string is too long for its intended use.",
	StatusFilesOpen:                                             "The user attempted to force close the files on a redirected drive, but there were opened files on the drive, and the user did not specify a sufficient level of force.",
	StatusConnectionInUse:                                       "The user attempted to force close the files on a redirected drive, but there were opened directories on the drive, and the user did not specify a sufficient level of force.",
	StatusMessageNotFound:                                       "RtlFindMessage could not locate the requested message ID in the message table resource.",
	StatusProcessIsTerminating:                                  "An attempt was made to duplicate an object handle into or out of an exiting process.",
	StatusInvalidLogonType:                                      "Indicates an invalid value has been provided for the LogonType requested.",
	StatusNoGuidTranslation:                                     "Indicates that an attempt was made to assign protection to a file system file or directory and one of the SIDs in the security descriptor could not be translated into a GUID that could be stored by the file system. This causes the protection attempt to fail, which may cause a file creation attempt to fail.",
	StatusCannotImpersonate:                                     "Indicates that an attempt has been made to impersonate via a named pipe that has not yet been read from.",
	StatusImageAlreadyLoaded:                                    "Indicates that the specified image is already loaded.",
	StatusNoLdt:                                                 "Indicates that an attempt was made to change the size of the LDT for a process that has no LDT.",
	StatusInvalidLdtSize:                                        "Indicates that an attempt was made to grow an LDT by setting its size, or that the size was not an even number of selectors.",
	StatusInvalidLdtOffset:                                      "Indicates that the starting value for the LDT information was not an integral multiple of the selector size.",
	StatusInvalidLdtDescriptor:                                  "Indicates that the user supplied an invalid descriptor when trying to set up LDT descriptors.",
	StatusInvalidImageNeFormat:                                  "The specified image file did not have the correct format. It appears to be NE format.",
	StatusRxactInvalidState:                                     "Indicates that the transaction state of a registry subtree is incompatible with the requested operation. For example, a request has been made to start a new transaction with one already in progress, or a request has been made to apply a transaction when one is not currently in progress.",
	StatusRxactCommitFailure:                                    "Indicates an error has occurred during a registry transaction commit. The database has been left in an unknown, but probably inconsistent, state. The state of the registry transaction is left as COMMITTING.",
	StatusMappedFileSizeZero:                                    "An attempt was made to map a file of size zero with the maximum size specified as zero.",
	StatusTooManyOpenedFiles:                                    "Too many files are opened on a remote server. This error should only be returned by the Windows redirector on a remote drive.",
	StatusCancelled:                                             "The I/O request was canceled.",
	StatusCannotDelete:                                          "An attempt has been made to remove a file or directory that cannot be deleted.",
	StatusInvalidComputerName:                                   "Indicates a name that was specified as a remote computer name is syntactically invalid.",
	StatusFileDeleted:                                           "An I/O request other than close was performed on a file after it was deleted, which can only happen to a request that did not complete before the last handle was closed via NtClose.",
	StatusSpecialAccount:                                        "Indicates an operation that is incompatible with built-in accounts has been attempted on a built-in (special) SAM account. For example, built-in accounts cannot be deleted.",
	StatusSpecialGroup:                                          "The operation requested may not be performed on the specified group because it is a built-in special group.",
	StatusSpecialUser:                                           "The operation requested may not be performed on the specified user because it is a built-in special user.",
	StatusMembersPrimaryGroup:                                   "Indicates a member cannot be removed from a group because the group is currently the member's primary group.",
	StatusFileClosed:                                            "An I/O request other than close and several other special case operations was attempted using a file object that had already been closed.",
	StatusTooManyThreads:                                        "Indicates a process has too many threads to perform the requested action. For example, assignment of a primary token may only be performed when a process has zero or one threads.",
	StatusThreadNotInProcess:                                    "An attempt was made to operate on a thread within a specific process, but the specified thread is not in the specified process.",
	StatusTokenAlreadyInUse:                                     "An attempt was made to establish a token for use as a primary token but the token is already in use. A token can only be the primary token of one process at a time.",
	StatusPagefileQuotaExceeded:                                 "The page file quota was exceeded.",
	StatusCommitmentLimit:                                       "{Out of Virtual Memory} Your system is low on virtual memory. To ensure that Windows runs correctly, increase the size of your virtual memory paging file. For more information, see Help.",
	StatusInvalidImageLeFormat:                                  "The specified image file did not have the correct format: it appears to be LE format.",
	StatusInvalidImageNotMz:                                     "The specified image file did not have the correct format: it did not have an initial MZ.",
	StatusInvalidImageProtect:                                   "The specified image file did not have the correct format: it did not have a proper e_lfarlc in the MZ header.",
	StatusInvalidImageWin16:                                     "The specified image file did not have the correct format: it appears to be a 16-bit Windows image.",
	StatusLogonServerConflict:                                   "The Netlogon service cannot start because another Netlogon service running in the domain conflicts with the specified role.",
	StatusTimeDifferenceAtDc:                                    "The time at the primary domain controller is different from the time at the backup domain controller or member server by too large an amount.",
	StatusSynchronizationRequired:                               "The SAM database on a Windows Server operating system is significantly out of synchronization with the copy on the domain controller. A complete synchronization is required.",
	StatusDllNotFound:                                           "{Unable To Locate Component} This application has failed to start because %hs was not found. Reinstalling the application may fix this problem.",
	StatusOpenFailed:                                            "The NtCreateFile API failed. This error should never be returned to an application; it is a place holder for the Windows LAN Manager Redirector to use in its internal error-mapping routines.",
	StatusIoPrivilegeFailed:                                     "{Privilege Failed} The I/O permissions for the process could not be changed.",
	StatusOrdinalNotFound:                                       "{Ordinal Not Found} The ordinal %ld could not be located in the dynamic link library %hs.",
	StatusEntrypointNotFound:                                    "{Entry Point Not Found} The procedure entry point %hs could not be located in the dynamic link library %hs.",
	StatusControlCExit:                                          "{Application Exit by CTRL+C} The application terminated as a result of a CTRL+C.",
	StatusLocalDisconnect:                                       "{Virtual Circuit Closed} The network transport on your computer has closed a network connection. There may or may not be I/O requests outstanding.",
	StatusRemoteDisconnect:                                      "{Virtual Circuit Closed} The network transport on a remote computer has closed a network connection. There may or may not be I/O requests outstanding.",
	StatusRemoteResources:                                       "{Insufficient Resources on Remote Computer} The remote computer has insufficient resources to complete the network request. For example, the remote computer may not have enough available memory to carry out the request at this time.",
	StatusLinkFailed:                                            "{Virtual Circuit Closed} An existing connection (virtual circuit) has been broken at the remote computer. There is probably something wrong with the network software protocol or the network hardware on the remote computer.",
	StatusLinkTimeout:                                           "{Virtual Circuit Closed} The network transport on your computer has closed a network connection because it had to wait too long for a response from the remote computer.",
	StatusInvalidConnection:                                     "The connection handle that was given to the transport was invalid.",
	StatusInvalidAddress:                                        "The address handle that was given to the transport was invalid.",
	StatusDllInitFailed:                                         "{DLL Initialization Failed} Initialization of the dynamic link library %hs failed. The process is terminating abnormally.",
	StatusMissingSystemfile:                                     "{Missing System File} The required system file %hs is bad or missing.",
	StatusUnhandledException:                                    "{Application Error} The exception %s (0x%08lx) occurred in the application at location 0x%08lx.",
	StatusAppInitFailure:                                        "{Application Error} The application failed to initialize properly (0x%lx). Click OK to terminate the application.",
	StatusPagefileCreateFailed:                                  "{Unable to Create Paging File} The creation of the paging file %hs failed (%lx). The requested size was %ld.",
	StatusNoPagefile:                                            "{No Paging File Specified} No paging file was specified in the system configuration.",
	StatusInvalidLevel:                                          "{Incorrect System Call Level} An invalid level was passed into the specified system call.",
	StatusWrongPasswordCore:                                     "{Incorrect Password to LAN Manager Server} You specified an incorrect password to a LAN Manager 2.x or MS-NET server.",
	StatusIllegalFloatContext:                                   "{EXCEPTION} A real-mode application issued a floating-point instruction and floating-point hardware is not present.",
	StatusPipeBroken:                                            "The pipe operation has failed because the other end of the pipe has been closed.",
	StatusRegistryCorrupt:                                       "{The Registry Is Corrupt} The structure of one of the files that contains registry data is corrupt; the image of the file in memory is corrupt; or the file could not be recovered because the alternate copy or log was absent or corrupt.",
	StatusRegistryIoFailed:                                      "An I/O operation initiated by the Registry failed and cannot be recovered. The registry could not read in, write out, or flush one of the files that contain the system's image of the registry.",
	StatusNoEventPair:                                           "An event pair synchronization operation was performed using the thread-specific client/server event pair object, but no event pair object was associated with the thread.",
	StatusUnrecognizedVolume:                                    "The volume does not contain a recognized file system. Be sure that all required file system drivers are loaded and that the volume is not corrupt.",
	StatusSerialNoDeviceInited:                                  "No serial device was successfully initialized. The serial driver will unload.",
	StatusNoSuchAlias:                                           "The specified local group does not exist.",
	StatusMemberNotInAlias:                                      "The specified account name is not a member of the group.",
	StatusMemberInAlias:                                         "The specified account name is already a member of the group.",
	StatusAliasExists:                                           "The specified local group already exists.",
	StatusLogonNotGranted:                                       "A requested type of logon (for example, interactive, network, and service) is not granted by the local security policy of the target system. Ask the system administrator to grant the necessary form of logon.",
	StatusTooManySecrets:                                        "The maximum number of secrets that may be stored in a single system was exceeded. The length and number of secrets is limited to satisfy U.S. State Department export restrictions.",
	StatusSecretTooLong:                                         "The length of a secret exceeds the maximum allowable length. The length and number of secrets is limited to satisfy U.S. State Department export restrictions.",
	StatusInternalDbError:                                       "The local security authority (LSA) database contains an internal inconsistency.",
	StatusFullscreenMode:                                        "The requested operation cannot be performed in full-screen mode.",
	StatusTooManyContextIds:                                     "During a logon attempt, the user's security context accumulated too many security IDs. This is a very unusual situation. Remove the user from some global or local groups to reduce the number of security IDs to incorporate into the security context.",
	StatusLogonTypeNotGranted:                                   "A user has requested a type of logon (for example, interactive or network) that has not been granted. An administrator has control over who may logon interactively and through the network.",
	StatusNotRegistryFile:                                       "The system has attempted to load or restore a file into the registry, and the specified file is not in the format of a registry file.",
	StatusNtCrossEncryptionRequired:                             "An attempt was made to change a user password in the security account manager without providing the necessary Windows cross-encrypted password.",
	StatusDomainCtrlrConfigError:                                "A Windows Server has an incorrect configuration.",
	StatusFtMissingMember:                                       "An attempt was made to explicitly access the secondary copy of information via a device control to the fault tolerance driver and the secondary copy is not present in the system.",
	StatusIllFormedServiceEntry:                                 "A configuration registry node that represents a driver service entry was ill-formed and did not contain the required value entries.",
	StatusIllegalCharacter:                                      "An illegal character was encountered. For a multibyte character set, this includes a lead byte without a succeeding trail byte. For the Unicode character set this includes the characters 0xFFFF and 0xFFFE.",
	StatusUnmappableCharacter:                                   "No mapping for the Unicode character exists in the target multibyte code page.",
	StatusUndefinedCharacter:                                    "The Unicode character is not defined in the Unicode character set that is installed on the system.",
	StatusFloppyVolume:                                          "The paging file cannot be created on a floppy disk.",
	StatusFloppyIdMarkNotFound:                                  "{Floppy Disk Error} While accessing a floppy disk, an ID address mark was not found.",
	StatusFloppyWrongCylinder:                                   "{Floppy Disk Error} While accessing a floppy disk, the track address from the sector ID field was found to be different from the track address that is maintained by the controller.",
	StatusFloppyUnknownError:                                    "{Floppy Disk Error} The floppy disk controller reported an error that is not recognized by the floppy disk driver.",
	StatusFloppyBadRegisters:                                    "{Floppy Disk Error} While accessing a floppy-disk, the controller returned inconsistent results via its registers.",
	StatusDiskRecalibrateFailed:                                 "{Hard Disk Error} While accessing the hard disk, a recalibrate operation failed, even after retries.",
	StatusDiskOperationFailed:                                   "{Hard Disk Error} While accessing the hard disk, a disk operation failed even after retries.",
	StatusDiskResetFailed:                                       "{Hard Disk Error} While accessing the hard disk, a disk controller reset was needed, but even that failed.",
	StatusSharedIrqBusy:                                         "An attempt was made to open a device that was sharing an interrupt request (IRQ) with other devices. At least one other device that uses that IRQ was already opened. Two concurrent opens of devices that share an IRQ and only work via interrupts is not supported for the particular bus type that the devices use.",
	StatusFtOrphaning:                                           "{FT Orphaning} A disk that is part of a fault-tolerant volume can no longer be accessed.",
	StatusBiosFailedToConnectInterrupt:                          "The basic input/output system (BIOS) failed to connect a system interrupt to the device or bus for which the device is connected.",
	StatusPartitionFailure:                                      "The tape could not be partitioned.",
	StatusInvalidBlockLength:                                    "When accessing a new tape of a multi-volume partition, the current blocksize is incorrect.",
	StatusDeviceNotPartitioned:                                  "The tape partition information could not be found when loading a tape.",
	StatusUnableToLockMedia:                                     "An attempt to lock the eject media mechanism failed.",
	StatusUnableToUnloadMedia:                                   "An attempt to unload media failed.",
	StatusEomOverflow:                                           "The physical end of tape was detected.",
	StatusNoMedia:                                               "{No Media} There is no media in the drive. Insert media into drive %hs.",
	StatusNoSuchMember:                                          "A member could not be added to or removed from the local group because the member does not exist.",
	StatusInvalidMember:                                         "A new member could not be added to a local group because the member has the wrong account type.",
	StatusKeyDeleted:                                            "An illegal operation was attempted on a registry key that has been marked for deletion.",
	StatusNoLogSpace:                                            "The system could not allocate the required space in a registry log.",
	StatusTooManySids:                                           "Too many SIDs have been specified.",
	StatusLmCrossEncryptionRequired:                             "An attempt was made to change a user password in the security account manager without providing the necessary LM cross-encrypted password.",
	StatusKeyHasChildren:                                        "An attempt was made to create a symbolic link in a registry key that already has subkeys or values.",
	StatusChildMustBeVolatile:                                   "An attempt was made to create a stable subkey under a volatile parent key.",
	StatusDeviceConfigurationError:                              "The I/O device is configured incorrectly or the configuration parameters to the driver are incorrect.",
	StatusDriverInternalError:                                   "An error was detected between two drivers or within an I/O driver.",
	StatusInvalidDeviceState:                                    "The device is not in a valid state to perform this request.",
	StatusIoDeviceError:                                         "The I/O device reported an I/O error.",
	StatusDeviceProtocolError:                                   "A protocol error was detected between the driver and the device.",
	StatusBackupController:                                      "This operation is only allowed for the primary domain controller of the domain.",
	StatusLogFileFull:                                           "The log file space is insufficient to support this operation.",
	StatusTooLate:                                               "A write operation was attempted to a volume after it was dismounted.",
	StatusNoTrustLsaSecret:                                      "The workstation does not have a trust secret for the primary domain in the local LSA database.",
	StatusNoTrustSamAccount:                                     "The SAM database on the Windows Server does not have a computer account for this workstation trust relationship.",
	StatusTrustedDomainFailure:                                  "The logon request failed because the trust relationship between the primary domain and the trusted domain failed.",
	StatusTrustedRelationshipFailure:                            "The logon request failed because the trust relationship between this workstation and the primary domain failed.",
	StatusEventlogFileCorrupt:                                   "The Eventlog log file is corrupt.",
	StatusEventlogCantStart:                                     "No Eventlog log file could be opened. The Eventlog service did not start.",
	StatusTrustFailure:                                          "The network logon failed. This may be because the validation authority cannot be reached.",
	StatusMutantLimitExceeded:                                   "An attempt was made to acquire a mutant such that its maximum count would have been exceeded.",
	StatusNetlogonNotStarted:                                    "An attempt was made to logon, but the NetLogon service was not started.",
	StatusAccountExpired:                                        "The user account has expired.",
	StatusPossibleDeadlock:                                      "{EXCEPTION} Possible deadlock condition.",
	StatusNetworkCredentialConflict:                             "Multiple connections to a server or shared resource by the same user, using more than one user name, are not allowed. Disconnect all previous connections to the server or shared resource and try again.",
	StatusRemoteSessionLimit:                                    "An attempt was made to establish a session to a network server, but there are already too many sessions established to that server.",
	StatusEventlogFileChanged:                                   "The log file has changed between reads.",
	StatusNologonInterdomainTrustAccount:                        "The account used is an interdomain trust account. Use your global user account or local user account to access this server.",
	StatusNologonWorkstationTrustAccount:                        "The account used is a computer account. Use your global user account or local user account to access this server.",
	StatusNologonServerTrustAccount:                             "The account used is a server trust account. Use your global user account or local user account to access this server.",
	StatusDomainTrustInconsistent:                               "The name or SID of the specified domain is inconsistent with the trust information for that domain.",
	StatusFsDriverRequired:                                      "A volume has been accessed for which a file system driver is required that has not yet been loaded.",
	StatusImageAlreadyLoadedAsDll:                               "Indicates that the specified image is already loaded as a DLL.",
	StatusIncompatibleWithGlobalShortNameRegistrySetting:        "Short name settings may not be changed on this volume due to the global registry setting.",
	StatusShortNamesNotEnabledOnVolume:                          "Short names are not enabled on this volume.",
	StatusSecurityStreamIsInconsistent:                          "The security stream for the given volume is in an inconsistent state. Please run CHKDSK on the volume.",
	StatusInvalidLockRange:                                      "A requested file lock operation cannot be processed due to an invalid byte range.",
	StatusInvalidAceCondition:                                   "The specified access control entry (ACE) contains an invalid condition.",
	StatusImageSubsystemNotPresent:                              "The subsystem needed to support the image type is not present.",
	StatusNotificationGuidAlreadyDefined:                        "The specified file already has a notification GUID associated with it.",
	StatusNetworkOpenRestriction:                                "A remote open failed because the network open restrictions were not satisfied.",
	StatusNoUserSessionKey:                                      "There is no user session key for the specified logon session.",
	StatusUserSessionDeleted:                                    "The remote user session has been deleted.",
	StatusResourceLangNotFound:                                  "Indicates the specified resource language ID cannot be found in the image file.",
	StatusInsuffServerResources:                                 "Insufficient server resources exist to complete the request.",
	StatusInvalidBufferSize:                                     "The size of the buffer is invalid for the specified operation.",
	StatusInvalidAddressComponent:                               "The transport rejected the specified network address as invalid.",
	StatusInvalidAddressWildcard:                                "The transport rejected the specified network address due to invalid use of a wildcard.",
	StatusTooManyAddresses:                                      "The transport address could not be opened because all the available addresses are in use.",
	StatusAddressAlreadyExists:                                  "The transport address could not be opened because it already exists.",
	StatusAddressClosed:                                         "The transport address is now closed.",
	StatusConnectionDisconnected:                                "The transport connection is now disconnected.",
	StatusConnectionReset:                                       "The transport connection has been reset.",
	StatusTooManyNodes:                                          "The transport cannot dynamically acquire any more nodes.",
	StatusTransactionAborted:                                    "The transport aborted a pending transaction.",
	StatusTransactionTimedOut:                                   "The transport timed out a request that is waiting for a response.",
	StatusTransactionNoRelease:                                  "The transport did not receive a release for a pending response.",
	StatusTransactionNoMatch:                                    "The transport did not find a transaction that matches the specific token.",
	StatusTransactionResponded:                                  "The transport had previously responded to a transaction request.",
	StatusTransactionInvalidId:                                  "The transport does not recognize the specified transaction request ID.",
	StatusTransactionInvalidType:                                "The transport does not recognize the specified transaction request type.",
	StatusNotServerSession:                                      "The transport can only process the specified request on the server side of a session.",
	StatusNotClientSession:                                      "The transport can only process the specified request on the client side of a session.",
	StatusCannotLoadRegistryFile:                                "{Registry File Failure} The registry cannot load the hive (file): %hs or its log or alternate. It is corrupt, absent, or not writable.",
	StatusDebugAttachFailed:                                     "{Unexpected Failure in DebugActiveProcess} An unexpected failure occurred while processing a DebugActiveProcess API request. You may choose OK to terminate the process, or Cancel to ignore the error.",
	StatusSystemProcessTerminated:                               "{Fatal System Error} The %hs system process terminated unexpectedly with a status of 0x%08x (0x%08x 0x%08x). The system has been shut down.",
	StatusDataNotAccepted:                                       "{Data Not Accepted} The TDI client could not handle the data received during an indication.",
	StatusNoBrowserServersFound:                                 "{Unable to Retrieve Browser Server List} The list of servers for this workgroup is not currently available.",
	StatusVdmHardError:                                          "NTVDM encountered a hard error.",
	StatusDriverCancelTimeout:                                   "{Cancel Timeout} The driver %hs failed to complete a canceled I/O request in the allotted time.",
	StatusReplyMessageMismatch:                                  "{Reply Message Mismatch} An attempt was made to reply to an LPC message, but the thread specified by the client ID in the message was not waiting on that message.",
	StatusMappedAlignment:                                       "{Mapped View Alignment Incorrect} An attempt was made to map a view of a file, but either the specified base address or the offset into the file were not aligned on the proper allocation granularity.",
	StatusImageChecksumMismatch:                                 "{Bad Image Checksum} The image %hs is possibly corrupt. The header checksum does not match the computed checksum.",
	StatusLostWritebehindData:                                   "{Delayed Write Failed} Windows was unable to save all the data for the file %hs. The data has been lost. This error may be caused by a failure of your computer hardware or network connection. Try to save this file elsewhere.",
	StatusClientServerParametersInvalid:                         "The parameters passed to the server in the client/server shared memory window were invalid. Too much data may have been put in the shared memory window.",
	StatusPasswordMustChange:                                    "The user password must be changed before logging on the first time.",
	StatusNotFound:                                              "The object was not found.",
	StatusNotTinyStream:                                         "The stream is not a tiny stream.",
	StatusRecoveryFailure:                                       "A transaction recovery failed.",
	StatusStackOverflowRead:                                     "The request must be handled by the stack overflow code.",
	StatusFailCheck:                                             "A consistency check failed.",
	StatusDuplicateObjectid:                                     "The attempt to insert the ID in the index failed because the ID is already in the index.",
	StatusObjectidExists:                                        "The attempt to set the object ID failed because the object already has an ID.",
	StatusConvertToLarge:                                        "Internal OFS status codes indicating how an allocation operation is handled. Either it is retried after the containing oNode is moved or the extent stream is converted to a large stream.",
	StatusRetry:                                                 "The request needs to be retried.",
	StatusFoundOutOfScope:                                       "The attempt to find the object found an object on the volume that matches by ID; however, it is out of the scope of the handle that is used for the operation.",
	StatusAllocateBucket:                                        "The bucket array must be grown. Retry the transaction after doing so.",
	StatusPropsetNotFound:                                       "The specified property set does not exist on the object.",
	StatusMarshallOverflow:                                      "The user/kernel marshaling buffer has overflowed.",
	StatusInvalidVariant:                                        "The supplied variant structure contains invalid data.",
	StatusDomainControllerNotFound:                              "A domain controller for this domain was not found.",
	StatusAccountLockedOut:                                      "The user account has been automatically locked because too many invalid logon attempts or password change attempts have been requested.",
	StatusHandleNotClosable:                                     "NtClose was called on a handle that was protected from close via NtSetInformationObject.",
	StatusConnectionRefused:                                     "The transport-connection attempt was refused by the remote system.",
	StatusGracefulDisconnect:                                    "The transport connection was gracefully closed.",
	StatusAddressAlreadyAssociated:                              "The transport endpoint already has an address associated with it.",
	StatusAddressNotAssociated:                                  "An address has not yet been associated with the transport endpoint.",
	StatusConnectionInvalid:                                     "An operation was attempted on a nonexistent transport connection.",
	StatusConnectionActive:                                      "An invalid operation was attempted on an active transport connection.",
	StatusNetworkUnreachable:                                    "The remote network is not reachable by the transport.",
	StatusHostUnreachable:                                       "The remote system is not reachable by the transport.",
	StatusProtocolUnreachable:                                   "The remote system does not support the transport protocol.",
	StatusPortUnreachable:                                       "No service is operating at the destination port of the transport on the remote system.",
	StatusRequestAborted:                                        "The request was aborted.",
	StatusConnectionAborted:                                     "The transport connection was aborted by the local system.",
	StatusBadCompressionBuffer:                                  "The specified buffer contains ill-formed data.",
	StatusUserMappedFile:                                        "The requested operation cannot be performed on a file with a user mapped section open.",
	StatusAuditFailed:                                           "{Audit Failed} An attempt to generate a security audit failed.",
	StatusTimerResolutionNotSet:                                 "The timer resolution was not previously set by the current process.",
	StatusConnectionCountLimit:                                  "A connection to the server could not be made because the limit on the number of concurrent connections for this account has been reached.",
	StatusLoginTimeRestriction:                                  "Attempting to log on during an unauthorized time of day for this account.",
	StatusLoginWkstaRestriction:                                 "The account is not authorized to log on from this station.",
	StatusImageMpUpMismatch:                                     "{UP/MP Image Mismatch} The image %hs has been modified for use on a uniprocessor system, but you are running it on a multiprocessor machine. Reinstall the image file.",
	StatusInsufficientLogonInfo:                                 "There is insufficient account information to log you on.",
	StatusBadDllEntrypoint:                                      "{Invalid DLL Entrypoint} The dynamic link library %hs is not written correctly. The stack pointer has been left in an inconsistent state. The entry point should be declared as WINAPI or STDCALL. Select YES to fail the DLL load. Select NO to continue execution. Selecting NO may cause the application to operate incorrectly.",
	StatusBadServiceEntrypoint:                                  "{Invalid Service Callback Entrypoint} The %hs service is not written correctly. The stack pointer has been left in an inconsistent state. The callback entry point should be declared as WINAPI or STDCALL. Selecting OK will cause the service to continue operation. However, the service process may operate incorrectly.",
	StatusLpcReplyLost:                                          "The server received the messages but did not send a reply.",
	StatusIpAddressConflict1:                                    "There is an IP address conflict with another system on the network.",
	StatusIpAddressConflict2:                                    "There is an IP address conflict with another system on the network.",
	StatusRegistryQuotaLimit:                                    "{Low On Registry Space} The system has reached the maximum size that is allowed for the system part of the registry. Additional storage requests will be ignored.",
	StatusPathNotCovered:                                        "The contacted server does not support the indicated part of the DFS namespace.",
	StatusNoCallbackActive:                                      "A callback return system service cannot be executed when no callback is active.",
	StatusLicenseQuotaExceeded:                                  "The service being accessed is licensed for a particular number of connections. No more connections can be made to the service at this time because the service has already accepted the maximum number of connections.",
	StatusPwdTooShort:                                           "The password provided is too short to meet the policy of your user account. Choose a longer password.",
	StatusPwdTooRecent:                                          "The policy of your user account does not allow you to change passwords too frequently. This is done to prevent users from changing back to a familiar, but potentially discovered, password. If you feel your password has been compromised, contact your administrator immediately to have a new one assigned.",
	StatusPwdHistoryConflict:                                    "You have attempted to change your password to one that you have used in the past. The policy of your user account does not allow this. Select a password that you have not previously used.",
	StatusPlugplayNoDevice:                                      "You have attempted to load a legacy device driver while its device instance had been disabled.",
	StatusUnsupportedCompression:                                "The specified compression format is unsupported.",
	StatusInvalidHwProfile:                                      "The specified hardware profile configuration is invalid.",
	StatusInvalidPlugplayDevicePath:                             "The specified Plug and Play registry device path is invalid.",
	StatusDriverOrdinalNotFound:                                 "{Driver Entry Point Not Found} The %hs device driver could not locate the ordinal %ld in driver %hs.",
	StatusDriverEntrypointNotFound:                              "{Driver Entry Point Not Found} The %hs device driver could not locate the entry point %hs in driver %hs.",
	StatusResourceNotOwned:                                      "{Application Error} The application attempted to release a resource it did not own. Click OK to terminate the application.",
	StatusTooManyLinks:                                          "An attempt was made to create more links on a file than the file system supports.",
	StatusQuotaListInconsistent:                                 "The specified quota list is internally inconsistent with its descriptor.",
	StatusFileIsOffline:                                         "The specified file has been relocated to offline storage.",
	StatusEvaluationExpiration:                                  "{Windows Evaluation Notification} The evaluation period for this installation of Windows has expired. This system will shutdown in 1 hour. To restore access to this installation of Windows, upgrade this installation by using a licensed distribution of this product.",
	StatusIllegalDllRelocation:                                  "{Illegal System DLL Relocation} The system DLL %hs was relocated in memory. The application will not run properly. The relocation occurred because the DLL %hs occupied an address range that is reserved for Windows system DLLs. The vendor supplying the DLL should be contacted for a new DLL.",
	StatusLicenseViolation:                                      "{License Violation} The system has detected tampering with your registered product type. This is a violation of your software license. Tampering with the product type is not permitted.",
	StatusDllInitFailedLogoff:                                   "{DLL Initialization Failed} The application failed to initialize because the window station is shutting down.",
	StatusDriverUnableToLoad:                                    "{Unable to Load Device Driver} %hs device driver could not be loaded. Error Status was 0x%x.",
	StatusDfsUnavailable:                                        "DFS is unavailable on the contacted server.",
	StatusVolumeDismounted:                                      "An operation was attempted to a volume after it was dismounted.",
	StatusWx86InternalError:                                     "An internal error occurred in the Win32 x86 emulation subsystem.",
	StatusWx86FloatStackCheck:                                   "Win32 x86 emulation subsystem floating-point stack check.",
	StatusValidateContinue:                                      "The validation process needs to continue on to the next step.",
	StatusNoMatch:                                               "There was no match for the specified key in the index.",
	StatusNoMoreMatches:                                         "There are no more matches for the current index enumeration.",
	StatusNotAReparsePoint:                                      "The NTFS file or directory is not a reparse point.",
	StatusIoReparseTagInvalid:                                   "The Windows I/O reparse tag passed for the NTFS reparse point is invalid.",
	StatusIoReparseTagMismatch:                                  "The Windows I/O reparse tag does not match the one that is in the NTFS reparse point.",
	StatusIoReparseDataInvalid:                                  "The user data passed for the NTFS reparse point is invalid.",
	StatusIoReparseTagNotHandled:                                "The layered file system driver for this I/O tag did not handle it when needed.",
	StatusReparsePointNotResolved:                               "The NTFS symbolic link could not be resolved even though the initial file name is valid.",
	StatusDirectoryIsAReparsePoint:                              "The NTFS directory is a reparse point.",
	StatusRangeListConflict:                                     "The range could not be added to the range list because of a conflict.",
	StatusSourceElementEmpty:                                    "The specified medium changer source element contains no media.",
	StatusDestinationElementFull:                                "The specified medium changer destination element already contains media.",
	StatusIllegalElementAddress:                                 "The specified medium changer element does not exist.",
	StatusMagazineNotPresent:                                    "The specified element is contained in a magazine that is no longer present.",
	StatusReinitializationNeeded:                                "The device requires re-initialization due to hardware errors.",
	StatusEncryptionFailed:                                      "The file encryption attempt failed.",
	StatusDecryptionFailed:                                      "The file decryption attempt failed.",
	StatusRangeNotFound:                                         "The specified range could not be found in the range list.",
	StatusNoRecoveryPolicy:                                      "There is no encryption recovery policy configured for this system.",
	StatusNoEfs:                                                 "The required encryption driver is not loaded for this system.",
	StatusWrongEfs:                                              "The file was encrypted with a different encryption driver than is currently loaded.",
	StatusNoUserKeys:                                            "There are no EFS keys defined for the user.",
	StatusFileNotEncrypted:                                      "The specified file is not encrypted.",
	StatusNotExportFormat:                                       "The specified file is not in the defined EFS export format.",
	StatusFileEncrypted:                                         "The specified file is encrypted and the user does not have the ability to decrypt it.",
	StatusWmiGuidNotFound:                                       "The GUID passed was not recognized as valid by a WMI data provider.",
	StatusWmiInstanceNotFound:                                   "The instance name passed was not recognized as valid by a WMI data provider.",
	StatusWmiItemidNotFound:                                     "The data item ID passed was not recognized as valid by a WMI data provider.",
	StatusWmiTryAgain:                                           "The WMI request could not be completed and should be retried.",
	StatusSharedPolicy:                                          "The policy object is shared and can only be modified at the root.",
	StatusPolicyObjectNotFound:                                  "The policy object does not exist when it should.",
	StatusPolicyOnlyInDs:                                        "The requested policy information only lives in the Ds.",
	StatusVolumeNotUpgraded:                                     "The volume must be upgraded to enable this feature.",
	StatusRemoteStorageNotActive:                                "The remote storage service is not operational at this time.",
	StatusRemoteStorageMediaError:                               "The remote storage service encountered a media error.",
	StatusNoTrackingService:                                     "The tracking (workstation) service is not running.",
	StatusServerSidMismatch:                                     "The server process is running under a SID that is different from the SID that is required by client.",
	StatusDsNoAttributeOrValue:                                  "The specified directory service attribute or value does not exist.",
	StatusDsInvalidAttributeSyntax:                              "The attribute syntax specified to the directory service is invalid.",
	StatusDsAttributeTypeUndefined:                              "The attribute type specified to the directory service is not defined.",
	StatusDsAttributeOrValueExists:                              "The specified directory service attribute or value already exists.",
	StatusDsBusy:                                                "The directory service is busy.",
	StatusDsUnavailable:                                         "The directory service is unavailable.",
	StatusDsNoRidsAllocated:                                     "The directory service was unable to allocate a relative identifier.",
	StatusDsNoMoreRids:                                          "The directory service has exhausted the pool of relative identifiers.",
	StatusDsIncorrectRoleOwner:                                  "The requested operation could not be performed because the directory service is not the master for that type of operation.",
	StatusDsRidmgrInitError:                                     "The directory service was unable to initialize the subsystem that allocates relative identifiers.",
	StatusDsObjClassViolation:                                   "The requested operation did not satisfy one or more constraints that are associated with the class of the object.",
	StatusDsCantOnNonLeaf:                                       "The directory service can perform the requested operation only on a leaf object.",
	StatusDsCantOnRdn:                                           "The directory service cannot perform the requested operation on the Relatively Defined Name (RDN) attribute of an object.",
	StatusDsCantModObjClass:                                     "The directory service detected an attempt to modify the object class of an object.",
	StatusDsCrossDomMoveFailed:                                  "An error occurred while performing a cross domain move operation.",
	StatusDsGcNotAvailable:                                      "Unable to contact the global catalog server.",
	StatusDirectoryServiceRequired:                              "The requested operation requires a directory service, and none was available.",
	StatusReparseAttributeConflict:                              "The reparse attribute cannot be set because it is incompatible with an existing attribute.",
	StatusCantEnableDenyOnly:                                    "A group marked \"use for deny only\" cannot be enabled.",
	StatusFloatMultipleFaults:                                   "{EXCEPTION} Multiple floating-point faults.",
	StatusFloatMultipleTraps:                                    "{EXCEPTION} Multiple floating-point traps.",
	StatusDeviceRemoved:                                         "The device has been removed.",
	StatusJournalDeleteInProgress:                               "The volume change journal is being deleted.",
	StatusJournalNotActive:                                      "The volume change journal is not active.",
	StatusNointerface:                                           "The requested interface is not supported.",
	StatusDsAdminLimitExceeded:                                  "A directory service resource limit has been exceeded.",
	StatusDriverFailedSleep:                                     "{System Standby Failed} The driver %hs does not support standby mode. Updating this driver may allow the system to go to standby mode.",
	StatusMutualAuthenticationFailed:                            "Mutual Authentication failed. The server password is out of date at the domain controller.",
	StatusCorruptSystemFile:                                     "The system file %1 has become corrupt and has been replaced.",
	StatusDatatypeMisalignmentError:                             "{EXCEPTION} Alignment Error A data type misalignment error was detected in a load or store instruction.",
	StatusWmiReadOnly:                                           "The WMI data item or data block is read-only.",
	StatusWmiSetFailure:                                         "The WMI data item or data block could not be changed.",
	StatusCommitmentMinimum:                                     "{Virtual Memory Minimum Too Low} Your system is low on virtual memory. Windows is increasing the size of your virtual memory paging file. During this process, memory requests for some applications may be denied. For more information, see Help.",
	StatusRegNatConsumption:                                     "{EXCEPTION} Register NaT consumption faults. A NaT value is consumed on a non-speculative instruction.",
	StatusTransportFull:                                         "The transport element of the medium changer contains media, which is causing the operation to fail.",
	StatusDsSamInitFailure:                                      "Security Accounts Manager initialization failed because of the following error: %hs Error Status: 0x%x. Click OK to shut down this system and restart in Directory Services Restore Mode. Check the event log for more detailed information.",
	StatusOnlyIfConnected:                                       "This operation is supported only when you are connected to the server.",
	StatusDsSensitiveGroupViolation:                             "Only an administrator can modify the membership list of an administrative group.",
	StatusPnpRestartEnumeration:                                 "A device was removed so enumeration must be restarted.",
	StatusJournalEntryDeleted:                                   "The journal entry has been deleted from the journal.",
	StatusDsCantModPrimarygroupid:                               "Cannot change the primary group ID of a domain controller account.",
	StatusSystemImageBadSignature:                               "{Fatal System Error} The system image %s is not properly signed. The file has been replaced with the signed file. The system has been shut down.",
	StatusPnpRebootRequired:                                     "The device will not start without a reboot.",
	StatusPowerStateInvalid:                                     "The power state of the current device cannot support this request.",
	StatusDsInvalidGroupType:                                    "The specified group type is invalid.",
	StatusDsNoNestGlobalgroupInMixeddomain:                      "In a mixed domain, no nesting of a global group if the group is security enabled.",
	StatusDsNoNestLocalgroupInMixeddomain:                       "In a mixed domain, cannot nest local groups with other local groups, if the group is security enabled.",
	StatusDsGlobalCantHaveLocalMember:                           "A global group cannot have a local group as a member.",
	StatusDsGlobalCantHaveUniversalMember:                       "A global group cannot have a universal group as a member.",
	StatusDsUniversalCantHaveLocalMember:                        "A universal group cannot have a local group as a member.",
	StatusDsGlobalCantHaveCrossdomainMember:                     "A global group cannot have a cross-domain member.",
	StatusDsLocalCantHaveCrossdomainLocalMember:                 "A local group cannot have another cross-domain local group as a member.",
	StatusDsHavePrimaryMembers:                                  "Cannot change to a security-disabled group because primary members are in this group.",
	StatusWmiNotSupported:                                       "The WMI operation is not supported by the data block or method.",
	StatusInsufficientPower:                                     "There is not enough power to complete the requested operation.",
	StatusSamNeedBootkeyPassword:                                "The Security Accounts Manager needs to get the boot password.",
	StatusSamNeedBootkeyFloppy:                                  "The Security Accounts Manager needs to get the boot key from the floppy disk.",
	StatusDsCantStart:                                           "The directory service cannot start.",
	StatusDsInitFailure:                                         "The directory service could not start because of the following error: %hs Error Status: 0x%x. Click OK to shut down this system and restart in Directory Services Restore Mode. Check the event log for more detailed information.",
	StatusSamInitFailure:                                        "The Security Accounts Manager initialization failed because of the following error: %hs Error Status: 0x%x. Click OK to shut down this system and restart in Safe Mode. Check the event log for more detailed information.",
	StatusDsGcRequired:                                          "The requested operation can be performed only on a global catalog server.",
	StatusDsLocalMemberOfLocalOnly:                              "A local group can only be a member of other local groups in the same domain.",
	StatusDsNoFpoInUniversalGroups:                              "Foreign security principals cannot be members of universal groups.",
	StatusDsMachineAccountQuotaExceeded:                         "Your computer could not be joined to the domain. You have exceeded the maximum number of computer accounts you are allowed to create in this domain. Contact your system administrator to have this limit reset or increased.",
	StatusCurrentDomainNotAllowed:                               "This operation cannot be performed on the current domain.",
	StatusCannotMake:                                            "The directory or file cannot be created.",
	StatusSystemShutdown:                                        "The system is in the process of shutting down.",
	StatusDsInitFailureConsole:                                  "Directory Services could not start because of the following error: %hs Error Status: 0x%x. Click OK to shut down the system. You can use the recovery console to diagnose the system further.",
	StatusDsSamInitFailureConsole:                               "Security Accounts Manager initialization failed because of the following error: %hs Error Status: 0x%x. Click OK to shut down the system. You can use the recovery console to diagnose the system further.",
	StatusUnfinishedContextDeleted:                              "A security context was deleted before the context was completed. This is considered a logon failure.",
	StatusNoTgtReply:                                            "The client is trying to negotiate a context and the server requires user-to-user but did not send a TGT reply.",
	StatusObjectidNotFound:                                      "An object ID was not found in the file.",
	StatusNoIpAddresses:                                         "Unable to accomplish the requested task because the local machine does not have any IP addresses.",
	StatusWrongCredentialHandle:                                 "The supplied credential handle does not match the credential that is associated with the security context.",
	StatusCryptoSystemInvalid:                                   "The crypto system or checksum function is invalid because a required function is unavailable.",
	StatusMaxReferralsExceeded:                                  "The number of maximum ticket referrals has been exceeded.",
	StatusMustBeKdc:                                             "The local machine must be a Kerberos KDC (domain controller) and it is not.",
	StatusStrongCryptoNotSupported:                              "The other end of the security negotiation requires strong crypto but it is not supported on the local machine.",
	StatusTooManyPrincipals:                                     "The KDC reply contained more than one principal name.",
	StatusNoPaData:                                              "Expected to find PA data for a hint of what etype to use, but it was not found.",
	StatusPkinitNameMismatch:                                    "The client certificate does not contain a valid UPN, or does not match the client name in the logon request. Contact your administrator.",
	StatusSmartcardLogonRequired:                                "Smart card logon is required and was not used.",
	StatusKdcInvalidRequest:                                     "An invalid request was sent to the KDC.",
	StatusKdcUnableToRefer:                                      "The KDC was unable to generate a referral for the service requested.",
	StatusKdcUnknownEtype:                                       "The encryption type requested is not supported by the KDC.",
	StatusShutdownInProgress:                                    "A system shutdown is in progress.",
	StatusServerShutdownInProgress:                              "The server machine is shutting down.",
	StatusNotSupportedOnSbs:                                     "This operation is not supported on a computer running Windows Server 2003 operating system for Small Business Server.",
	StatusWmiGuidDisconnected:                                   "The WMI GUID is no longer available.",
	StatusWmiAlreadyDisabled:                                    "Collection or events for the WMI GUID is already disabled.",
	StatusWmiAlreadyEnabled:                                     "Collection or events for the WMI GUID is already enabled.",
	StatusMftTooFragmented:                                      "The master file table on the volume is too fragmented to complete this operation.",
	StatusCopyProtectionFailure:                                 "Copy protection failure.",
	StatusCssAuthenticationFailure:                              "Copy protection error—DVD CSS Authentication failed.",
	StatusCssKeyNotPresent:                                      "Copy protection error—The specified sector does not contain a valid key.",
	StatusCssKeyNotEstablished:                                  "Copy protection error—DVD session key not established.",
	StatusCssScrambledSector:                                    "Copy protection error—The read failed because the sector is encrypted.",
	StatusCssRegionMismatch:                                     "Copy protection error—The region of the specified DVD does not correspond to the region setting of the drive.",
	StatusCssResetsExhausted:                                    "Copy protection error—The region setting of the drive may be permanent.",
	StatusPkinitFailure:                                         "The Kerberos protocol encountered an error while validating the KDC certificate during smart card logon. There is more information in the system event log.",
	StatusSmartcardSubsystemFailure:                             "The Kerberos protocol encountered an error while attempting to use the smart card subsystem.",
	StatusNoKerbKey:                                             "The target server does not have acceptable Kerberos credentials.",
	StatusHostDown:                                              "The transport determined that the remote system is down.",
	StatusUnsupportedPreauth:                                    "An unsupported pre-authentication mechanism was presented to the Kerberos package.",
	StatusEfsAlgBlobTooBig:                                      "The encryption algorithm that is used on the source file needs a bigger key buffer than the one that is used on the destination file.",
	StatusPortNotSet:                                            "An attempt to remove a processes DebugPort was made, but a port was not already associated with the process.",
	StatusDebuggerInactive:                                      "An attempt to do an operation on a debug port failed because the port is in the process of being deleted.",
	StatusDsVersionCheckFailure:                                 "This version of Windows is not compatible with the behavior version of the directory forest, domain, or domain controller.",
	StatusAuditingDisabled:                                      "The specified event is currently not being audited.",
	StatusPrent4MachineAccount:                                  "The machine account was created prior to Windows NT 4.0 operating system. The account needs to be recreated.",
	StatusDsAgCantHaveUniversalMember:                           "An account group cannot have a universal group as a member.",
	StatusInvalidImageWin32:                                     "The specified image file did not have the correct format; it appears to be a 32-bit Windows image.",
	StatusInvalidImageWin64:                                     "The specified image file did not have the correct format; it appears to be a 64-bit Windows image.",
	StatusBadBindings:                                           "The client's supplied SSPI channel bindings were incorrect.",
	StatusNetworkSessionExpired:                                 "The client session has expired; so the client must re-authenticate to continue accessing the remote resources.",
	StatusApphelpBlock:                                          "The AppHelp dialog box canceled; thus preventing the application from starting.",
	StatusAllSidsFiltered:                                       "The SID filtering operation removed all SIDs.",
	StatusNotSafeModeDriver:                                     "The driver was not loaded because the system is starting in safe mode.",
	StatusAccessDisabledByPolicyDefault:                         "Access to %1 has been restricted by your Administrator by the default software restriction policy level.",
	StatusAccessDisabledByPolicyPath:                            "Access to %1 has been restricted by your Administrator by location with policy rule %2 placed on path %3.",
	StatusAccessDisabledByPolicyPublisher:                       "Access to %1 has been restricted by your Administrator by software publisher policy.",
	StatusAccessDisabledByPolicyOther:                           "Access to %1 has been restricted by your Administrator by policy rule %2.",
	StatusFailedDriverEntry:                                     "The driver was not loaded because it failed its initialization call.",
	StatusDeviceEnumerationError:                                "The device encountered an error while applying power or reading the device configuration. This may be caused by a failure of your hardware or by a poor connection.",
	StatusMountPointNotResolved:                                 "The create operation failed because the name contained at least one mount point that resolves to a volume to which the specified device object is not attached.",
	StatusInvalidDeviceObjectParameter:                          "The device object parameter is either not a valid device object or is not attached to the volume that is specified by the file name.",
	StatusMcaOccured:                                            "A machine check error has occurred. Check the system event log for additional information.",
	StatusDriverBlockedCritical:                                 "Driver %2 has been blocked from loading.",
	StatusDriverBlocked:                                         "Driver %2 has been blocked from loading.",
	StatusDriverDatabaseError:                                   "There was error [%2] processing the driver database.",
	StatusSystemHiveTooLarge:                                    "System hive size has exceeded its limit.",
	StatusInvalidImportOfNonDll:                                 "A dynamic link library (DLL) referenced a module that was neither a DLL nor the process's executable image.",
	StatusNoSecrets:                                             "The local account store does not contain secret material for the specified account.",
	StatusAccessDisabledNoSaferUiByPolicy:                       "Access to %1 has been restricted by your Administrator by policy rule %2.",
	StatusFailedStackSwitch:                                     "The system was not able to allocate enough memory to perform a stack switch.",
	StatusHeapCorruption:                                        "A heap has been corrupted.",
	StatusSmartcardWrongPin:                                     "An incorrect PIN was presented to the smart card.",
	StatusSmartcardCardBlocked:                                  "The smart card is blocked.",
	StatusSmartcardCardNotAuthenticated:                         "No PIN was presented to the smart card.",
	StatusSmartcardNoCard:                                       "No smart card is available.",
	StatusSmartcardNoKeyContainer:                               "The requested key container does not exist on the smart card.",
	StatusSmartcardNoCertificate:                                "The requested certificate does not exist on the smart card.",
	StatusSmartcardNoKeyset:                                     "The requested keyset does not exist.",
	StatusSmartcardIoError:                                      "A communication error with the smart card has been detected.",
	StatusDowngradeDetected:                                     "The system detected a possible attempt to compromise security. Ensure that you can contact the server that authenticated you.",
	StatusSmartcardCertRevoked:                                  "The smart card certificate used for authentication has been revoked. Contact your system administrator. There may be additional information in the event log.",
	StatusIssuingCaUntrusted:                                    "An untrusted certificate authority was detected while processing the smart card certificate that is used for authentication. Contact your system administrator.",
	StatusRevocationOfflineC:                                    "The revocation status of the smart card certificate that is used for authentication could not be determined. Contact your system administrator.",
	StatusPkinitClientFailure:                                   "The smart card certificate used for authentication was not trusted. Contact your system administrator.",
	StatusSmartcardCertExpired:                                  "The smart card certificate used for authentication has expired. Contact your system administrator.",
	StatusDriverFailedPriorUnload:                               "The driver could not be loaded because a previous version of the driver is still in memory.",
	StatusSmartcardSilentContext:                                "The smart card provider could not perform the action because the context was acquired as silent.",
	StatusPerUserTrustQuotaExceeded:                             "The delegated trust creation quota of the current user has been exceeded.",
	StatusAllUserTrustQuotaExceeded:                             "The total delegated trust creation quota has been exceeded.",
	StatusUserDeleteTrustQuotaExceeded:                          "The delegated trust deletion quota of the current user has been exceeded.",
	StatusDsNameNotUnique:                                       "The requested name already exists as a unique identifier.",
	StatusDsDuplicateIdFound:                                    "The requested object has a non-unique identifier and cannot be retrieved.",
	StatusDsGroupConversionError:                                "The group cannot be converted due to attribute restrictions on the requested group type.",
	StatusVolsnapPrepareHibernate:                               "{Volume Shadow Copy Service} Wait while the Volume Shadow Copy Service prepares volume %hs for hibernation.",
	StatusUser2userRequired:                                     "Kerberos sub-protocol User2User is required.",
	StatusStackBufferOverrun:                                    "The system detected an overrun of a stack-based buffer in this application. This overrun could potentially allow a malicious user to gain control of this application.",
	StatusNoS4uProtSupport:                                      "The Kerberos subsystem encountered an error. A service for user protocol request was made against a domain controller which does not support service for user.",
	StatusCrossrealmDelegationFailure:                           "An attempt was made by this server to make a Kerberos constrained delegation request for a target that is outside the server realm. This action is not supported and the resulting error indicates a misconfiguration on the allowed-to-delegate-to list for this server. Contact your administrator.",
	StatusRevocationOfflineKdc:                                  "The revocation status of the domain controller certificate used for smart card authentication could not be determined. There is additional information in the system event log. Contact your system administrator.",
	StatusIssuingCaUntrustedKdc:                                 "An untrusted certificate authority was detected while processing the domain controller certificate used for authentication. There is additional information in the system event log. Contact your system administrator.",
	StatusKdcCertExpired:                                        "The domain controller certificate used for smart card logon has expired. Contact your system administrator with the contents of your system event log.",
	StatusKdcCertRevoked:                                        "The domain controller certificate used for smart card logon has been revoked. Contact your system administrator with the contents of your system event log.",
	StatusParameterQuotaExceeded:                                "Data present in one of the parameters is more than the function can operate on.",
	StatusHibernationFailure:                                    "The system has failed to hibernate (The error code is %hs). Hibernation will be disabled until the system is restarted.",
	StatusDelayLoadFailed:                                       "An attempt to delay-load a .dll or get a function address in a delay-loaded .dll failed.",
	StatusAuthenticationFirewallFailed:                          "Logon Failure: The machine you are logging onto is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine.",
	StatusVdmDisallowed:                                         "%hs is a 16-bit application. You do not have permissions to execute 16-bit applications. Check your permissions with your system administrator.",
	StatusHungDisplayDriverThread:                               "{Display Driver Stopped Responding} The %hs display driver has stopped working normally. Save your work and reboot the system to restore full display functionality. The next time you reboot the machine a dialog will be displayed giving you a chance to report this failure to Microsoft.",
	StatusInsufficientResourceForSpecifiedSharedSectionSize:     "The Desktop heap encountered an error while allocating session memory. There is more information in the system event log.",
	StatusInvalidCruntimeParameter:                              "An invalid parameter was passed to a C runtime function.",
	StatusNtlmBlocked:                                           "The authentication failed because NTLM was blocked.",
	StatusDsSrcSidExistsInForest:                                "The source object's SID already exists in destination forest.",
	StatusDsDomainNameExistsInForest:                            "The domain name of the trusted domain already exists in the forest.",
	StatusDsFlatNameExistsInForest:                              "The flat name of the trusted domain already exists in the forest.",
	StatusInvalidUserPrincipalName:                              "The User Principal Name (UPN) is invalid.",
	StatusAssertionFailure:                                      "There has been an assertion failure.",
	StatusVerifierStop:                                          "Application verifier has found an error in the current process.",
	StatusCallbackPopStack:                                      "A user mode unwind is in progress.",
	StatusIncompatibleDriverBlocked:                             "%2 has been blocked from loading due to incompatibility with this system. Contact your software vendor for a compatible version of the driver.",
	StatusHiveUnloaded:                                          "Illegal operation attempted on a registry key which has already been unloaded.",
	StatusCompressionDisabled:                                   "Compression is disabled for this volume.",
	StatusFileSystemLimitation:                                  "The requested operation could not be completed due to a file system limitation.",
	StatusInvalidImageHash:                                      "The hash for image %hs cannot be found in the system catalogs. The image is likely corrupt or the victim of tampering.",
	StatusNotCapable:                                            "The implementation is not capable of performing the request.",
	StatusRequestOutOfSequence:                                  "The requested operation is out of order with respect to other operations.",
	StatusImplementationLimit:                                   "An operation attempted to exceed an implementation-defined limit.",
	StatusElevationRequired:                                     "The requested operation requires elevation.",
	StatusNoSecurityContext:                                     "The required security context does not exist.",
	StatusPku2uCertFailure:                                      "The PKU2U protocol encountered an error while attempting to utilize the associated certificates.",
	StatusBeyondVdl:                                             "The operation was attempted beyond the valid data length of the file.",
	StatusEncounteredWriteInProgress:                            "The attempted write operation encountered a write already in progress for some portion of the range.",
	StatusPteChanged:                                            "The page fault mappings changed in the middle of processing a fault so the operation must be retried.",
	StatusPurgeFailed:                                           "The attempt to purge this file from memory failed to purge some or all the data from memory.",
	StatusCredRequiresConfirmation:                              "The requested credential requires confirmation.",
	StatusCsEncryptionInvalidServerResponse:                     "The remote server sent an invalid response for a file being opened with Client Side Encryption.",
	StatusCsEncryptionUnsupportedServer:                         "Client Side Encryption is not supported by the remote server even though it claims to support it.",
	StatusCsEncryptionExistingEncryptedFile:                     "File is encrypted and should be opened in Client Side Encryption mode.",
	StatusCsEncryptionNewEncryptedFile:                          "A new encrypted file is being created and a $EFS needs to be provided.",
	StatusCsEncryptionFileNotCse:                                "The SMB client requested a CSE FSCTL on a non-CSE file.",
	StatusInvalidLabel:                                          "Indicates a particular Security ID may not be assigned as the label of an object.",
	StatusDriverProcessTerminated:                               "The process hosting the driver for this device has terminated.",
	StatusAmbiguousSystemDevice:                                 "The requested system device cannot be identified due to multiple indistinguishable devices potentially matching the identification criteria.",
	StatusSystemDeviceNotFound:                                  "The requested system device cannot be found.",
	StatusRestartBootApplication:                                "This boot application must be restarted.",
	StatusInsufficientNvramResources:                            "Insufficient NVRAM resources exist to complete the API.\u00a0 A reboot might be required.",
	StatusNoRangesProcessed:                                     "No ranges for the specified operation were able to be processed.",
	StatusDeviceFeatureNotSupported:                             "The storage device does not support Offload Write.",
	StatusDeviceUnreachable:                                     "Data cannot be moved because the source device cannot communicate with the destination device.",
	StatusInvalidToken:                                          "The token representing the data is invalid or expired.",
	StatusServerUnavailable:                                     "The file server is temporarily unavailable.",
	StatusInvalidTaskName:                                       "The specified task name is invalid.",
	StatusInvalidTaskIndex:                                      "The specified task index is invalid.",
	StatusThreadAlreadyInTask:                                   "The specified thread is already joining a task.",
	StatusCallbackBypass:                                        "A callback has requested to bypass native code.",
	StatusFailFastException:                                     "A fail fast exception occurred. Exception handlers will not be invoked and the process will be terminated immediately.",
	StatusImageCertRevoked:                                      "Windows cannot verify the digital signature for this file. The signing certificate for this file has been revoked.",
	StatusPortClosed:                                            "The ALPC port is closed.",
	StatusMessageLost:                                           "The ALPC message requested is no longer available.",
	StatusInvalidMessage:                                        "The ALPC message supplied is invalid.",
	StatusRequestCanceled:                                       "The ALPC message has been canceled.",
	StatusRecursiveDispatch:                                     "Invalid recursive dispatch attempt.",
	StatusLpcReceiveBufferExpected:                              "No receive buffer has been supplied in a synchronous request.",
	StatusLpcInvalidConnectionUsage:                             "The connection port is used in an invalid context.",
	StatusLpcRequestsNotAllowed:                                 "The ALPC port does not accept new request messages.",
	StatusResourceInUse:                                         "The resource requested is already in use.",
	StatusHardwareMemoryError:                                   "The hardware has reported an uncorrectable memory error.",
	StatusThreadpoolHandleException:                             "Status 0x%08x was returned, waiting on handle 0x%x for wait 0x%p, in waiter 0x%p.",
	StatusThreadpoolSetEventOnCompletionFailed:                  "After a callback to 0x%p(0x%p), a completion call to Set event(0x%p) failed with status 0x%08x.",
	StatusThreadpoolReleaseSemaphoreOnCompletionFailed:          "After a callback to 0x%p(0x%p), a completion call to ReleaseSemaphore(0x%p, %d) failed with status 0x%08x.",
	StatusThreadpoolReleaseMutexOnCompletionFailed:              "After a callback to 0x%p(0x%p), a completion call to ReleaseMutex(%p) failed with status 0x%08x.",
	StatusThreadpoolFreeLibraryOnCompletionFailed:               "After a callback to 0x%p(0x%p), a completion call to FreeLibrary(%p) failed with status 0x%08x.",
	StatusThreadpoolReleasedDuringOperation:                     "The thread pool 0x%p was released while a thread was posting a callback to 0x%p(0x%p) to it.",
	StatusCallbackReturnedWhileImpersonating:                    "A thread pool worker thread is impersonating a client, after a callback to 0x%p(0x%p). This is unexpected, indicating that the callback is missing a call to revert the impersonation.",
	StatusApcReturnedWhileImpersonating:                         "A thread pool worker thread is impersonating a client, after executing an APC. This is unexpected, indicating that the APC is missing a call to revert the impersonation.",
	StatusProcessIsProtected:                                    "Either the target process, or the target thread's containing process, is a protected process.",
	StatusMcaException:                                          "A thread is getting dispatched with MCA EXCEPTION because of MCA.",
	StatusCertificateMappingNotUnique:                           "The client certificate account mapping is not unique.",
	StatusSymlinkClassDisabled:                                  "The symbolic link cannot be followed because its type is disabled.",
	StatusInvalidIdnNormalization:                               "Indicates that the specified string is not valid for IDN normalization.",
	StatusNoUnicodeTranslation:                                  "No mapping for the Unicode character exists in the target multi-byte code page.",
	StatusAlreadyRegistered:                                     "The provided callback is already registered.",
	StatusContextMismatch:                                       "The provided context did not match the target.",
	StatusPortAlreadyHasCompletionList:                          "The specified port already has a completion list.",
	StatusCallbackReturnedThreadPriority:                        "A threadpool worker thread entered a callback at thread base priority 0x%x and exited at priority 0x%x.This is unexpected, indicating that the callback missed restoring the priority.",
	StatusInvalidThread:                                         "An invalid thread, handle %p, is specified for this operation. Possibly, a threadpool worker thread was specified.",
	StatusCallbackReturnedTransaction:                           "A threadpool worker thread entered a callback, which left transaction state.This is unexpected, indicating that the callback missed clearing the transaction.",
	StatusCallbackReturnedLdrLock:                               "A threadpool worker thread entered a callback, which left the loader lock held.This is unexpected, indicating that the callback missed releasing the lock.",
	StatusCallbackReturnedLang:                                  "A threadpool worker thread entered a callback, which left with preferred languages set.This is unexpected, indicating that the callback missed clearing them.",
	StatusCallbackReturnedPriBack:                               "A threadpool worker thread entered a callback, which left with background priorities set.This is unexpected, indicating that the callback missed restoring the original priorities.",
	StatusDiskRepairDisabled:                                    "The attempted operation required self healing to be enabled.",
	StatusDsDomainRenameInProgress:                              "The directory service cannot perform the requested operation because a domain rename operation is in progress.",
	StatusDiskQuotaExceeded:                                     "An operation failed because the storage quota was exceeded.",
	StatusContentBlocked:                                        "An operation failed because the content was blocked.",
	StatusBadClusters:                                           "The operation could not be completed due to bad clusters on disk.",
	StatusVolumeDirty:                                           "The operation could not be completed because the volume is dirty. Please run the Chkdsk utility and try again. ",
	StatusFileCheckedOut:                                        "This file is checked out or locked for editing by another user.",
	StatusCheckoutRequired:                                      "The file must be checked out before saving changes.",
	StatusBadFileType:                                           "The file type being saved or retrieved has been blocked.",
	StatusFileTooLarge:                                          "The file size exceeds the limit allowed and cannot be saved.",
	StatusFormsAuthRequired:                                     "Access Denied. Before opening files in this location, you must first browse to the e.g. site and select the option to log on automatically.",
	StatusVirusInfected:                                         "The operation did not complete successfully because the file contains a virus.",
	StatusVirusDeleted:                                          "This file contains a virus and cannot be opened. Due to the nature of this virus, the file has been removed from this location.",
	StatusBadMcfgTable:                                          "The resources required for this device conflict with the MCFG table.",
	StatusCannotBreakOplock:                                     "The operation did not complete successfully because it would cause an oplock to be broken. The caller has requested that existing oplocks not be broken.",
	StatusWowAssertion:                                          "WOW Assertion Error.",
	StatusInvalidSignature:                                      "The cryptographic signature is invalid.",
	StatusHmacNotSupported:                                      "The cryptographic provider does not support HMAC.",
	StatusIpsecQueueOverflow:                                    "The IPsec queue overflowed.",
	StatusNdQueueOverflow:                                       "The neighbor discovery queue overflowed.",
	StatusHoplimitExceeded:                                      "An Internet Control Message Protocol (ICMP) hop limit exceeded error was received.",
	StatusProtocolNotSupported:                                  "The protocol is not installed on the local machine.",
	StatusLostWritebehindDataNetworkDisconnected:                "{Delayed Write Failed} Windows was unable to save all the data for the file %hs; the data has been lost. This error may be caused by network connectivity issues. Try to save this file elsewhere.",
	StatusLostWritebehindDataNetworkServerError:                 "{Delayed Write Failed} Windows was unable to save all the data for the file %hs; the data has been lost. This error was returned by the server on which the file exists. Try to save this file elsewhere.",
	StatusLostWritebehindDataLocalDiskError:                     "{Delayed Write Failed} Windows was unable to save all the data for the file %hs; the data has been lost. This error may be caused if the device has been removed or the media is write-protected.",
	StatusXmlParseError:                                         "Windows was unable to parse the requested XML data.",
	StatusXmldsigError:                                          "An error was encountered while processing an XML digital signature.",
	StatusWrongCompartment:                                      "This indicates that the caller made the connection request in the wrong routing compartment.",
	StatusAuthipFailure:                                         "This indicates that there was an AuthIP failure when attempting to connect to the remote host.",
	StatusDsOidMappedGroupCantHaveMembers:                       "OID mapped groups cannot have members.",
	StatusDsOidNotFound:                                         "The specified OID cannot be found.",
	StatusHashNotSupported:                                      "Hash generation for the specified version and hash type is not enabled on server.",
	StatusHashNotPresent:                                        "The hash requests is not present or not up to date with the current file contents.",
	StatusOffloadReadFltNotSupported:                            "A file system filter on the server has not opted in for Offload Read support.",
	StatusOffloadWriteFltNotSupported:                           "A file system filter on the server has not opted in for Offload Write support.",
	StatusOffloadReadFileNotSupported:                           "Offload read operations cannot be performed on:   Compressed files   Sparse files   Encrypted files   File system metadata files",
	StatusOffloadWriteFileNotSupported:                          "Offload write operations cannot be performed on:   Compressed files   Sparse files   Encrypted files   File system metadata files",
	DbgNoStateChange:                                            "The debugger did not perform a state change.",
	DbgAppNotIdle:                                               "The debugger found that the application is not idle.",
	RpcNtInvalidStringBinding:                                   "The string binding is invalid.",
	RpcNtWrongKindOfBinding:                                     "The binding handle is not the correct type.",
	RpcNtInvalidBinding:                                         "The binding handle is invalid.",
	RpcNtProtseqNotSupported:                                    "The RPC protocol sequence is not supported.",
	RpcNtInvalidRpcProtseq:                                      "The RPC protocol sequence is invalid.",
	RpcNtInvalidStringUuid:                                      "The string UUID is invalid.",
	RpcNtInvalidEndpointFormat:                                  "The endpoint format is invalid.",
	RpcNtInvalidNetAddr:                                         "The network address is invalid.",
	RpcNtNoEndpointFound:                                        "No endpoint was found.",
	RpcNtInvalidTimeout:                                         "The time-out value is invalid.",
	RpcNtObjectNotFound:                                         "The object UUID was not found.",
	RpcNtAlreadyRegistered:                                      "The object UUID has already been registered.",
	RpcNtTypeAlreadyRegistered:                                  "The type UUID has already been registered.",
	RpcNtAlreadyListening:                                       "The RPC server is already listening.",
	RpcNtNoProtseqsRegistered:                                   "No protocol sequences have been registered.",
	RpcNtNotListening:                                           "The RPC server is not listening.",
	RpcNtUnknownMgrType:                                         "The manager type is unknown.",
	RpcNtUnknownIf:                                              "The interface is unknown.",
	RpcNtNoBindings:                                             "There are no bindings.",
	RpcNtNoProtseqs:                                             "There are no protocol sequences.",
	RpcNtCantCreateEndpoint:                                     "The endpoint cannot be created.",
	RpcNtOutOfResources:                                         "Insufficient resources are available to complete this operation.",
	RpcNtServerUnavailable:                                      "The RPC server is unavailable.",
	RpcNtServerTooBusy:                                          "The RPC server is too busy to complete this operation.",
	RpcNtInvalidNetworkOptions:                                  "The network options are invalid.",
	RpcNtNoCallActive:                                           "No RPCs are active on this thread.",
	RpcNtCallFailed:                                             "The RPC failed.",
	RpcNtCallFailedDne:                                          "The RPC failed and did not execute.",
	RpcNtProtocolError:                                          "An RPC protocol error occurred.",
	RpcNtUnsupportedTransSyn:                                    "The RPC server does not support the transfer syntax.",
	RpcNtUnsupportedType:                                        "The type UUID is not supported.",
	RpcNtInvalidTag:                                             "The tag is invalid.",
	RpcNtInvalidBound:                                           "The array bounds are invalid.",
	RpcNtNoEntryName:                                            "The binding does not contain an entry name.",
	RpcNtInvalidNameSyntax:                                      "The name syntax is invalid.",
	RpcNtUnsupportedNameSyntax:                                  "The name syntax is not supported.",
	RpcNtUuidNoAddress:                                          "No network address is available to construct a UUID.",
	RpcNtDuplicateEndpoint:                                      "The endpoint is a duplicate.",
	RpcNtUnknownAuthnType:                                       "The authentication type is unknown.",
	RpcNtMaxCallsTooSmall:                                       "The maximum number of calls is too small.",
	RpcNtStringTooLong:                                          "The string is too long.",
	RpcNtProtseqNotFound:                                        "The RPC protocol sequence was not found.",
	RpcNtProcnumOutOfRange:                                      "The procedure number is out of range.",
	RpcNtBindingHasNoAuth:                                       "The binding does not contain any authentication information.",
	RpcNtUnknownAuthnService:                                    "The authentication service is unknown.",
	RpcNtUnknownAuthnLevel:                                      "The authentication level is unknown.",
	RpcNtInvalidAuthIdentity:                                    "The security context is invalid.",
	RpcNtUnknownAuthzService:                                    "The authorization service is unknown.",
	EptNtInvalidEntry:                                           "The entry is invalid.",
	EptNtCantPerformOp:                                          "The operation cannot be performed.",
	EptNtNotRegistered:                                          "No more endpoints are available from the endpoint mapper.",
	RpcNtNothingToExport:                                        "No interfaces have been exported.",
	RpcNtIncompleteName:                                         "The entry name is incomplete.",
	RpcNtInvalidVersOption:                                      "The version option is invalid.",
	RpcNtNoMoreMembers:                                          "There are no more members.",
	RpcNtNotAllObjsUnexported:                                   "There is nothing to unexport.",
	RpcNtInterfaceNotFound:                                      "The interface was not found.",
	RpcNtEntryAlreadyExists:                                     "The entry already exists.",
	RpcNtEntryNotFound:                                          "The entry was not found.",
	RpcNtNameServiceUnavailable:                                 "The name service is unavailable.",
	RpcNtInvalidNafId:                                           "The network address family is invalid.",
	RpcNtCannotSupport:                                          "The requested operation is not supported.",
	RpcNtNoContextAvailable:                                     "No security context is available to allow impersonation.",
	RpcNtInternalError:                                          "An internal error occurred in the RPC.",
	RpcNtZeroDivide:                                             "The RPC server attempted to divide an integer by zero.",
	RpcNtAddressError:                                           "An addressing error occurred in the RPC server.",
	RpcNtFpDivZero:                                              "A floating point operation at the RPC server caused a divide by zero.",
	RpcNtFpUnderflow:                                            "A floating point underflow occurred at the RPC server.",
	RpcNtFpOverflow:                                             "A floating point overflow occurred at the RPC server.",
	RpcNtCallInProgress:                                         "An RPC is already in progress for this thread.",
	RpcNtNoMoreBindings:                                         "There are no more bindings.",
	RpcNtGroupMemberNotFound:                                    "The group member was not found.",
	EptNtCantCreate:                                             "The endpoint mapper database entry could not be created.",
	RpcNtInvalidObject:                                          "The object UUID is the nil UUID.",
	RpcNtNoInterfaces:                                           "No interfaces have been registered.",
	RpcNtCallCancelled:                                          "The RPC was canceled.",
	RpcNtBindingIncomplete:                                      "The binding handle does not contain all the required information.",
	RpcNtCommFailure:                                            "A communications failure occurred during an RPC.",
	RpcNtUnsupportedAuthnLevel:                                  "The requested authentication level is not supported.",
	RpcNtNoPrincName:                                            "No principal name was registered.",
	RpcNtNotRpcError:                                            "The error specified is not a valid Windows RPC error code.",
	RpcNtSecPkgError:                                            "A security package-specific error occurred.",
	RpcNtNotCancelled:                                           "The thread was not canceled.",
	RpcNtInvalidAsyncHandle:                                     "Invalid asynchronous RPC handle.",
	RpcNtInvalidAsyncCall:                                       "Invalid asynchronous RPC call handle for this operation.",
	RpcNtProxyAccessDenied:                                      "Access to the HTTP proxy is denied.",
	RpcNtNoMoreEntries:                                          "The list of RPC servers available for auto-handle binding has been exhausted.",
	RpcNtSsCharTransOpenFail:                                    "The file designated by DCERPCCHARTRANS cannot be opened.",
	RpcNtSsCharTransShortFile:                                   "The file containing the character translation table has fewer than 512 bytes.",
	RpcNtSsInNullContext:                                        "A null context handle is passed as an [in] parameter.",
	RpcNtSsContextMismatch:                                      "The context handle does not match any known context handles.",
	RpcNtSsContextDamaged:                                       "The context handle changed during a call.",
	RpcNtSsHandlesMismatch:                                      "The binding handles passed to an RPC do not match.",
	RpcNtSsCannotGetCallHandle:                                  "The stub is unable to get the call handle.",
	RpcNtNullRefPointer:                                         "A null reference pointer was passed to the stub.",
	RpcNtEnumValueOutOfRange:                                    "The enumeration value is out of range.",
	RpcNtByteCountTooSmall:                                      "The byte count is too small.",
	RpcNtBadStubData:                                            "The stub received bad data.",
	RpcNtInvalidEsAction:                                        "Invalid operation on the encoding/decoding handle.",
	RpcNtWrongEsVersion:                                         "Incompatible version of the serializing package.",
	RpcNtWrongStubVersion:                                       "Incompatible version of the RPC stub.",
	RpcNtInvalidPipeObject:                                      "The RPC pipe object is invalid or corrupt.",
	RpcNtInvalidPipeOperation:                                   "An invalid operation was attempted on an RPC pipe object.",
	RpcNtWrongPipeVersion:                                       "Unsupported RPC pipe version.",
	RpcNtPipeClosed:                                             "The RPC pipe object has already been closed.",
	RpcNtPipeDisciplineError:                                    "The RPC call completed before all pipes were processed.",
	RpcNtPipeEmpty:                                              "No more data is available from the RPC pipe.",
	StatusPnpBadMpsTable:                                        "A device is missing in the system BIOS MPS table. This device will not be used. Contact your system vendor for a system BIOS update.",
	StatusPnpTranslationFailed:                                  "A translator failed to translate resources.",
	StatusPnpIrqTranslationFailed:                               "An IRQ translator failed to translate resources.",
	StatusPnpInvalidId:                                          "Driver %2 returned an invalid ID for a child device (%3).",
	StatusIoReissueAsCached:                                     "Reissue the given operation as a cached I/O operation",
	StatusCtxWinstationNameInvalid:                              "Session name %1 is invalid.",
	StatusCtxInvalidPd:                                          "The protocol driver %1 is invalid.",
	StatusCtxPdNotFound:                                         "The protocol driver %1 was not found in the system path.",
	StatusCtxClosePending:                                       "A close operation is pending on the terminal connection.",
	StatusCtxNoOutbuf:                                           "No free output buffers are available.",
	StatusCtxModemInfNotFound:                                   "The MODEM.INF file was not found.",
	StatusCtxInvalidModemname:                                   "The modem (%1) was not found in the MODEM.INF file.",
	StatusCtxResponseError:                                      "The modem did not accept the command sent to it. Verify that the configured modem name matches the attached modem.",
	StatusCtxModemResponseTimeout:                               "The modem did not respond to the command sent to it. Verify that the modem cable is properly attached and the modem is turned on.",
	StatusCtxModemResponseNoCarrier:                             "Carrier detection has failed or the carrier has been dropped due to disconnection.",
	StatusCtxModemResponseNoDialtone:                            "A dial tone was not detected within the required time. Verify that the phone cable is properly attached and functional.",
	StatusCtxModemResponseBusy:                                  "A busy signal was detected at a remote site on callback.",
	StatusCtxModemResponseVoice:                                 "A voice was detected at a remote site on callback.",
	StatusCtxTdError:                                            "Transport driver error.",
	StatusCtxLicenseClientInvalid:                               "The client you are using is not licensed to use this system. Your logon request is denied.",
	StatusCtxLicenseNotAvailable:                                "The system has reached its licensed logon limit. Try again later.",
	StatusCtxLicenseExpired:                                     "The system license has expired. Your logon request is denied.",
	StatusCtxWinstationNotFound:                                 "The specified session cannot be found.",
	StatusCtxWinstationNameCollision:                            "The specified session name is already in use.",
	StatusCtxWinstationBusy:                                     "The requested operation cannot be completed because the terminal connection is currently processing a connect, disconnect, reset, or delete operation.",
	StatusCtxBadVideoMode:                                       "An attempt has been made to connect to a session whose video mode is not supported by the current client.",
	StatusCtxGraphicsInvalid:                                    "The application attempted to enable DOS graphics mode. DOS graphics mode is not supported.",
	StatusCtxNotConsole:                                         "The requested operation can be performed only on the system console. This is most often the result of a driver or system DLL requiring direct console access.",
	StatusCtxClientQueryTimeout:                                 "The client failed to respond to the server connect message.",
	StatusCtxConsoleDisconnect:                                  "Disconnecting the console session is not supported.",
	StatusCtxConsoleConnect:                                     "Reconnecting a disconnected session to the console is not supported.",
	StatusCtxShadowDenied:                                       "The request to control another session remotely was denied.",
	StatusCtxWinstationAccessDenied:                             "A process has requested access to a session, but has not been granted those access rights.",
	StatusCtxInvalidWd:                                          "The terminal connection driver %1 is invalid.",
	StatusCtxWdNotFound:                                         "The terminal connection driver %1 was not found in the system path.",
	StatusCtxShadowInvalid:                                      "The requested session cannot be controlled remotely. You cannot control your own session, a session that is trying to control your session, a session that has no user logged on, or other sessions from the console.",
	StatusCtxShadowDisabled:                                     "The requested session is not configured to allow remote control.",
	StatusRdpProtocolError:                                      "The RDP protocol component %2 detected an error in the protocol stream and has disconnected the client.",
	StatusCtxClientLicenseNotSet:                                "Your request to connect to this terminal server has been rejected. Your terminal server client license number has not been entered for this copy of the terminal client. Contact your system administrator for help in entering a valid, unique license number for this terminal server client. Click OK to continue.",
	StatusCtxClientLicenseInUse:                                 "Your request to connect to this terminal server has been rejected. Your terminal server client license number is currently being used by another user. Contact your system administrator to obtain a new copy of the terminal server client with a valid, unique license number. Click OK to continue.",
	StatusCtxShadowEndedByModeChange:                            "The remote control of the console was terminated because the display mode was changed. Changing the display mode in a remote control session is not supported.",
	StatusCtxShadowNotRunning:                                   "Remote control could not be terminated because the specified session is not currently being remotely controlled.",
	StatusCtxLogonDisabled:                                      "Your interactive logon privilege has been disabled. Contact your system administrator.",
	StatusCtxSecurityLayerError:                                 "The terminal server security layer detected an error in the protocol stream and has disconnected the client.",
	StatusTsIncompatibleSessions:                                "The target session is incompatible with the current session.",
	StatusMuiFileNotFound:                                       "The resource loader failed to find an MUI file.",
	StatusMuiInvalidFile:                                        "The resource loader failed to load an MUI file because the file failed to pass validation.",
	StatusMuiInvalidRcConfig:                                    "The RC manifest is corrupted with garbage data, is an unsupported version, or is missing a required item.",
	StatusMuiInvalidLocaleName:                                  "The RC manifest has an invalid culture name.",
	StatusMuiInvalidUltimatefallbackName:                        "The RC manifest has and invalid ultimate fallback name.",
	StatusMuiFileNotLoaded:                                      "The resource loader cache does not have a loaded MUI entry.",
	StatusResourceEnumUserStop:                                  "The user stopped resource enumeration.",
	StatusClusterInvalidNode:                                    "The cluster node is not valid.",
	StatusClusterNodeExists:                                     "The cluster node already exists.",
	StatusClusterJoinInProgress:                                 "A node is in the process of joining the cluster.",
	StatusClusterNodeNotFound:                                   "The cluster node was not found.",
	StatusClusterLocalNodeNotFound:                              "The cluster local node information was not found.",
	StatusClusterNetworkExists:                                  "The cluster network already exists.",
	StatusClusterNetworkNotFound:                                "The cluster network was not found.",
	StatusClusterNetinterfaceExists:                             "The cluster network interface already exists.",
	StatusClusterNetinterfaceNotFound:                           "The cluster network interface was not found.",
	StatusClusterInvalidRequest:                                 "The cluster request is not valid for this object.",
	StatusClusterInvalidNetworkProvider:                         "The cluster network provider is not valid.",
	StatusClusterNodeDown:                                       "The cluster node is down.",
	StatusClusterNodeUnreachable:                                "The cluster node is not reachable.",
	StatusClusterNodeNotMember:                                  "The cluster node is not a member of the cluster.",
	StatusClusterJoinNotInProgress:                              "A cluster join operation is not in progress.",
	StatusClusterInvalidNetwork:                                 "The cluster network is not valid.",
	StatusClusterNoNetAdapters:                                  "No network adapters are available.",
	StatusClusterNodeUp:                                         "The cluster node is up.",
	StatusClusterNodePaused:                                     "The cluster node is paused.",
	StatusClusterNodeNotPaused:                                  "The cluster node is not paused.",
	StatusClusterNoSecurityContext:                              "No cluster security context is available.",
	StatusClusterNetworkNotInternal:                             "The cluster network is not configured for internal cluster communication.",
	StatusClusterPoisoned:                                       "The cluster node has been poisoned.",
	StatusAcpiInvalidOpcode:                                     "An attempt was made to run an invalid AML opcode.",
	StatusAcpiStackOverflow:                                     "The AML interpreter stack has overflowed.",
	StatusAcpiAssertFailed:                                      "An inconsistent state has occurred.",
	StatusAcpiInvalidIndex:                                      "An attempt was made to access an array outside its bounds.",
	StatusAcpiInvalidArgument:                                   "A required argument was not specified.",
	StatusAcpiFatal:                                             "A fatal error has occurred.",
	StatusAcpiInvalidSupername:                                  "An invalid SuperName was specified.",
	StatusAcpiInvalidArgtype:                                    "An argument with an incorrect type was specified.",
	StatusAcpiInvalidObjtype:                                    "An object with an incorrect type was specified.",
	StatusAcpiInvalidTargettype:                                 "A target with an incorrect type was specified.",
	StatusAcpiIncorrectArgumentCount:                            "An incorrect number of arguments was specified.",
	StatusAcpiAddressNotMapped:                                  "An address failed to translate.",
	StatusAcpiInvalidEventtype:                                  "An incorrect event type was specified.",
	StatusAcpiHandlerCollision:                                  "A handler for the target already exists.",
	StatusAcpiInvalidData:                                       "Invalid data for the target was specified.",
	StatusAcpiInvalidRegion:                                     "An invalid region for the target was specified.",
	StatusAcpiInvalidAccessSize:                                 "An attempt was made to access a field outside the defined range.",
	StatusAcpiAcquireGlobalLock:                                 "The global system lock could not be acquired.",
	StatusAcpiAlreadyInitialized:                                "An attempt was made to reinitialize the ACPI subsystem.",
	StatusAcpiNotInitialized:                                    "The ACPI subsystem has not been initialized.",
	StatusAcpiInvalidMutexLevel:                                 "An incorrect mutex was specified.",
	StatusAcpiMutexNotOwned:                                     "The mutex is not currently owned.",
	StatusAcpiMutexNotOwner:                                     "An attempt was made to access the mutex by a process that was not the owner.",
	StatusAcpiRsAccess:                                          "An error occurred during an access to region space.",
	StatusAcpiInvalidTable:                                      "An attempt was made to use an incorrect table.",
	StatusAcpiRegHandlerFailed:                                  "The registration of an ACPI event failed.",
	StatusAcpiPowerRequestFailed:                                "An ACPI power object failed to transition state.",
	StatusSxsSectionNotFound:                                    "The requested section is not present in the activation context.",
	StatusSxsCantGenActctx:                                      "Windows was unble to process the application binding information. Refer to the system event log for further information.",
	StatusSxsInvalidActctxdataFormat:                            "The application binding data format is invalid.",
	StatusSxsAssemblyNotFound:                                   "The referenced assembly is not installed on the system.",
	StatusSxsManifestFormatError:                                "The manifest file does not begin with the required tag and format information.",
	StatusSxsManifestParseError:                                 "The manifest file contains one or more syntax errors.",
	StatusSxsActivationContextDisabled:                          "The application attempted to activate a disabled activation context.",
	StatusSxsKeyNotFound:                                        "The requested lookup key was not found in any active activation context.",
	StatusSxsVersionConflict:                                    "A component version required by the application conflicts with another component version that is already active.",
	StatusSxsWrongSectionType:                                   "The type requested activation context section does not match the query API used.",
	StatusSxsThreadQueriesDisabled:                              "Lack of system resources has required isolated activation to be disabled for the current thread of execution.",
	StatusSxsAssemblyMissing:                                    "The referenced assembly could not be found.",
	StatusSxsProcessDefaultAlreadySet:                           "An attempt to set the process default activation context failed because the process default activation context was already set.",
	StatusSxsEarlyDeactivation:                                  "The activation context being deactivated is not the most recently activated one.",
	StatusSxsInvalidDeactivation:                                "The activation context being deactivated is not active for the current thread of execution.",
	StatusSxsMultipleDeactivation:                               "The activation context being deactivated has already been deactivated.",
	StatusSxsSystemDefaultActivationContextEmpty:                "The activation context of the system default assembly could not be generated.",
	StatusSxsProcessTerminationRequested:                        "A component used by the isolation facility has requested that the process be terminated.",
	StatusSxsCorruptActivationStack:                             "The activation context activation stack for the running thread of execution is corrupt.",
	StatusSxsCorruption:                                         "The application isolation metadata for this process or thread has become corrupt.",
	StatusSxsInvalidIdentityAttributeValue:                      "The value of an attribute in an identity is not within the legal range.",
	StatusSxsInvalidIdentityAttributeName:                       "The name of an attribute in an identity is not within the legal range.",
	StatusSxsIdentityDuplicateAttribute:                         "An identity contains two definitions for the same attribute.",
	StatusSxsIdentityParseError:                                 "The identity string is malformed. This may be due to a trailing comma, more than two unnamed attributes, a missing attribute name, or a missing attribute value.",
	StatusSxsComponentStoreCorrupt:                              "The component store has become corrupted.",
	StatusSxsFileHashMismatch:                                   "A component's file does not match the verification information present in the component manifest.",
	StatusSxsManifestIdentitySameButContentsDifferent:           "The identities of the manifests are identical, but their contents are different.",
	StatusSxsIdentitiesDifferent:                                "The component identities are different.",
	StatusSxsAssemblyIsNotADeployment:                           "The assembly is not a deployment.",
	StatusSxsFileNotPartOfAssembly:                              "The file is not a part of the assembly.",
	StatusAdvancedInstallerFailed:                               "An advanced installer failed during setup or servicing.",
	StatusXmlEncodingMismatch:                                   "The character encoding in the XML declaration did not match the encoding used in the document.",
	StatusSxsManifestTooBig:                                     "The size of the manifest exceeds the maximum allowed.",
	StatusSxsSettingNotRegistered:                               "The setting is not registered.",
	StatusSxsTransactionClosureIncomplete:                       "One or more required transaction members are not present.",
	StatusSmiPrimitiveInstallerFailed:                           "The SMI primitive installer failed during setup or servicing.",
	StatusGenericCommandFailed:                                  "A generic command executable returned a result that indicates failure.",
	StatusSxsFileHashMissing:                                    "A component is missing file verification information in its manifest.",
	StatusTransactionalConflict:                                 "The function attempted to use a name that is reserved for use by another transaction.",
	StatusInvalidTransaction:                                    "The transaction handle associated with this operation is invalid.",
	StatusTransactionNotActive:                                  "The requested operation was made in the context of a transaction that is no longer active.",
	StatusTmInitializationFailed:                                "The transaction manager was unable to be successfully initialized. Transacted operations are not supported.",
	StatusRmNotActive:                                           "Transaction support within the specified file system resource manager was not started or was shut down due to an error.",
	StatusRmMetadataCorrupt:                                     "The metadata of the resource manager has been corrupted. The resource manager will not function.",
	StatusTransactionNotJoined:                                  "The resource manager attempted to prepare a transaction that it has not successfully joined.",
	StatusDirectoryNotRm:                                        "The specified directory does not contain a file system resource manager.",
	StatusTransactionsUnsupportedRemote:                         "The remote server or share does not support transacted file operations.",
	StatusLogResizeInvalidSize:                                  "The requested log size for the file system resource manager is invalid.",
	StatusRemoteFileVersionMismatch:                             "The remote server sent mismatching version number or Fid for a file opened with transactions.",
	StatusCrmProtocolAlreadyExists:                              "The resource manager tried to register a protocol that already exists.",
	StatusTransactionPropagationFailed:                          "The attempt to propagate the transaction failed.",
	StatusCrmProtocolNotFound:                                   "The requested propagation protocol was not registered as a CRM.",
	StatusTransactionSuperiorExists:                             "The transaction object already has a superior enlistment, and the caller attempted an operation that would have created a new superior. Only a single superior enlistment is allowed.",
	StatusTransactionRequestNotValid:                            "The requested operation is not valid on the transaction object in its current state.",
	StatusTransactionNotRequested:                               "The caller has called a response API, but the response is not expected because the transaction manager did not issue the corresponding request to the caller.",
	StatusTransactionAlreadyAborted:                             "It is too late to perform the requested operation, because the transaction has already been aborted.",
	StatusTransactionAlreadyCommitted:                           "It is too late to perform the requested operation, because the transaction has already been committed.",
	StatusTransactionInvalidMarshallBuffer:                      "The buffer passed in to NtPushTransaction or NtPullTransaction is not in a valid format.",
	StatusCurrentTransactionNotValid:                            "The current transaction context associated with the thread is not a valid handle to a transaction object.",
	StatusLogGrowthFailed:                                       "An attempt to create space in the transactional resource manager's log failed. The failure status has been recorded in the event log.",
	StatusObjectNoLongerExists:                                  "The object (file, stream, or link) that corresponds to the handle has been deleted by a transaction savepoint rollback.",
	StatusStreamMiniversionNotFound:                             "The specified file miniversion was not found for this transacted file open.",
	StatusStreamMiniversionNotValid:                             "The specified file miniversion was found but has been invalidated. The most likely cause is a transaction savepoint rollback.",
	StatusMiniversionInaccessibleFromSpecifiedTransaction:       "A miniversion may be opened only in the context of the transaction that created it.",
	StatusCantOpenMiniversionWithModifyIntent:                   "It is not possible to open a miniversion with modify access.",
	StatusCantCreateMoreStreamMiniversions:                      "It is not possible to create any more miniversions for this stream.",
	StatusHandleNoLongerValid:                                   "The handle has been invalidated by a transaction. The most likely cause is the presence of memory mapping on a file or an open handle when the transaction ended or rolled back to savepoint.",
	StatusLogCorruptionDetected:                                 "The log data is corrupt.",
	StatusRmDisconnected:                                        "The transaction outcome is unavailable because the resource manager responsible for it is disconnected.",
	StatusEnlistmentNotSuperior:                                 "The request was rejected because the enlistment in question is not a superior enlistment.",
	StatusFileIdentityNotPersistent:                             "The file cannot be opened in a transaction because its identity depends on the outcome of an unresolved transaction.",
	StatusCantBreakTransactionalDependency:                      "The operation cannot be performed because another transaction is depending on this property not changing.",
	StatusCantCrossRmBoundary:                                   "The operation would involve a single file with two transactional resource managers and is, therefore, not allowed.",
	StatusTxfDirNotEmpty:                                        "The $Txf directory must be empty for this operation to succeed.",
	StatusIndoubtTransactionsExist:                              "The operation would leave a transactional resource manager in an inconsistent state and is therefore not allowed.",
	StatusTmVolatile:                                            "The operation could not be completed because the transaction manager does not have a log.",
	StatusRollbackTimerExpired:                                  "A rollback could not be scheduled because a previously scheduled rollback has already executed or been queued for execution.",
	StatusTxfAttributeCorrupt:                                   "The transactional metadata attribute on the file or directory %hs is corrupt and unreadable.",
	StatusEfsNotAllowedInTransaction:                            "The encryption operation could not be completed because a transaction is active.",
	StatusTransactionalOpenNotAllowed:                           "This object is not allowed to be opened in a transaction.",
	StatusTransactedMappingUnsupportedRemote:                    "Memory mapping (creating a mapped section) a remote file under a transaction is not supported.",
	StatusTransactionRequiredPromotion:                          "Promotion was required to allow the resource manager to enlist, but the transaction was set to disallow it.",
	StatusCannotExecuteFileInTransaction:                        "This file is open for modification in an unresolved transaction and may be opened for execute only by a transacted reader.",
	StatusTransactionsNotFrozen:                                 "The request to thaw frozen transactions was ignored because transactions were not previously frozen.",
	StatusTransactionFreezeInProgress:                           "Transactions cannot be frozen because a freeze is already in progress.",
	StatusNotSnapshotVolume:                                     "The target volume is not a snapshot volume. This operation is valid only on a volume mounted as a snapshot.",
	StatusNoSavepointWithOpenFiles:                              "The savepoint operation failed because files are open on the transaction, which is not permitted.",
	StatusSparseNotAllowedInTransaction:                         "The sparse operation could not be completed because a transaction is active on the file.",
	StatusTmIdentityMismatch:                                    "The call to create a transaction manager object failed because the Tm Identity that is stored in the log file does not match the Tm Identity that was passed in as an argument.",
	StatusFloatedSection:                                        "I/O was attempted on a section object that has been floated as a result of a transaction ending. There is no valid data.",
	StatusCannotAcceptTransactedWork:                            "The transactional resource manager cannot currently accept transacted work due to a transient condition, such as low resources.",
	StatusCannotAbortTransactions:                               "The transactional resource manager had too many transactions outstanding that could not be aborted. The transactional resource manager has been shut down.",
	StatusTransactionNotFound:                                   "The specified transaction was unable to be opened because it was not found.",
	StatusResourcemanagerNotFound:                               "The specified resource manager was unable to be opened because it was not found.",
	StatusEnlistmentNotFound:                                    "The specified enlistment was unable to be opened because it was not found.",
	StatusTransactionmanagerNotFound:                            "The specified transaction manager was unable to be opened because it was not found.",
	StatusTransactionmanagerNotOnline:                           "The specified resource manager was unable to create an enlistment because its associated transaction manager is not online.",
	StatusTransactionmanagerRecoveryNameCollision:               "The specified transaction manager was unable to create the objects contained in its log file in the Ob namespace. Therefore, the transaction manager was unable to recover.",
	StatusTransactionNotRoot:                                    "The call to create a superior enlistment on this transaction object could not be completed because the transaction object specified for the enlistment is a subordinate branch of the transaction. Only the root of the transaction can be enlisted as a superior.",
	StatusTransactionObjectExpired:                              "Because the associated transaction manager or resource manager has been closed, the handle is no longer valid.",
	StatusCompressionNotAllowedInTransaction:                    "The compression operation could not be completed because a transaction is active on the file.",
	StatusTransactionResponseNotEnlisted:                        "The specified operation could not be performed on this superior enlistment because the enlistment was not created with the corresponding completion response in the NotificationMask.",
	StatusTransactionRecordTooLong:                              "The specified operation could not be performed because the record to be logged was too long. This can occur because either there are too many enlistments on this transaction or the combined RecoveryInformation being logged on behalf of those enlistments is too long.",
	StatusNoLinkTrackingInTransaction:                           "The link-tracking operation could not be completed because a transaction is active.",
	StatusOperationNotSupportedInTransaction:                    "This operation cannot be performed in a transaction.",
	StatusTransactionIntegrityViolated:                          "The kernel transaction manager had to abort or forget the transaction because it blocked forward progress.",
	StatusExpiredHandle:                                         "The handle is no longer properly associated with its transaction.\u00a0 It may have been opened in a transactional resource manager that was subsequently forced to restart.\u00a0 Please close the handle and open a new one.",
	StatusTransactionNotEnlisted:                                "The specified operation could not be performed because the resource manager is not enlisted in the transaction.",
	StatusLogSectorInvalid:                                      "The log service found an invalid log sector.",
	StatusLogSectorParityInvalid:                                "The log service encountered a log sector with invalid block parity.",
	StatusLogSectorRemapped:                                     "The log service encountered a remapped log sector.",
	StatusLogBlockIncomplete:                                    "The log service encountered a partial or incomplete log block.",
	StatusLogInvalidRange:                                       "The log service encountered an attempt to access data outside the active log range.",
	StatusLogBlocksExhausted:                                    "The log service user-log marshaling buffers are exhausted.",
	StatusLogReadContextInvalid:                                 "The log service encountered an attempt to read from a marshaling area with an invalid read context.",
	StatusLogRestartInvalid:                                     "The log service encountered an invalid log restart area.",
	StatusLogBlockVersion:                                       "The log service encountered an invalid log block version.",
	StatusLogBlockInvalid:                                       "The log service encountered an invalid log block.",
	StatusLogReadModeInvalid:                                    "The log service encountered an attempt to read the log with an invalid read mode.",
	StatusLogMetadataCorrupt:                                    "The log service encountered a corrupted metadata file.",
	StatusLogMetadataInvalid:                                    "The log service encountered a metadata file that could not be created by the log file system.",
	StatusLogMetadataInconsistent:                               "The log service encountered a metadata file with inconsistent data.",
	StatusLogReservationInvalid:                                 "The log service encountered an attempt to erroneously allocate or dispose reservation space.",
	StatusLogCantDelete:                                         "The log service cannot delete the log file or the file system container.",
	StatusLogContainerLimitExceeded:                             "The log service has reached the maximum allowable containers allocated to a log file.",
	StatusLogStartOfLog:                                         "The log service has attempted to read or write backward past the start of the log.",
	StatusLogPolicyAlreadyInstalled:                             "The log policy could not be installed because a policy of the same type is already present.",
	StatusLogPolicyNotInstalled:                                 "The log policy in question was not installed at the time of the request.",
	StatusLogPolicyInvalid:                                      "The installed set of policies on the log is invalid.",
	StatusLogPolicyConflict:                                     "A policy on the log in question prevented the operation from completing.",
	StatusLogPinnedArchiveTail:                                  "The log space cannot be reclaimed because the log is pinned by the archive tail.",
	StatusLogRecordNonexistent:                                  "The log record is not a record in the log file.",
	StatusLogRecordsReservedInvalid:                             "The number of reserved log records or the adjustment of the number of reserved log records is invalid.",
	StatusLogSpaceReservedInvalid:                               "The reserved log space or the adjustment of the log space is invalid.",
	StatusLogTailInvalid:                                        "A new or existing archive tail or the base of the active log is invalid.",
	StatusLogFull:                                               "The log space is exhausted.",
	StatusLogMultiplexed:                                        "The log is multiplexed; no direct writes to the physical log are allowed.",
	StatusLogDedicated:                                          "The operation failed because the log is dedicated.",
	StatusLogArchiveNotInProgress:                               "The operation requires an archive context.",
	StatusLogArchiveInProgress:                                  "Log archival is in progress.",
	StatusLogEphemeral:                                          "The operation requires a nonephemeral log, but the log is ephemeral.",
	StatusLogNotEnoughContainers:                                "The log must have at least two containers before it can be read from or written to.",
	StatusLogClientAlreadyRegistered:                            "A log client has already registered on the stream.",
	StatusLogClientNotRegistered:                                "A log client has not been registered on the stream.",
	StatusLogFullHandlerInProgress:                              "A request has already been made to handle the log full condition.",
	StatusLogContainerReadFailed:                                "The log service encountered an error when attempting to read from a log container.",
	StatusLogContainerWriteFailed:                               "The log service encountered an error when attempting to write to a log container.",
	StatusLogContainerOpenFailed:                                "The log service encountered an error when attempting to open a log container.",
	StatusLogContainerStateInvalid:                              "The log service encountered an invalid container state when attempting a requested action.",
	StatusLogStateInvalid:                                       "The log service is not in the correct state to perform a requested action.",
	StatusLogPinned:                                             "The log space cannot be reclaimed because the log is pinned.",
	StatusLogMetadataFlushFailed:                                "The log metadata flush failed.",
	StatusLogInconsistentSecurity:                               "Security on the log and its containers is inconsistent.",
	StatusLogAppendedFlushFailed:                                "Records were appended to the log or reservation changes were made, but the log could not be flushed.",
	StatusLogPinnedReservation:                                  "The log is pinned due to reservation consuming most of the log space. Free some reserved records to make space available.",
	StatusVideoHungDisplayDriverThread:                          "{Display Driver Stopped Responding} The %hs display driver has stopped working normally. Save your work and reboot the system to restore full display functionality. The next time you reboot the computer, a dialog box will allow you to upload data about this failure to Microsoft.",
	StatusFltNoHandlerDefined:                                   "A handler was not defined by the filter for this operation.",
	StatusFltContextAlreadyDefined:                              "A context is already defined for this object.",
	StatusFltInvalidAsynchronousRequest:                         "Asynchronous requests are not valid for this operation.",
	StatusFltDisallowFastIo:                                     "This is an internal error code used by the filter manager to determine if a fast I/O operation should be forced down the input/output request packet (IRP) path. Minifilters should never return this value.",
	StatusFltInvalidNameRequest:                                 "An invalid name request was made. The name requested cannot be retrieved at this time.",
	StatusFltNotSafeToPostOperation:                             "Posting this operation to a worker thread for further processing is not safe at this time because it could lead to a system deadlock.",
	StatusFltNotInitialized:                                     "The Filter Manager was not initialized when a filter tried to register. Make sure that the Filter Manager is loaded as a driver.",
	StatusFltFilterNotReady:                                     "The filter is not ready for attachment to volumes because it has not finished initializing (FltStartFiltering has not been called).",
	StatusFltPostOperationCleanup:                               "The filter must clean up any operation-specific context at this time because it is being removed from the system before the operation is completed by the lower drivers.",
	StatusFltInternalError:                                      "The Filter Manager had an internal error from which it cannot recover; therefore, the operation has failed. This is usually the result of a filter returning an invalid value from a pre-operation callback.",
	StatusFltDeletingObject:                                     "The object specified for this action is in the process of being deleted; therefore, the action requested cannot be completed at this time.",
	StatusFltMustBeNonpagedPool:                                 "A nonpaged pool must be used for this type of context.",
	StatusFltDuplicateEntry:                                     "A duplicate handler definition has been provided for an operation.",
	StatusFltCbdqDisabled:                                       "The callback data queue has been disabled.",
	StatusFltDoNotAttach:                                        "Do not attach the filter to the volume at this time.",
	StatusFltDoNotDetach:                                        "Do not detach the filter from the volume at this time.",
	StatusFltInstanceAltitudeCollision:                          "An instance already exists at this altitude on the volume specified.",
	StatusFltInstanceNameCollision:                              "An instance already exists with this name on the volume specified.",
	StatusFltFilterNotFound:                                     "The system could not find the filter specified.",
	StatusFltVolumeNotFound:                                     "The system could not find the volume specified.",
	StatusFltInstanceNotFound:                                   "The system could not find the instance specified.",
	StatusFltContextAllocationNotFound:                          "No registered context allocation definition was found for the given request.",
	StatusFltInvalidContextRegistration:                         "An invalid parameter was specified during context registration.",
	StatusFltNameCacheMiss:                                      "The name requested was not found in the Filter Manager name cache and could not be retrieved from the file system.",
	StatusFltNoDeviceObject:                                     "The requested device object does not exist for the given volume.",
	StatusFltVolumeAlreadyMounted:                               "The specified volume is already mounted.",
	StatusFltAlreadyEnlisted:                                    "The specified transaction context is already enlisted in a transaction.",
	StatusFltContextAlreadyLinked:                               "The specified context is already attached to another object.",
	StatusFltNoWaiterForReply:                                   "No waiter is present for the filter's reply to this message.",
	StatusMonitorNoDescriptor:                                   "A monitor descriptor could not be obtained.",
	StatusMonitorUnknownDescriptorFormat:                        "This release does not support the format of the obtained monitor descriptor.",
	StatusMonitorInvalidDescriptorChecksum:                      "The checksum of the obtained monitor descriptor is invalid.",
	StatusMonitorInvalidStandardTimingBlock:                     "The monitor descriptor contains an invalid standard timing block.",
	StatusMonitorWmiDatablockRegistrationFailed:                 "WMI data-block registration failed for one of the MSMonitorClass WMI subclasses.",
	StatusMonitorInvalidSerialNumberMondscBlock:                 "The provided monitor descriptor block is either corrupted or does not contain the monitor's detailed serial number.",
	StatusMonitorInvalidUserFriendlyMondscBlock:                 "The provided monitor descriptor block is either corrupted or does not contain the monitor's user-friendly name.",
	StatusMonitorNoMoreDescriptorData:                           "There is no monitor descriptor data at the specified (offset or size) region.",
	StatusMonitorInvalidDetailedTimingBlock:                     "The monitor descriptor contains an invalid detailed timing block.",
	StatusMonitorInvalidManufactureDate:                         "Monitor descriptor contains invalid manufacture date.",
	StatusGraphicsNotExclusiveModeOwner:                         "Exclusive mode ownership is needed to create an unmanaged primary allocation.",
	StatusGraphicsInsufficientDmaBuffer:                         "The driver needs more DMA buffer space to complete the requested operation.",
	StatusGraphicsInvalidDisplayAdapter:                         "The specified display adapter handle is invalid.",
	StatusGraphicsAdapterWasReset:                               "The specified display adapter and all of its state have been reset.",
	StatusGraphicsInvalidDriverModel:                            "The driver stack does not match the expected driver model.",
	StatusGraphicsPresentModeChanged:                            "Present happened but ended up into the changed desktop mode.",
	StatusGraphicsPresentOccluded:                               "Nothing to present due to desktop occlusion.",
	StatusGraphicsPresentDenied:                                 "Not able to present due to denial of desktop access.",
	StatusGraphicsCannotcolorconvert:                            "Not able to present with color conversion.",
	StatusGraphicsPresentRedirectionDisabled:                    "Present redirection is disabled (desktop windowing management subsystem is off).",
	StatusGraphicsPresentUnoccluded:                             "Previous exclusive VidPn source owner has released its ownership",
	StatusGraphicsNoVideoMemory:                                 "Not enough video memory is available to complete the operation.",
	StatusGraphicsCantLockMemory:                                "Could not probe and lock the underlying memory of an allocation.",
	StatusGraphicsAllocationBusy:                                "The allocation is currently busy.",
	StatusGraphicsTooManyReferences:                             "An object being referenced has already reached the maximum reference count and cannot be referenced further.",
	StatusGraphicsTryAgainLater:                                 "A problem could not be solved due to an existing condition. Try again later.",
	StatusGraphicsTryAgainNow:                                   "A problem could not be solved due to an existing condition. Try again now.",
	StatusGraphicsAllocationInvalid:                             "The allocation is invalid.",
	StatusGraphicsUnswizzlingApertureUnavailable:                "No more unswizzling apertures are currently available.",
	StatusGraphicsUnswizzlingApertureUnsupported:                "The current allocation cannot be unswizzled by an aperture.",
	StatusGraphicsCantEvictPinnedAllocation:                     "The request failed because a pinned allocation cannot be evicted.",
	StatusGraphicsInvalidAllocationUsage:                        "The allocation cannot be used from its current segment location for the specified operation.",
	StatusGraphicsCantRenderLockedAllocation:                    "A locked allocation cannot be used in the current command buffer.",
	StatusGraphicsAllocationClosed:                              "The allocation being referenced has been closed permanently.",
	StatusGraphicsInvalidAllocationInstance:                     "An invalid allocation instance is being referenced.",
	StatusGraphicsInvalidAllocationHandle:                       "An invalid allocation handle is being referenced.",
	StatusGraphicsWrongAllocationDevice:                         "The allocation being referenced does not belong to the current device.",
	StatusGraphicsAllocationContentLost:                         "The specified allocation lost its content.",
	StatusGraphicsGpuExceptionOnDevice:                          "A GPU exception was detected on the given device. The device cannot be scheduled.",
	StatusGraphicsInvalidVidpnTopology:                          "The specified VidPN topology is invalid.",
	StatusGraphicsVidpnTopologyNotSupported:                     "The specified VidPN topology is valid but is not supported by this model of the display adapter.",
	StatusGraphicsVidpnTopologyCurrentlyNotSupported:            "The specified VidPN topology is valid but is not currently supported by the display adapter due to allocation of its resources.",
	StatusGraphicsInvalidVidpn:                                  "The specified VidPN handle is invalid.",
	StatusGraphicsInvalidVideoPresentSource:                     "The specified video present source is invalid.",
	StatusGraphicsInvalidVideoPresentTarget:                     "The specified video present target is invalid.",
	StatusGraphicsVidpnModalityNotSupported:                     "The specified VidPN modality is not supported (for example, at least two of the pinned modes are not co-functional).",
	StatusGraphicsInvalidVidpnSourcemodeset:                     "The specified VidPN source mode set is invalid.",
	StatusGraphicsInvalidVidpnTargetmodeset:                     "The specified VidPN target mode set is invalid.",
	StatusGraphicsInvalidFrequency:                              "The specified video signal frequency is invalid.",
	StatusGraphicsInvalidActiveRegion:                           "The specified video signal active region is invalid.",
	StatusGraphicsInvalidTotalRegion:                            "The specified video signal total region is invalid.",
	StatusGraphicsInvalidVideoPresentSourceMode:                 "The specified video present source mode is invalid.",
	StatusGraphicsInvalidVideoPresentTargetMode:                 "The specified video present target mode is invalid.",
	StatusGraphicsPinnedModeMustRemainInSet:                     "The pinned mode must remain in the set on the VidPN's co-functional modality enumeration.",
	StatusGraphicsPathAlreadyInTopology:                         "The specified video present path is already in the VidPN's topology.",
	StatusGraphicsModeAlreadyInModeset:                          "The specified mode is already in the mode set.",
	StatusGraphicsInvalidVideopresentsourceset:                  "The specified video present source set is invalid.",
	StatusGraphicsInvalidVideopresenttargetset:                  "The specified video present target set is invalid.",
	StatusGraphicsSourceAlreadyInSet:                            "The specified video present source is already in the video present source set.",
	StatusGraphicsTargetAlreadyInSet:                            "The specified video present target is already in the video present target set.",
	StatusGraphicsInvalidVidpnPresentPath:                       "The specified VidPN present path is invalid.",
	StatusGraphicsNoRecommendedVidpnTopology:                    "The miniport has no recommendation for augmenting the specified VidPN's topology.",
	StatusGraphicsInvalidMonitorFrequencyrangeset:               "The specified monitor frequency range set is invalid.",
	StatusGraphicsInvalidMonitorFrequencyrange:                  "The specified monitor frequency range is invalid.",
	StatusGraphicsFrequencyrangeNotInSet:                        "The specified frequency range is not in the specified monitor frequency range set.",
	StatusGraphicsFrequencyrangeAlreadyInSet:                    "The specified frequency range is already in the specified monitor frequency range set.",
	StatusGraphicsStaleModeset:                                  "The specified mode set is stale. Reacquire the new mode set.",
	StatusGraphicsInvalidMonitorSourcemodeset:                   "The specified monitor source mode set is invalid.",
	StatusGraphicsInvalidMonitorSourceMode:                      "The specified monitor source mode is invalid.",
	StatusGraphicsNoRecommendedFunctionalVidpn:                  "The miniport does not have a recommendation regarding the request to provide a functional VidPN given the current display adapter configuration.",
	StatusGraphicsModeIdMustBeUnique:                            "The ID of the specified mode is being used by another mode in the set.",
	StatusGraphicsEmptyAdapterMonitorModeSupportIntersection:    "The system failed to determine a mode that is supported by both the display adapter and the monitor connected to it.",
	StatusGraphicsVideoPresentTargetsLessThanSources:            "The number of video present targets must be greater than or equal to the number of video present sources.",
	StatusGraphicsPathNotInTopology:                             "The specified present path is not in the VidPN's topology.",
	StatusGraphicsAdapterMustHaveAtLeastOneSource:               "The display adapter must have at least one video present source.",
	StatusGraphicsAdapterMustHaveAtLeastOneTarget:               "The display adapter must have at least one video present target.",
	StatusGraphicsInvalidMonitordescriptorset:                   "The specified monitor descriptor set is invalid.",
	StatusGraphicsInvalidMonitordescriptor:                      "The specified monitor descriptor is invalid.",
	StatusGraphicsMonitordescriptorNotInSet:                     "The specified descriptor is not in the specified monitor descriptor set.",
	StatusGraphicsMonitordescriptorAlreadyInSet:                 "The specified descriptor is already in the specified monitor descriptor set.",
	StatusGraphicsMonitordescriptorIdMustBeUnique:               "The ID of the specified monitor descriptor is being used by another descriptor in the set.",
	StatusGraphicsInvalidVidpnTargetSubsetType:                  "The specified video present target subset type is invalid.",
	StatusGraphicsResourcesNotRelated:                           "Two or more of the specified resources are not related to each other, as defined by the interface semantics.",
	StatusGraphicsSourceIdMustBeUnique:                          "The ID of the specified video present source is being used by another source in the set.",
	StatusGraphicsTargetIdMustBeUnique:                          "The ID of the specified video present target is being used by another target in the set.",
	StatusGraphicsNoAvailableVidpnTarget:                        "The specified VidPN source cannot be used because there is no available VidPN target to connect it to.",
	StatusGraphicsMonitorCouldNotBeAssociatedWithAdapter:        "The newly arrived monitor could not be associated with a display adapter.",
	StatusGraphicsNoVidpnmgr:                                    "The particular display adapter does not have an associated VidPN manager.",
	StatusGraphicsNoActiveVidpn:                                 "The VidPN manager of the particular display adapter does not have an active VidPN.",
	StatusGraphicsStaleVidpnTopology:                            "The specified VidPN topology is stale; obtain the new topology.",
	StatusGraphicsMonitorNotConnected:                           "No monitor is connected on the specified video present target.",
	StatusGraphicsSourceNotInTopology:                           "The specified source is not part of the specified VidPN's topology.",
	StatusGraphicsInvalidPrimarysurfaceSize:                     "The specified primary surface size is invalid.",
	StatusGraphicsInvalidVisibleregionSize:                      "The specified visible region size is invalid.",
	StatusGraphicsInvalidStride:                                 "The specified stride is invalid.",
	StatusGraphicsInvalidPixelformat:                            "The specified pixel format is invalid.",
	StatusGraphicsInvalidColorbasis:                             "The specified color basis is invalid.",
	StatusGraphicsInvalidPixelvalueaccessmode:                   "The specified pixel value access mode is invalid.",
	StatusGraphicsTargetNotInTopology:                           "The specified target is not part of the specified VidPN's topology.",
	StatusGraphicsNoDisplayModeManagementSupport:                "Failed to acquire the display mode management interface.",
	StatusGraphicsVidpnSourceInUse:                              "The specified VidPN source is already owned by a DMM client and cannot be used until that client releases it.",
	StatusGraphicsCantAccessActiveVidpn:                         "The specified VidPN is active and cannot be accessed.",
	StatusGraphicsInvalidPathImportanceOrdinal:                  "The specified VidPN's present path importance ordinal is invalid.",
	StatusGraphicsInvalidPathContentGeometryTransformation:      "The specified VidPN's present path content geometry transformation is invalid.",
	StatusGraphicsPathContentGeometryTransformationNotSupported: "The specified content geometry transformation is not supported on the respective VidPN present path.",
	StatusGraphicsInvalidGammaRamp:                              "The specified gamma ramp is invalid.",
	StatusGraphicsGammaRampNotSupported:                         "The specified gamma ramp is not supported on the respective VidPN present path.",
	StatusGraphicsMultisamplingNotSupported:                     "Multisampling is not supported on the respective VidPN present path.",
	StatusGraphicsModeNotInModeset:                              "The specified mode is not in the specified mode set.",
	StatusGraphicsInvalidVidpnTopologyRecommendationReason:      "The specified VidPN topology recommendation reason is invalid.",
	StatusGraphicsInvalidPathContentType:                        "The specified VidPN present path content type is invalid.",
	StatusGraphicsInvalidCopyprotectionType:                     "The specified VidPN present path copy protection type is invalid.",
	StatusGraphicsUnassignedModesetAlreadyExists:                "Only one unassigned mode set can exist at any one time for a particular VidPN source or target.",
	StatusGraphicsInvalidScanlineOrdering:                       "The specified scan line ordering type is invalid.",
	StatusGraphicsTopologyChangesNotAllowed:                     "The topology changes are not allowed for the specified VidPN.",
	StatusGraphicsNoAvailableImportanceOrdinals:                 "All available importance ordinals are being used in the specified topology.",
	StatusGraphicsIncompatiblePrivateFormat:                     "The specified primary surface has a different private-format attribute than the current primary surface.",
	StatusGraphicsInvalidModePruningAlgorithm:                   "The specified mode-pruning algorithm is invalid.",
	StatusGraphicsInvalidMonitorCapabilityOrigin:                "The specified monitor-capability origin is invalid.",
	StatusGraphicsInvalidMonitorFrequencyrangeConstraint:        "The specified monitor-frequency range constraint is invalid.",
	StatusGraphicsMaxNumPathsReached:                            "The maximum supported number of present paths has been reached.",
	StatusGraphicsCancelVidpnTopologyAugmentation:               "The miniport requested that augmentation be canceled for the specified source of the specified VidPN's topology.",
	StatusGraphicsInvalidClientType:                             "The specified client type was not recognized.",
	StatusGraphicsClientvidpnNotSet:                             "The client VidPN is not set on this adapter (for example, no user mode-initiated mode changes have taken place on this adapter).",
	StatusGraphicsSpecifiedChildAlreadyConnected:                "The specified display adapter child device already has an external device connected to it.",
	StatusGraphicsChildDescriptorNotSupported:                   "The display adapter child device does not support reporting a descriptor.",
	StatusGraphicsNotALinkedAdapter:                             "The display adapter is not linked to any other adapters.",
	StatusGraphicsLeadlinkNotEnumerated:                         "The lead adapter in a linked configuration was not enumerated yet.",
	StatusGraphicsChainlinksNotEnumerated:                       "Some chain adapters in a linked configuration have not yet been enumerated.",
	StatusGraphicsAdapterChainNotReady:                          "The chain of linked adapters is not ready to start because of an unknown failure.",
	StatusGraphicsChainlinksNotStarted:                          "An attempt was made to start a lead link display adapter when the chain links had not yet started.",
	StatusGraphicsChainlinksNotPoweredOn:                        "An attempt was made to turn on a lead link display adapter when the chain links were turned off.",
	StatusGraphicsInconsistentDeviceLinkState:                   "The adapter link was found in an inconsistent state. Not all adapters are in an expected PNP/power state.",
	StatusGraphicsNotPostDeviceDriver:                           "The driver trying to start is not the same as the driver for the posted display adapter.",
	StatusGraphicsAdapterAccessNotExcluded:                      "An operation is being attempted that requires the display adapter to be in a quiescent state.",
	StatusGraphicsOpmNotSupported:                               "The driver does not support OPM.",
	StatusGraphicsCoppNotSupported:                              "The driver does not support COPP.",
	StatusGraphicsUabNotSupported:                               "The driver does not support UAB.",
	StatusGraphicsOpmInvalidEncryptedParameters:                 "The specified encrypted parameters are invalid.",
	StatusGraphicsOpmParameterArrayTooSmall:                     "An array passed to a function cannot hold all of the data that the function wants to put in it.",
	StatusGraphicsOpmNoProtectedOutputsExist:                    "The GDI display device passed to this function does not have any active protected outputs.",
	StatusGraphicsPvpNoDisplayDeviceCorrespondsToName:           "The PVP cannot find an actual GDI display device that corresponds to the passed-in GDI display device name.",
	StatusGraphicsPvpDisplayDeviceNotAttachedToDesktop:          "This function failed because the GDI display device passed to it was not attached to the Windows desktop.",
	StatusGraphicsPvpMirroringDevicesNotSupported:               "The PVP does not support mirroring display devices because they do not have any protected outputs.",
	StatusGraphicsOpmInvalidPointer:                             "The function failed because an invalid pointer parameter was passed to it. A pointer parameter is invalid if it is null, is not correctly aligned, or it points to an invalid address or a kernel mode address.",
	StatusGraphicsOpmInternalError:                              "An internal error caused an operation to fail.",
	StatusGraphicsOpmInvalidHandle:                              "The function failed because the caller passed in an invalid OPM user-mode handle.",
	StatusGraphicsPvpNoMonitorsCorrespondToDisplayDevice:        "This function failed because the GDI device passed to it did not have any monitors associated with it.",
	StatusGraphicsPvpInvalidCertificateLength:                   "A certificate could not be returned because the certificate buffer passed to the function was too small.",
	StatusGraphicsOpmSpanningModeEnabled:                        "DxgkDdiOpmCreateProtectedOutput() could not create a protected output because the video present yarget is in spanning mode.",
	StatusGraphicsOpmTheaterModeEnabled:                         "DxgkDdiOpmCreateProtectedOutput() could not create a protected output because the video present target is in theater mode.",
	StatusGraphicsPvpHfsFailed:                                  "The function call failed because the display adapter's hardware functionality scan (HFS) failed to validate the graphics hardware.",
	StatusGraphicsOpmInvalidSrm:                                 "The HDCP SRM passed to this function did not comply with section 5 of the HDCP 1.1 specification.",
	StatusGraphicsOpmOutputDoesNotSupportHdcp:                   "The protected output cannot enable the HDCP system because it does not support it.",
	StatusGraphicsOpmOutputDoesNotSupportAcp:                    "The protected output cannot enable analog copy protection because it does not support it.",
	StatusGraphicsOpmOutputDoesNotSupportCgmsa:                  "The protected output cannot enable the CGMS-A protection technology because it does not support it.",
	StatusGraphicsOpmHdcpSrmNeverSet:                            "DxgkDdiOPMGetInformation() cannot return the version of the SRM being used because the application never successfully passed an SRM to the protected output.",
	StatusGraphicsOpmResolutionTooHigh:                          "DxgkDdiOPMConfigureProtectedOutput() cannot enable the specified output protection technology because the output's screen resolution is too high.",
	StatusGraphicsOpmAllHdcpHardwareAlreadyInUse:                "DxgkDdiOPMConfigureProtectedOutput() cannot enable HDCP because other physical outputs are using the display adapter's HDCP hardware.",
	StatusGraphicsOpmProtectedOutputNoLongerExists:              "The operating system asynchronously destroyed this OPM-protected output because the operating system state changed. This error typically occurs because the monitor PDO associated with this protected output was removed or stopped, the protected output's session became a nonconsole session, or the protected output's desktop became inactive.",
	StatusGraphicsOpmSessionTypeChangeInProgress:                "OPM functions cannot be called when a session is changing its type. Three types of sessions currently exist: console, disconnected, and remote (RDP or ICA).",
	StatusGraphicsOpmProtectedOutputDoesNotHaveCoppSemantics:    "The DxgkDdiOPMGetCOPPCompatibleInformation, DxgkDdiOPMGetInformation, or DxgkDdiOPMConfigureProtectedOutput function failed. This error is returned only if a protected output has OPM semantics. DxgkDdiOPMGetCOPPCompatibleInformation always returns this error if a protected output has OPM semantics.DxgkDdiOPMGetInformation returns this error code if the caller requested COPP-specific information.DxgkDdiOPMConfigureProtectedOutput returns this error when the caller tries to use a COPP-specific command.",
	StatusGraphicsOpmInvalidInformationRequest:                  "The DxgkDdiOPMGetInformation and DxgkDdiOPMGetCOPPCompatibleInformation functions return this error code if the passed-in sequence number is not the expected sequence number or the passed-in OMAC value is invalid.",
	StatusGraphicsOpmDriverInternalError:                        "The function failed because an unexpected error occurred inside a display driver.",
	StatusGraphicsOpmProtectedOutputDoesNotHaveOpmSemantics:     "The DxgkDdiOPMGetCOPPCompatibleInformation, DxgkDdiOPMGetInformation, or DxgkDdiOPMConfigureProtectedOutput function failed. This error is returned only if a protected output has COPP semantics. DxgkDdiOPMGetCOPPCompatibleInformation returns this error code if the caller requested OPM-specific information.DxgkDdiOPMGetInformation always returns this error if a protected output has COPP semantics.DxgkDdiOPMConfigureProtectedOutput returns this error when the caller tries to use an OPM-specific command.",
	StatusGraphicsOpmSignalingNotSupported:                      "The DxgkDdiOPMGetCOPPCompatibleInformation and DxgkDdiOPMConfigureProtectedOutput functions return this error if the display driver does not support the DXGKMDT_OPM_GET_ACP_AND_CGMSA_SIGNALING and DXGKMDT_OPM_SET_ACP_AND_CGMSA_SIGNALING GUIDs.",
	StatusGraphicsOpmInvalidConfigurationRequest:                "The DxgkDdiOPMConfigureProtectedOutput function returns this error code if the passed-in sequence number is not the expected sequence number or the passed-in OMAC value is invalid.",
	StatusGraphicsI2cNotSupported:                               "The monitor connected to the specified video output does not have an I2C bus.",
	StatusGraphicsI2cDeviceDoesNotExist:                         "No device on the I2C bus has the specified address.",
	StatusGraphicsI2cErrorTransmittingData:                      "An error occurred while transmitting data to the device on the I2C bus.",
	StatusGraphicsI2cErrorReceivingData:                         "An error occurred while receiving data from the device on the I2C bus.",
	StatusGraphicsDdcciVcpNotSupported:                          "The monitor does not support the specified VCP code.",
	StatusGraphicsDdcciInvalidData:                              "The data received from the monitor is invalid.",
	StatusGraphicsDdcciMonitorReturnedInvalidTimingStatusByte:   "A function call failed because a monitor returned an invalid timing status byte when the operating system used the DDC/CI get timing report and timing message command to get a timing report from a monitor.",
	StatusGraphicsDdcciInvalidCapabilitiesString:                "A monitor returned a DDC/CI capabilities string that did not comply with the ACCESS.bus 3.0, DDC/CI 1.1, or MCCS 2 Revision 1 specification.",
	StatusGraphicsMcaInternalError:                              "An internal error caused an operation to fail.",
	StatusGraphicsDdcciInvalidMessageCommand:                    "An operation failed because a DDC/CI message had an invalid value in its command field.",
	StatusGraphicsDdcciInvalidMessageLength:                     "This error occurred because a DDC/CI message had an invalid value in its length field.",
	StatusGraphicsDdcciInvalidMessageChecksum:                   "This error occurred because the value in a DDC/CI message's checksum field did not match the message's computed checksum value. This error implies that the data was corrupted while it was being transmitted from a monitor to a computer.",
	StatusGraphicsInvalidPhysicalMonitorHandle:                  "This function failed because an invalid monitor handle was passed to it.",
	StatusGraphicsMonitorNoLongerExists:                         "The operating system asynchronously destroyed the monitor that corresponds to this handle because the operating system's state changed. This error typically occurs because the monitor PDO associated with this handle was removed or stopped, or a display mode change occurred. A display mode change occurs when Windows sends a WM_DISPLAYCHANGE message to applications.",
	StatusGraphicsOnlyConsoleSessionSupported:                   "This function can be used only if a program is running in the local console session. It cannot be used if a program is running on a remote desktop session or on a terminal server session.",
	StatusGraphicsNoDisplayDeviceCorrespondsToName:              "This function cannot find an actual GDI display device that corresponds to the specified GDI display device name.",
	StatusGraphicsDisplayDeviceNotAttachedToDesktop:             "The function failed because the specified GDI display device was not attached to the Windows desktop.",
	StatusGraphicsMirroringDevicesNotSupported:                  "This function does not support GDI mirroring display devices because GDI mirroring display devices do not have any physical monitors associated with them.",
	StatusGraphicsInvalidPointer:                                "The function failed because an invalid pointer parameter was passed to it. A pointer parameter is invalid if it is null, is not correctly aligned, or points to an invalid address or to a kernel mode address.",
	StatusGraphicsNoMonitorsCorrespondToDisplayDevice:           "This function failed because the GDI device passed to it did not have a monitor associated with it.",
	StatusGraphicsParameterArrayTooSmall:                        "An array passed to the function cannot hold all of the data that the function must copy into the array.",
	StatusGraphicsInternalError:                                 "An internal error caused an operation to fail.",
	StatusGraphicsSessionTypeChangeInProgress:                   "The function failed because the current session is changing its type. This function cannot be called when the current session is changing its type. Three types of sessions currently exist: console, disconnected, and remote (RDP or ICA).",
	StatusFveLockedVolume:                                       "The volume must be unlocked before it can be used.",
	StatusFveNotEncrypted:                                       "The volume is fully decrypted and no key is available.",
	StatusFveBadInformation:                                     "The control block for the encrypted volume is not valid.",
	StatusFveTooSmall:                                           "Not enough free space remains on the volume to allow encryption.",
	StatusFveFailedWrongFs:                                      "The partition cannot be encrypted because the file system is not supported.",
	StatusFveFailedBadFs:                                        "The file system is inconsistent. Run the Check Disk utility.",
	StatusFveFsNotExtended:                                      "The file system does not extend to the end of the volume.",
	StatusFveFsMounted:                                          "This operation cannot be performed while a file system is mounted on the volume.",
	StatusFveNoLicense:                                          "BitLocker Drive Encryption is not included with this version of Windows.",
	StatusFveActionNotAllowed:                                   "The requested action was denied by the FVE control engine.",
	StatusFveBadData:                                            "The data supplied is malformed.",
	StatusFveVolumeNotBound:                                     "The volume is not bound to the system.",
	StatusFveNotDataVolume:                                      "The volume specified is not a data volume.",
	StatusFveConvReadError:                                      "A read operation failed while converting the volume.",
	StatusFveConvWriteError:                                     "A write operation failed while converting the volume.",
	StatusFveOverlappedUpdate:                                   "The control block for the encrypted volume was updated by another thread. Try again.",
	StatusFveFailedSectorSize:                                   "The volume encryption algorithm cannot be used on this sector size.",
	StatusFveFailedAuthentication:                               "BitLocker recovery authentication failed.",
	StatusFveNotOsVolume:                                        "The volume specified is not the boot operating system volume.",
	StatusFveKeyfileNotFound:                                    "The BitLocker startup key or recovery password could not be read from external media.",
	StatusFveKeyfileInvalid:                                     "The BitLocker startup key or recovery password file is corrupt or invalid.",
	StatusFveKeyfileNoVmk:                                       "The BitLocker encryption key could not be obtained from the startup key or the recovery password.",
	StatusFveTpmDisabled:                                        "The TPM is disabled.",
	StatusFveTpmSrkAuthNotZero:                                  "The authorization data for the SRK of the TPM is not zero.",
	StatusFveTpmInvalidPcr:                                      "The system boot information changed or the TPM locked out access to BitLocker encryption keys until the computer is restarted.",
	StatusFveTpmNoVmk:                                           "The BitLocker encryption key could not be obtained from the TPM.",
	StatusFvePinInvalid:                                         "The BitLocker encryption key could not be obtained from the TPM and PIN.",
	StatusFveAuthInvalidApplication:                             "A boot application hash does not match the hash computed when BitLocker was turned on.",
	StatusFveAuthInvalidConfig:                                  "The Boot Configuration Data (BCD) settings are not supported or have changed because BitLocker was enabled.",
	StatusFveDebuggerEnabled:                                    "Boot debugging is enabled. Run Windows Boot Configuration Data Store Editor (bcdedit.exe) to turn it off.",
	StatusFveDryRunFailed:                                       "The BitLocker encryption key could not be obtained.",
	StatusFveBadMetadataPointer:                                 "The metadata disk region pointer is incorrect.",
	StatusFveOldMetadataCopy:                                    "The backup copy of the metadata is out of date.",
	StatusFveRebootRequired:                                     "No action was taken because a system restart is required.",
	StatusFveRawAccess:                                          "No action was taken because BitLocker Drive Encryption is in RAW access mode.",
	StatusFveRawBlocked:                                         "BitLocker Drive Encryption cannot enter RAW access mode for this volume.",
	StatusFveNoFeatureLicense:                                   "This feature of BitLocker Drive Encryption is not included with this version of Windows.",
	StatusFvePolicyUserDisableRdvNotAllowed:                     "Group policy does not permit turning off BitLocker Drive Encryption on roaming data volumes.",
	StatusFveConvRecoveryFailed:                                 "Bitlocker Drive Encryption failed to recover from aborted conversion. This could be due to either all conversion logs being corrupted or the media being write-protected.",
	StatusFveVirtualizedSpaceTooBig:                             "The requested virtualization size is too big.",
	StatusFveVolumeTooSmall:                                     "The drive is too small to be protected using BitLocker Drive Encryption.",
	StatusFwpCalloutNotFound:                                    "The callout does not exist.",
	StatusFwpConditionNotFound:                                  "The filter condition does not exist.",
	StatusFwpFilterNotFound:                                     "The filter does not exist.",
	StatusFwpLayerNotFound:                                      "The layer does not exist.",
	StatusFwpProviderNotFound:                                   "The provider does not exist.",
	StatusFwpProviderContextNotFound:                            "The provider context does not exist.",
	StatusFwpSublayerNotFound:                                   "The sublayer does not exist.",
	StatusFwpNotFound:                                           "The object does not exist.",
	StatusFwpAlreadyExists:                                      "An object with that GUID or LUID already exists.",
	StatusFwpInUse:                                              "The object is referenced by other objects and cannot be deleted.",
	StatusFwpDynamicSessionInProgress:                           "The call is not allowed from within a dynamic session.",
	StatusFwpWrongSession:                                       "The call was made from the wrong session and cannot be completed.",
	StatusFwpNoTxnInProgress:                                    "The call must be made from within an explicit transaction.",
	StatusFwpTxnInProgress:                                      "The call is not allowed from within an explicit transaction.",
	StatusFwpTxnAborted:                                         "The explicit transaction has been forcibly canceled.",
	StatusFwpSessionAborted:                                     "The session has been canceled.",
	StatusFwpIncompatibleTxn:                                    "The call is not allowed from within a read-only transaction.",
	StatusFwpTimeout:                                            "The call timed out while waiting to acquire the transaction lock.",
	StatusFwpNetEventsDisabled:                                  "The collection of network diagnostic events is disabled.",
	StatusFwpIncompatibleLayer:                                  "The operation is not supported by the specified layer.",
	StatusFwpKmClientsOnly:                                      "The call is allowed for kernel-mode callers only.",
	StatusFwpLifetimeMismatch:                                   "The call tried to associate two objects with incompatible lifetimes.",
	StatusFwpBuiltinObject:                                      "The object is built-in and cannot be deleted.",
	StatusFwpTooManyBoottimeFilters:                             "The maximum number of boot-time filters has been reached.",
	StatusFwpNotificationDropped:                                "A notification could not be delivered because a message queue has reached maximum capacity.",
	StatusFwpTrafficMismatch:                                    "The traffic parameters do not match those for the security association context.",
	StatusFwpIncompatibleSaState:                                "The call is not allowed for the current security association state.",
	StatusFwpNullPointer:                                        "A required pointer is null.",
	StatusFwpInvalidEnumerator:                                  "An enumerator is not valid.",
	StatusFwpInvalidFlags:                                       "The flags field contains an invalid value.",
	StatusFwpInvalidNetMask:                                     "A network mask is not valid.",
	StatusFwpInvalidRange:                                       "An FWP_RANGE is not valid.",
	StatusFwpInvalidInterval:                                    "The time interval is not valid.",
	StatusFwpZeroLengthArray:                                    "An array that must contain at least one element has a zero length.",
	StatusFwpNullDisplayName:                                    "The displayData.name field cannot be null.",
	StatusFwpInvalidActionType:                                  "The action type is not one of the allowed action types for a filter.",
	StatusFwpInvalidWeight:                                      "The filter weight is not valid.",
	StatusFwpMatchTypeMismatch:                                  "A filter condition contains a match type that is not compatible with the operands.",
	StatusFwpTypeMismatch:                                       "An FWP_VALUE or FWPM_CONDITION_VALUE is of the wrong type.",
	StatusFwpOutOfBounds:                                        "An integer value is outside the allowed range.",
	StatusFwpReserved:                                           "A reserved field is nonzero.",
	StatusFwpDuplicateCondition:                                 "A filter cannot contain multiple conditions operating on a single field.",
	StatusFwpDuplicateKeymod:                                    "A policy cannot contain the same keying module more than once.",
	StatusFwpActionIncompatibleWithLayer:                        "The action type is not compatible with the layer.",
	StatusFwpActionIncompatibleWithSublayer:                     "The action type is not compatible with the sublayer.",
	StatusFwpContextIncompatibleWithLayer:                       "The raw context or the provider context is not compatible with the layer.",
	StatusFwpContextIncompatibleWithCallout:                     "The raw context or the provider context is not compatible with the callout.",
	StatusFwpIncompatibleAuthMethod:                             "The authentication method is not compatible with the policy type.",
	StatusFwpIncompatibleDhGroup:                                "The Diffie-Hellman group is not compatible with the policy type.",
	StatusFwpEmNotSupported:                                     "An IKE policy cannot contain an Extended Mode policy.",
	StatusFwpNeverMatch:                                         "The enumeration template or subscription will never match any objects.",
	StatusFwpProviderContextMismatch:                            "The provider context is of the wrong type.",
	StatusFwpInvalidParameter:                                   "The parameter is incorrect.",
	StatusFwpTooManySublayers:                                   "The maximum number of sublayers has been reached.",
	StatusFwpCalloutNotificationFailed:                          "The notification function for a callout returned an error.",
	StatusFwpIncompatibleAuthConfig:                             "The IPsec authentication configuration is not compatible with the authentication type.",
	StatusFwpIncompatibleCipherConfig:                           "The IPsec cipher configuration is not compatible with the cipher type.",
	StatusFwpDuplicateAuthMethod:                                "A policy cannot contain the same auth method more than once.",
	StatusFwpTcpipNotReady:                                      "The TCP/IP stack is not ready.",
	StatusFwpInjectHandleClosing:                                "The injection handle is being closed by another thread.",
	StatusFwpInjectHandleStale:                                  "The injection handle is stale.",
	StatusFwpCannotPend:                                         "The classify cannot be pended.",
	StatusNdisClosing:                                           "The binding to the network interface is being closed.",
	StatusNdisBadVersion:                                        "An invalid version was specified.",
	StatusNdisBadCharacteristics:                                "An invalid characteristics table was used.",
	StatusNdisAdapterNotFound:                                   "Failed to find the network interface or the network interface is not ready.",
	StatusNdisOpenFailed:                                        "Failed to open the network interface.",
	StatusNdisDeviceFailed:                                      "The network interface has encountered an internal unrecoverable failure.",
	StatusNdisMulticastFull:                                     "The multicast list on the network interface is full.",
	StatusNdisMulticastExists:                                   "An attempt was made to add a duplicate multicast address to the list.",
	StatusNdisMulticastNotFound:                                 "At attempt was made to remove a multicast address that was never added.",
	StatusNdisRequestAborted:                                    "The network interface aborted the request.",
	StatusNdisResetInProgress:                                   "The network interface cannot process the request because it is being reset.",
	StatusNdisInvalidPacket:                                     "An attempt was made to send an invalid packet on a network interface.",
	StatusNdisInvalidDeviceRequest:                              "The specified request is not a valid operation for the target device.",
	StatusNdisAdapterNotReady:                                   "The network interface is not ready to complete this operation.",
	StatusNdisInvalidLength:                                     "The length of the buffer submitted for this operation is not valid.",
	StatusNdisInvalidData:                                       "The data used for this operation is not valid.",
	StatusNdisBufferTooShort:                                    "The length of the submitted buffer for this operation is too small.",
	StatusNdisInvalidOid:                                        "The network interface does not support this object identifier.",
	StatusNdisAdapterRemoved:                                    "The network interface has been removed.",
	StatusNdisUnsupportedMedia:                                  "The network interface does not support this media type.",
	StatusNdisGroupAddressInUse:                                 "An attempt was made to remove a token ring group address that is in use by other components.",
	StatusNdisFileNotFound:                                      "An attempt was made to map a file that cannot be found.",
	StatusNdisErrorReadingFile:                                  "An error occurred while NDIS tried to map the file.",
	StatusNdisAlreadyMapped:                                     "An attempt was made to map a file that is already mapped.",
	StatusNdisResourceConflict:                                  "An attempt to allocate a hardware resource failed because the resource is used by another component.",
	StatusNdisMediaDisconnected:                                 "The I/O operation failed because the network media is disconnected or the wireless access point is out of range.",
	StatusNdisInvalidAddress:                                    "The network address used in the request is invalid.",
	StatusNdisPaused:                                            "The offload operation on the network interface has been paused.",
	StatusNdisInterfaceNotFound:                                 "The network interface was not found.",
	StatusNdisUnsupportedRevision:                               "The revision number specified in the structure is not supported.",
	StatusNdisInvalidPort:                                       "The specified port does not exist on this network interface.",
	StatusNdisInvalidPortState:                                  "The current state of the specified port on this network interface does not support the requested operation.",
	StatusNdisLowPowerState:                                     "The miniport adapter is in a lower power state.",
	StatusNdisNotSupported:                                      "The network interface does not support this request.",
	StatusNdisOffloadPolicy:                                     "The TCP connection is not offloadable because of a local policy setting.",
	StatusNdisOffloadConnectionRejected:                         "The TCP connection is not offloadable by the Chimney offload target.",
	StatusNdisOffloadPathRejected:                               "The IP Path object is not in an offloadable state.",
	StatusNdisDot11AutoConfigEnabled:                            "The wireless LAN interface is in auto-configuration mode and does not support the requested parameter change operation.",
	StatusNdisDot11MediaInUse:                                   "The wireless LAN interface is busy and cannot perform the requested operation.",
	StatusNdisDot11PowerStateInvalid:                            "The wireless LAN interface is power down and does not support the requested operation.",
	StatusNdisPmWolPatternListFull:                              "The list of wake on LAN patterns is full.",
	StatusNdisPmProtocolOffloadListFull:                         "The list of low power protocol offloads is full.",
	StatusIpsecBadSpi:                                           "The SPI in the packet does not match a valid IPsec SA.",
	StatusIpsecSaLifetimeExpired:                                "The packet was received on an IPsec SA whose lifetime has expired.",
	StatusIpsecWrongSa:                                          "The packet was received on an IPsec SA that does not match the packet characteristics.",
	StatusIpsecReplayCheckFailed:                                "The packet sequence number replay check failed.",
	StatusIpsecInvalidPacket:                                    "The IPsec header and/or trailer in the packet is invalid.",
	StatusIpsecIntegrityCheckFailed:                             "The IPsec integrity check failed.",
	StatusIpsecClearTextDrop:                                    "IPsec dropped a clear text packet.",
	StatusIpsecAuthFirewallDrop:                                 "IPsec dropped an incoming ESP packet in authenticated firewall mode.\u00a0 This drop is benign.",
	StatusIpsecThrottleDrop:                                     "IPsec dropped a packet due to DOS throttle.",
	StatusIpsecDospBlock:                                        "IPsec Dos Protection matched an explicit block rule.",
	StatusIpsecDospReceivedMulticast:                            "IPsec Dos Protection received an IPsec specific multicast packet which is not allowed.",
	StatusIpsecDospInvalidPacket:                                "IPsec Dos Protection received an incorrectly formatted packet.",
	StatusIpsecDospStateLookupFailed:                            "IPsec Dos Protection failed to lookup state.",
	StatusIpsecDospMaxEntries:                                   "IPsec Dos Protection failed to create state because there are already maximum number of entries allowed by policy.",
	StatusIpsecDospKeymodNotAllowed:                             "IPsec Dos Protection received an IPsec negotiation packet for a keying module which is not allowed by policy.",
	StatusIpsecDospMaxPerIpRatelimitQueues:                      "IPsec Dos Protection failed to create per internal IP ratelimit queue because there is already maximum number of queues allowed by policy.",
	StatusVolmgrMirrorNotSupported:                              "The system does not support mirrored volumes.",
	StatusVolmgrRaid5NotSupported:                               "The system does not support RAID-5 volumes.",
	StatusVirtdiskProviderNotFound:                              "A virtual disk support provider for the specified file was not found.",
	StatusVirtdiskNotVirtualDisk:                                "The specified disk is not a virtual disk.",
	StatusVhdParentVhdAccessDenied:                              "The chain of virtual hard disks is inaccessible. The process has not been granted access rights to the parent virtual hard disk for the differencing disk.",
	StatusVhdChildParentSizeMismatch:                            "The chain of virtual hard disks is corrupted. There is a mismatch in the virtual sizes of the parent virtual hard disk and differencing disk.",
	StatusVhdDifferencingChainCycleDetected:                     "The chain of virtual hard disks is corrupted. A differencing disk is indicated in its own parent chain.",
	StatusVhdDifferencingChainErrorInParent:                     "The chain of virtual hard disks is inaccessible. There was an error opening a virtual hard disk further up the chain.",
}
