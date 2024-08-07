// ref: MS-SMB2

package smb2

const (
	MAGIC  = "\xfeSMB"
	MAGIC2 = "\xfdSMB"
)

// ----------------------------------------------------------------------------
// SMB2 Packet Header
//

// Command
const (
	Smb2Negotiate = iota
	Smb2SessionSetup
	Smb2Logoff
	Smb2TreeConnect
	Smb2TreeDisconnect
	Smb2Create
	Smb2Close
	Smb2Flush
	Smb2Read
	Smb2Write
	Smb2Lock
	Smb2Ioctl
	Smb2Cancel
	Smb2Echo
	Smb2QueryDirectory
	Smb2ChangeNotify
	Smb2QueryInfo
	Smb2SetInfo
	Smb2OplockBreak
)

// Flags
const (
	Smb2FlagsServerToRedir = 1 << iota
	Smb2FlagsAsyncCommand
	Smb2FlagsRelatedOperations
	Smb2FlagsSigned

	Smb2FlagsPriorityMask     = 0x70
	Smb2FlagsDfsOperations    = 0x10000000
	Smb2FlagsReplayOperations = 0x20000000
)

// ----------------------------------------------------------------------------
// SMB2 TRANSFORM_HEADER
//

// From SMB3

// EncryptionAlgorithm
const (
	Smb2EncryptionAes128Ccm = 1 << iota
)

// From SMB311

// Flags
const (
	Encrypted = 1 << iota
)

// ----------------------------------------------------------------------------
// SMB2 Error Response
//

// ErrorId
const (
	Smb2ErrorIdDefault = 0x0
)

// Flags
const (
	SymlinkFlagRelative = 0x1
)

// ----------------------------------------------------------------------------
// SMB2 NEGOTIATE Request and Response
//

// SecurityMode
const (
	Smb2NegotiateSigningEnabled = 1 << iota
	Smb2NegotiateSigningRequired
)

// Capabilities
const (
	Smb2GlobalCapDfs = 1 << iota
	Smb2GlobalCapLeasing
	Smb2GlobalCapLargeMtu
	Smb2GlobalCapMultiChannel
	Smb2GlobalCapPersistentHandles
	Smb2GlobalCapDirectoryLeasing
	Smb2GlobalCapEncryption
)

// Dialects
const (
	UnknownSMB = 0x0
	SMB2       = 0x2FF
	SMB202     = 0x202
	SMB210     = 0x210
	SMB300     = 0x300
	SMB302     = 0x302
	SMB311     = 0x311
)

//

// SecurityMode
const (
// SMB2_NEGOTIATE_SIGNING_ENABLED = 1 << iota
// SMB2_NEGOTIATE_SIGNING_REQUIRED
)

// DialectRevision
const (
// SMB2   = 0x2FF
// SMB202 = 0x202
// SMB210 = 0x210
// SMB300 = 0x300
// SMB302 = 0x302
// SMB311 = 0x311
)

// Capabilities
const (
// SMB2_GLOBAL_CAP_DFS = 1 << iota
// SMB2_GLOBAL_CAP_LEASING
// SMB2_GLOBAL_CAP_LARGE_MTU
// SMB2_GLOBAL_CAP_MULTI_CHANNEL
// SMB2_GLOBAL_CAP_PERSISTENT_HANDLES
// SMB2_GLOBAL_CAP_DIRECTORY_LEASING
// SMB2_GLOBAL_CAP_ENCRYPTION
)

// ----------------------------------------------------------------------------
// SMB2 NEGOTIATE Contexts
//

// From SMB311

// ContextType
const (
	Smb2PreauthIntegrityCapabilities = 1 << iota
	Smb2EncryptionCapabilities
)

// HashAlgorithms
const (
	SHA512 = 0x1
)

// Ciphers
const (
	AES128CCM = 1 << iota
	AES128GCM
)

// ----------------------------------------------------------------------------
// SMB2 SESSION_SETUP Request and Response
//

// Flags
const (
	Smb2SessionFlagBinding = 0x1
)

// SecurityMode
const (
// SMB2_NEGOTIATE_SIGNING_ENABLED = 1 << iota
// SMB2_NEGOTIATE_SIGNING_REQUIRED
)

// Capabilities
const (
// SMB2_GLOBAL_CAP_DFS = 1 << iota
// SMB2_GLOBAL_CAP_UNUSED1
// SMB2_GLOBAL_CAP_UNUSED2
// SMB2_GLOBAL_CAP_UNUSED3
)

//

// SessionFlags
const (
	Smb2SessionFlagIsGuest = 1 << iota
	Smb2SessionFlagIsNull
	Smb2SessionFlagEncryptData
)

// ----------------------------------------------------------------------------
// SMB2 LOGOFF Request and Response
//

//

// ----------------------------------------------------------------------------
// SMB2 TREE_CONNECT Request and Response
//

// From SMB311

// Flags
const (
	Smb2TreeConnectFlagClusterReconnect = 0x1
)

//

// ShareType
const (
	Smb2ShareTypeDisk = 1 + iota
	Smb2ShareTypePipe
	Smb2ShareTypePrint
)

// ShareFlags
const (
	Smb2ShareflagManualCaching            = 0x0
	Smb2ShareflagAutoCaching              = 0x10
	Smb2ShareflagVdoCaching               = 0x20
	Smb2ShareflagNoCaching                = 0x30
	Smb2ShareflagDfs                      = 0x1
	Smb2ShareflagDfsRoot                  = 0x2
	Smb2ShareflagRestrictExclusiveOpens   = 0x100
	Smb2ShareflagForceSharedDelete        = 0x200
	Smb2ShareflagAllowNamespaceCaching    = 0x400
	Smb2ShareflagAccessBasedDirectoryEnum = 0x800
	Smb2ShareflagForceLeveliiOplock       = 0x1000
	Smb2ShareflagEnableHashV1             = 0x2000
	Smb2ShareflagEnableHashV2             = 0x4000
	Smb2ShareflagEncryptData              = 0x8000
)

// Capabilities
const (
	Smb2ShareCapDfs = 0x8 << iota
	Smb2ShareCapContinuousAvailability
	Smb2ShareCapScaleout
	Smb2ShareCapCluster
	Smb2ShareCapAsymmetric
)

// ----------------------------------------------------------------------------
// SMB2 TREE_DISCONNECT Request and Response
//

//

// ----------------------------------------------------------------------------
// SMB2 CREATE Request and Response
//

// RequestedOplockLevel
const (
	Smb2OplockLevelNone      = 0x0
	Smb2OplockLevelIi        = 0x1
	Smb2OplockLevelExclusive = 0x8
	Smb2OplockLevelBatch     = 0x9
	Smb2OplockLevelLease     = 0xff
)

// ImpersonationLevel
const (
	Anonymous = iota
	Identification
	Impersonation
	Delegate
)

// DesiredAccess
const (
	// for file, pipe, printer
	FileReadData = 1 << iota
	FileWriteData
	FileAppendData
	FileReadEa
	FileWriteEa
	FileExecute
	FileDeleteChild
	FileReadAttributes
	FileWriteAttributes

	// for directory
	FileListDirectory = 1 << iota
	FileAddFile
	FileAddSubdirectory
	_ // FileReadEa
	_ // FileWriteEa
	FileTraverse
	_ // FileDeleteChild
	_ // FileReadAttributes
	_ // FileWriteAttributes

	// common
	DELETE               = 0x10000
	ReadControl          = 0x20000
	WriteDac             = 0x40000
	WriteOwner           = 0x80000
	SYNCHRONIZE          = 0x100000
	AccessSystemSecurity = 0x1000000
	MaximumAllowed       = 0x2000000
	GenericAll           = 0x10000000
	GenericExecute       = 0x20000000
	GenericWrite         = 0x40000000
	GenericRead          = 0x80000000
)

// FileAttributes (from MS-FSCC)
const (
// FILE_ATTRIBUTE_ARCHIVE             = 0x20
// FILE_ATTRIBUTE_COMPRESSED          = 0x800
// FILE_ATTRIBUTE_DIRECTORY           = 0x10
// FILE_ATTRIBUTE_ENCRYPTED           = 0x4000
// FILE_ATTRIBUTE_HIDDEN              = 0x2
// FILE_ATTRIBUTE_NORMAL              = 0x80
// FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x2000
// FILE_ATTRIBUTE_OFFLINE             = 0x1000
// FILE_ATTRIBUTE_READONLY            = 0x1
// FILE_ATTRIBUTE_REPARSE_POINT       = 0x400
// FILE_ATTRIBUTE_SPARSE_FILE         = 0x200
// FILE_ATTRIBUTE_SYSTEM              = 0x4
// FILE_ATTRIBUTE_TEMPORARY           = 0x100
// FILE_ATTRIBUTE_INTEGRITY_STREAM    = 0x8000
// FILE_ATTRIBUTE_NO_SCRUB_DATA       = 0x20000
)

// ShareAccess
const (
	FileShareRead = 1 << iota
	FileShareWrite
	FileShareDelete
)

// CreateDisposition
const (
	FileSupersede = iota
	FileOpen
	FileCreate
	FileOpenIf
	FileOverwrite
	FileOverwriteIf
)

// CreateOptions
const (
	FileDirectoryFile = 1 << iota
	FileWriteThrough
	FileSequentialOnly
	FileNoIntermediateBuffering
	FileSynchronousIoAlert
	FileSynchronousIoNonalert
	FileNonDirectoryFile
	_
	FileCompleteIfOplocked
	FileNoEaKnowledge
	FileOpenRemoteInstance
	FileRandomAccess
	FileDeleteOnClose
	FileOpenByFileId
	FileOpenForBackupIntent
	FileNoCompression
	FileOpenRequiringOplock
	FileDisallowExclusive
	_
	_
	FileReserveOpfilter
	FileOpenReparsePoint
	FileOpenNoRecall
	FileOpenForFreeSpaceQuery
)

//

// OplockLevel
const (
// SMB2_OPLOCK_LEVEL_NONE      = 0x0
// SMB2_OPLOCK_LEVEL_II        = 0x1
// SMB2_OPLOCK_LEVEL_EXCLUSIVE = 0x8
// SMB2_OPLOCK_LEVEL_BATCH     = 0x9
// SMB2_OPLOCK_LEVEL_LEASE     = 0xff
)

// Flags
const (
	Smb2CreateFlagReparsepoint = 1 << iota
)

// CreateAction
const (
// FILE_SUPERSEDE = iota
// FILE_OPEN
// FILE_CREATE
// FILE_OPEN_IF
// FILE_OVERWRITE
)

// FileAttributes (from MS-FSCC)
const (
// FILE_ATTRIBUTE_ARCHIVE             = 0x20
// FILE_ATTRIBUTE_COMPRESSED          = 0x800
// FILE_ATTRIBUTE_DIRECTORY           = 0x10
// FILE_ATTRIBUTE_ENCRYPTED           = 0x4000
// FILE_ATTRIBUTE_HIDDEN              = 0x2
// FILE_ATTRIBUTE_NORMAL              = 0x80
// FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x2000
// FILE_ATTRIBUTE_OFFLINE             = 0x1000
// FILE_ATTRIBUTE_READONLY            = 0x1
// FILE_ATTRIBUTE_REPARSE_POINT       = 0x400
// FILE_ATTRIBUTE_SPARSE_FILE         = 0x200
// FILE_ATTRIBUTE_SYSTEM              = 0x4
// FILE_ATTRIBUTE_TEMPORARY           = 0x100
// FILE_ATTRIBUTE_INTEGRITY_STREAM    = 0x8000
// FILE_ATTRIBUTE_NO_SCRUB_DATA       = 0x20000
)

// ----------------------------------------------------------------------------
// SMB2 CLOSE Request and Response
//

// Flags
const (
	Smb2CloseFlagPostqueryAttrib = 1 << iota
)

//

// Flags
const (
// SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB = 1 << iota
)

// FileAttributes (from MS-FSCC)
const (
// FILE_ATTRIBUTE_ARCHIVE             = 0x20
// FILE_ATTRIBUTE_COMPRESSED          = 0x800
// FILE_ATTRIBUTE_DIRECTORY           = 0x10
// FILE_ATTRIBUTE_ENCRYPTED           = 0x4000
// FILE_ATTRIBUTE_HIDDEN              = 0x2
// FILE_ATTRIBUTE_NORMAL              = 0x80
// FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x2000
// FILE_ATTRIBUTE_OFFLINE             = 0x1000
// FILE_ATTRIBUTE_READONLY            = 0x1
// FILE_ATTRIBUTE_REPARSE_POINT       = 0x400
// FILE_ATTRIBUTE_SPARSE_FILE         = 0x200
// FILE_ATTRIBUTE_SYSTEM              = 0x4
// FILE_ATTRIBUTE_TEMPORARY           = 0x100
// FILE_ATTRIBUTE_INTEGRITY_STREAM    = 0x8000
// FILE_ATTRIBUTE_NO_SCRUB_DATA       = 0x20000
)

// ----------------------------------------------------------------------------
// SMB2 FLUSH Request and Response
//

//

// ----------------------------------------------------------------------------
// SMB2 READ Request and Response
//

// Flags
const (
	Smb2ReadflagReadUnbuffered = 1 << iota
)

// Channel
const (
	Smb2ChannelNone = iota
	Smb2ChannelRdmaV1
	Smb2ChannelRdmaV1Invalidate
)

//

// ----------------------------------------------------------------------------
// SMB2 WRITE Request and Response
//

// Channel
const (
// SMB2_CHANNEL_NONE = iota
// SMB2_CHANNEL_RDMA_V1
// SMB2_CHANNEL_RDMA_V1_INVALIDATE
)

// Flags
const (
	Smb2WriteflagWriteThrough = 1 << iota
	Smb2WriteflagWriteUnbuffered
)

//

// ----------------------------------------------------------------------------
// SMB2 OPLOCK_BREAK Notification, Acknowledgement and Response
//

//

//

// ----------------------------------------------------------------------------
// SMB2 LOCK Request and Response
//

//

// ----------------------------------------------------------------------------
// SMB2 CANCEL Request
//

// ----------------------------------------------------------------------------
// SMB2 ECHO Request and Response
//

//

// ----------------------------------------------------------------------------
// SMB2 IOCTL Request and Response
//

// CtlCode (from MS-FSCC)
const (
// FSCTL_DFS_GET_REFERRALS            = 0x00060194
// FSCTL_PIPE_PEEK                    = 0x0011400C
// FSCTL_PIPE_WAIT                    = 0x00110018
// FSCTL_PIPE_TRANSCEIVE              = 0x0011C017
// FSCTL_SRV_COPYCHUNK                = 0x001440F2
// FSCTL_SRV_ENUMERATE_SNAPSHOTS      = 0x00144064
// FSCTL_SRV_REQUEST_RESUME_KEY       = 0x00140078
// FSCTL_SRV_READ_HASH                = 0x001441bb
// FSCTL_SRV_COPYCHUNK_WRITE          = 0x001480F2
// FSCTL_LMR_REQUEST_RESILIENCY       = 0x001401D4
// FSCTL_QUERY_NETWORK_INTERFACE_INFO = 0x001401FC
// FSCTL_GET_REPARSE_POINT            = 0x000900A8
// FSCTL_SET_REPARSE_POINT            = 0x000900A4
// FSCTL_DFS_GET_REFERRALS_EX         = 0x000601B0
// FSCTL_FILE_LEVEL_TRIM              = 0x00098208
// FSCTL_VALIDATE_NEGOTIATE_INFO      = 0x00140204
)

// Flags
const (
	Smb20IoctlIsFsctl = 0x1
)

//

// CtlCode (from MS-FSCC)
const (
// FSCTL_DFS_GET_REFERRALS            = 0x00060194
// FSCTL_PIPE_PEEK                    = 0x0011400C
// FSCTL_PIPE_WAIT                    = 0x00110018
// FSCTL_PIPE_TRANSCEIVE              = 0x0011C017
// FSCTL_SRV_COPYCHUNK                = 0x001440F2
// FSCTL_SRV_ENUMERATE_SNAPSHOTS      = 0x00144064
// FSCTL_SRV_REQUEST_RESUME_KEY       = 0x00140078
// FSCTL_SRV_READ_HASH                = 0x001441bb
// FSCTL_SRV_COPYCHUNK_WRITE          = 0x001480F2
// FSCTL_LMR_REQUEST_RESILIENCY       = 0x001401D4
// FSCTL_QUERY_NETWORK_INTERFACE_INFO = 0x001401FC
// FSCTL_SET_REPARSE_POINT            = 0x000900A4
// FSCTL_DFS_GET_REFERRALS_EX         = 0x000601B0
// FSCTL_FILE_LEVEL_TRIM              = 0x00098208
// FSCTL_VALIDATE_NEGOTIATE_INFO      = 0x00140204
)

// ----------------------------------------------------------------------------
// SMB2 QUERY_DIRECTORY Request and Response
//

// FileInformationClass (from MS-FSCC)
const (
// FileDirectoryInformation = 0x1
// FileFullDirectoryInformation = 0x2
// FileIdFullDirectoryInformation = 0x26
// FileBothDirectoryInformation = 0x3
// FileIdBothDirectoryInformation = 0x25
// FileNamesInformation = 0xc
)

// Flags
const (
	RestartScans = 1 << iota
	ReturnSingleEntry
	IndexSpecified
	_
	REOPEN
)

//

// ----------------------------------------------------------------------------
// SMB2 CHANGE_NOTIFY Request and Response
//

//

// ----------------------------------------------------------------------------
// SMB2 QUERY_INFO Request and Response
//

// InfoType
const (
	InfoFile = 1 + iota
	InfoFilesystem
	InfoSecurity
	InfoQuota
)

// FileInfoClass (from MS-FSCC)
const (
// FileAccessInformation
// FileAlignmentInformation
// FileAllInformation
// FileAlternateNameInformation
// FileAttributeTagInformation
// FileBasicInformation
// FileCompressionInformation
// FileEaInformation
// FileFullEaInformation
// FileInternalInformation
// FileModeInformation
// FileNetworkOpenInformation
// FilePipeInformation
// FilePipeLocalInformation
// FilePipeRemoteInformation
// FilePositionInformation
// FileStandardInformation
// FileStreamInformation

// FileFsAttributeInformation
// FileFsControlInformation
// FileFsDeviceInformation
// FileFsFullSizeInformation
// FileFsObjectIdInformation
// FileFsSectorSizeInformation
// FileFsSizeInformation
// FileFsVolumeInformation
)

// AdditionalInformation
const (
	OwnerSecurityInformation = 1 << iota
	GroupSecuirtyInformation
	DaclSecuirtyInformation
	SaclSecuirtyInformation
	LabelSecuirtyInformation
	AttributeSecuirtyInformation
	ScopeSecuirtyInformation

	BackupSecuirtyInformation = 0x10000
)

// Flags
const (
	SlRestartScan = 1 << iota
	SlReturnSingleEntry
	SlIndexSpecified
)

//

// ----------------------------------------------------------------------------
// SMB2 SET_INFO Request and Response
//

// InfoType
const (
	Smb20InfoFile = 1 + iota
	Smb20InfoFilesystem
	Smb20InfoSecurity
	Smb20InfoQuota
)

// FileInfoClass
const (
// FileAllocationInformation
// FileBasicInformation
// FileDispositionInformation
// FileEndOfFileInformation
// FileFullEaInformation
// FileLinkInformation
// FileModeInformation
// FilePipeInformation
// FilePositionInformation
// FileRenameInformation
// FileShortNameInformation
// FileValidDataLengthInformation

// FileFsControlInformation
// FileFsObjectIdInformation
)

// AdditionalInformation
const (
// OWNER_SECURITY_INFORMATION = 1 << iota
// GROUP_SECUIRTY_INFORMATION
// DACL_SECUIRTY_INFORMATION
// SACL_SECUIRTY_INFORMATION
// LABEL_SECUIRTY_INFORMATION
// ATTRIBUTE_SECUIRTY_INFORMATION
// SCOPE_SECUIRTY_INFORMATION

// BACKUP_SECUIRTY_INFORMATION = 0x10000
)

//
