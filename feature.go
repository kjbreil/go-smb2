package smb2

import (
	. "github.com/kjbreil/go-smb2/internal/smb2"
)

// client

const (
	clientCapabilities = Smb2GlobalCapLargeMtu | Smb2GlobalCapEncryption
)

var (
	clientHashAlgorithms = []uint16{SHA512}
	clientCiphers        = []uint16{AES128GCM, AES128CCM}
	clientDialects       = []uint16{SMB311, SMB302, SMB300, SMB210, SMB202}
)

const (
	clientMaxCreditBalance = 128
)

const (
	clientMaxSymlinkDepth = 8
)
