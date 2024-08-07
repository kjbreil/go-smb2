package smb2

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	. "github.com/kjbreil/go-smb2/internal/erref"
	. "github.com/kjbreil/go-smb2/internal/smb2"

	"github.com/kjbreil/go-smb2/internal/msrpc"
)

// Dialer contains options for func (*Dialer) Dial.
type Dialer struct {
	MaxCreditBalance uint16 // if it's zero, clientMaxCreditBalance is used. (See feature.go for more details)
	Negotiator       Negotiator
	Initiator        Initiator
}

// Dial performs negotiation and authentication.
// It returns a session. It doesn't support NetBIOS transport.
// This implementation doesn't support multi-session on the same TCP connection.
// If you want to use another session, you need to prepare another TCP connection at first.
func (d *Dialer) Dial(tcpConn net.Conn) (*Session, error) {
	return d.DialContext(context.Background(), tcpConn)
}

// DialContext performs negotiation and authentication using the provided context.
// Note that returned session doesn't inherit context.
// If you want to use the same context, call Session.WithContext manually.
// This implementation doesn't support multi-session on the same TCP connection.
// If you want to use another session, you need to prepare another TCP connection at first.
func (d *Dialer) DialContext(ctx context.Context, tcpConn net.Conn) (*Session, error) {
	if ctx == nil {
		panic("nil context")
	}
	if d.Initiator == nil {
		return nil, &InternalError{"Initiator is empty"}
	}
	if i, ok := d.Initiator.(*NTLMInitiator); ok {
		if i.User == "" {
			return nil, &InternalError{"Anonymous account is not supported yet. Use guest account instead"}
		}
	}

	maxCreditBalance := d.MaxCreditBalance
	if maxCreditBalance == 0 {
		maxCreditBalance = clientMaxCreditBalance
	}

	a := openAccount(maxCreditBalance)

	conn, err := d.Negotiator.negotiate(direct(tcpConn), a, ctx)
	if err != nil {
		return nil, err
	}

	s, err := sessionSetup(conn, d.Initiator, ctx)
	if err != nil {
		return nil, err
	}

	return &Session{s: s, ctx: context.Background(), addr: tcpConn.RemoteAddr().String()}, nil
}

// Session represents a SMB session.
type Session struct {
	s    *session
	ctx  context.Context
	addr string
}

func (c *Session) WithContext(ctx context.Context) *Session {
	if ctx == nil {
		panic("nil context")
	}
	return &Session{s: c.s, ctx: ctx, addr: c.addr}
}

// Logoff invalidates the current SMB session.
func (c *Session) Logoff() error {
	return c.s.logoff(c.ctx)
}

// Mount mounts the SMB share.
// sharename must follow format like `<share>` or `\\<server>\<share>`.
// Note that the mounted share doesn't inherit session's context.
// If you want to use the same context, call Share.WithContext manually.
func (c *Session) Mount(sharename string) (*Share, error) {
	sharename = normPath(sharename)

	if !strings.ContainsRune(sharename, '\\') {
		sharename = fmt.Sprintf(`\\%s\%s`, c.addr, sharename)
	}

	if err := validateMountPath(sharename); err != nil {
		return nil, err
	}

	tc, err := treeConnect(c.s, sharename, 0, c.ctx)
	if err != nil {
		return nil, err
	}

	return &Share{treeConn: tc, ctx: context.Background()}, nil
}

func (c *Session) ListSharenames() ([]string, error) {
	servername := c.addr

	fs, err := c.Mount(fmt.Sprintf(`\\%s\IPC$`, servername))
	if err != nil {
		return nil, err
	}
	defer fs.Umount()

	fs = fs.WithContext(c.ctx)

	f, err := fs.OpenFile("srvsvc", os.O_RDWR, 0666)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	callId := rand.Uint32()

	bindReq := &IoctlRequest{
		CtlCode:           FsctlPipeTransceive,
		OutputOffset:      0,
		OutputCount:       0,
		MaxInputResponse:  0,
		MaxOutputResponse: 4280,
		Flags:             Smb20IoctlIsFsctl,
		Input: &msrpc.Bind{
			CallId: callId,
		},
	}

	output, err := f.ioctl(bindReq)
	if err != nil {
		return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: err}
	}

	r1 := msrpc.BindAckDecoder(output)
	if r1.IsInvalid() || r1.CallId() != callId {
		return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: &InvalidResponseError{"broken bind ack response format"}}
	}

	callId++

	reqReq := &IoctlRequest{
		CtlCode:          FsctlPipeTransceive,
		OutputOffset:     0,
		OutputCount:      0,
		MaxInputResponse: 0,
		// MaxOutputResponse: 4280,
		MaxOutputResponse: 1024,
		Flags:             Smb20IoctlIsFsctl,
		Input: &msrpc.NetShareEnumAllRequest{
			CallId:     callId,
			ServerName: servername,
			Level:      1, // level 1 seems to be portable
		},
	}

	output, err = f.ioctl(reqReq)
	if err != nil {
		if rerr, ok := err.(*ResponseError); ok && NtStatus(rerr.Code) == StatusBufferOverflow {
			buf := make([]byte, 4280)

			rlen := 4280 - len(output)

			n, err := f.readAt(buf[:rlen], 0)
			if err != nil {
				return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: err}
			}

			output = append(output, buf[:n]...)

			r2 := msrpc.NetShareEnumAllResponseDecoder(output)
			if r2.IsInvalid() || r2.CallId() != callId {
				return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: &InvalidResponseError{"broken net share enum response format"}}
			}

			for r2.IsIncomplete() {
				n, err := f.readAt(buf, 0)
				if err != nil {
					return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: err}
				}

				r3 := msrpc.NetShareEnumAllResponseDecoder(buf[:n])
				if r3.IsInvalid() || r3.CallId() != callId {
					return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: &InvalidResponseError{"broken net share enum response format"}}
				}

				output = append(output, r3.Buffer()...)

				r2 = msrpc.NetShareEnumAllResponseDecoder(output)
			}

			return r2.ShareNameList(), nil
		}

		return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: err}
	}

	r2 := msrpc.NetShareEnumAllResponseDecoder(output)
	if r2.IsInvalid() || r2.IsIncomplete() || r2.CallId() != callId {
		return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: &InvalidResponseError{"broken net share enum response format"}}
	}

	return r2.ShareNameList(), nil
}

// Share represents a SMB tree connection with VFS interface.
type Share struct {
	*treeConn
	ctx context.Context
}

func (s *Share) WithContext(ctx context.Context) *Share {
	if ctx == nil {
		panic("nil context")
	}
	return &Share{
		treeConn: s.treeConn,
		ctx:      ctx,
	}
}

// Umount disconects the current SMB tree.
func (s *Share) Umount() error {
	return s.treeConn.disconnect(s.ctx)
}

func (s *Share) Create(name string) (*File, error) {
	return s.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
}

func (s *Share) newFile(r CreateResponseDecoder, name string) *File {
	fd := r.FileId().Decode()

	fileStat := &FileStat{
		CreationTime:   time.Unix(0, r.CreationTime().Nanoseconds()),
		LastAccessTime: time.Unix(0, r.LastAccessTime().Nanoseconds()),
		LastWriteTime:  time.Unix(0, r.LastWriteTime().Nanoseconds()),
		ChangeTime:     time.Unix(0, r.ChangeTime().Nanoseconds()),
		EndOfFile:      r.EndofFile(),
		AllocationSize: r.AllocationSize(),
		FileAttributes: r.FileAttributes(),
		FileName:       base(name),
	}

	f := &File{fs: s, fd: fd, name: name, fileStat: fileStat}

	runtime.SetFinalizer(f, (*File).close)

	return f
}

func (s *Share) Open(name string) (*File, error) {
	return s.OpenFile(name, os.O_RDONLY, 0)
}

func (s *Share) OpenFile(name string, flag int, perm os.FileMode) (*File, error) {
	name = normPath(name)

	if err := validatePath("open", name, false); err != nil {
		return nil, err
	}

	var access uint32
	switch flag & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR) {
	case os.O_RDONLY:
		access = GenericRead
	case os.O_WRONLY:
		access = GenericWrite
	case os.O_RDWR:
		access = GenericRead | GenericWrite
	}
	if flag&os.O_CREATE != 0 {
		access |= GenericWrite
	}
	if flag&os.O_APPEND != 0 {
		access &^= GenericWrite
		access |= FileAppendData
	}

	sharemode := uint32(FileShareRead | FileShareWrite)

	var createmode uint32
	switch {
	case flag&(os.O_CREATE|os.O_EXCL) == (os.O_CREATE | os.O_EXCL):
		createmode = FileCreate
	case flag&(os.O_CREATE|os.O_TRUNC) == (os.O_CREATE | os.O_TRUNC):
		createmode = FileOverwriteIf
	case flag&os.O_CREATE == os.O_CREATE:
		createmode = FileOpenIf
	case flag&os.O_TRUNC == os.O_TRUNC:
		createmode = FileOverwrite
	default:
		createmode = FileOpen
	}

	var attrs uint32 = FileAttributeArchive
	if perm&0200 == 0 {
		attrs = FileAttributeReadonly
	}

	req := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: Smb2OplockLevelNone,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        access,
		FileAttributes:       attrs,
		ShareAccess:          sharemode,
		CreateDisposition:    createmode,
		CreateOptions:        FileSynchronousIoNonalert,
	}

	f, err := s.createFile(name, req, true)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	if flag&os.O_APPEND != 0 {
		f.seek(0, io.SeekEnd)
	}
	return f, nil
}

func (s *Share) Mkdir(name string, perm os.FileMode) error {
	name = normPath(name)

	if err := validatePath("mkdir", name, false); err != nil {
		return err
	}

	req := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: Smb2OplockLevelNone,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        FileWriteAttributes,
		FileAttributes:       FileAttributeNormal,
		ShareAccess:          FileShareRead | FileShareWrite,
		CreateDisposition:    FileCreate,
		CreateOptions:        FileDirectoryFile,
	}

	f, err := s.createFile(name, req, false)
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: name, Err: err}
	}

	err = f.close()
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: name, Err: err}
	}
	return nil
}

func (s *Share) Readlink(name string) (string, error) {
	name = normPath(name)

	if err := validatePath("readlink", name, false); err != nil {
		return "", err
	}

	create := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: Smb2OplockLevelNone,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        FileReadAttributes,
		FileAttributes:       FileAttributeNormal,
		ShareAccess:          FileShareRead | FileShareWrite,
		CreateDisposition:    FileOpen,
		CreateOptions:        FileOpenReparsePoint,
	}

	f, err := s.createFile(name, create, false)
	if err != nil {
		return "", &os.PathError{Op: "readlink", Path: name, Err: err}
	}

	req := &IoctlRequest{
		CtlCode:           FsctlGetReparsePoint,
		OutputOffset:      0,
		OutputCount:       0,
		MaxInputResponse:  0,
		MaxOutputResponse: uint32(f.maxTransactSize()),
		Flags:             Smb20IoctlIsFsctl,
		Input:             nil,
	}

	output, err := f.ioctl(req)
	if e := f.close(); err == nil {
		err = e
	}
	if err != nil {
		return "", &os.PathError{Op: "readlink", Path: f.name, Err: err}
	}

	r := SymbolicLinkReparseDataBufferDecoder(output)
	if r.IsInvalid() {
		return "", &os.PathError{Op: "readlink", Path: f.name, Err: &InvalidResponseError{"broken symbolic link response data buffer format"}}
	}

	target := r.SubstituteName()

	switch {
	case strings.HasPrefix(target, `\??\UNC\`):
		target = `\\` + target[8:]
	case strings.HasPrefix(target, `\??\`):
		target = target[4:]
	}

	return target, nil
}

func (s *Share) Remove(name string) error {
	err := s.remove(name)
	if os.IsPermission(err) {
		if e := s.Chmod(name, 0666); e != nil {
			return err
		}
		return s.remove(name)
	}
	return err
}

func (s *Share) remove(name string) error {
	name = normPath(name)

	if err := validatePath("remove", name, false); err != nil {
		return err
	}

	req := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: Smb2OplockLevelNone,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        DELETE,
		FileAttributes:       0,
		ShareAccess:          FileShareDelete,
		CreateDisposition:    FileOpen,
		// CreateOptions:        FILE_OPEN_REPARSE_POINT | FILE_DELETE_ON_CLOSE,
		CreateOptions: FileOpenReparsePoint,
	}
	// FILE_DELETE_ON_CLOSE doesn't work for reparse point, so use FileDispositionInformation instead

	f, err := s.createFile(name, req, false)
	if err != nil {
		return &os.PathError{Op: "remove", Path: name, Err: err}
	}

	err = f.remove()
	if e := f.close(); err == nil {
		err = e
	}
	if err != nil {
		return &os.PathError{Op: "remove", Path: name, Err: err}
	}

	return nil
}

func (s *Share) Rename(oldpath, newpath string) error {
	oldpath = normPath(oldpath)
	newpath = normPath(newpath)

	if err := validatePath("rename from", oldpath, false); err != nil {
		return err
	}

	if err := validatePath("rename to", newpath, false); err != nil {
		return err
	}

	create := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: Smb2OplockLevelNone,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        DELETE,
		FileAttributes:       FileAttributeNormal,
		ShareAccess:          FileShareDelete,
		CreateDisposition:    FileOpen,
		CreateOptions:        FileOpenReparsePoint,
	}

	f, err := s.createFile(oldpath, create, false)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}

	info := &SetInfoRequest{
		FileInfoClass:         FileRenameInformation,
		AdditionalInformation: 0,
		Input: &FileRenameInformationType2Encoder{
			ReplaceIfExists: 0,
			RootDirectory:   0,
			FileName:        newpath,
		},
	}

	err = f.setInfo(info)
	if e := f.close(); err == nil {
		err = e
	}
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}
	return nil
}

// Symlink mimics os.Symlink.
// This API should work on latest Windows and latest MacOS.
// However it may not work on Linux because Samba doesn't support reparse point well.
// Also there is a restriction on target pathname.
// Generally, a pathname begins with leading backslash (e.g `\dir\name`) can be interpreted as two ways.
// On windows, it is evaluated as a relative path, on other systems, it is evaluated as an absolute path.
// This implementation always assumes that format is absolute path.
// So, if you know the target server is Windows, you should avoid that format.
// If you want to use an absolute target path on windows, you can use // `C:\dir\name` format instead.
func (s *Share) Symlink(target, linkpath string) error {
	target = normPath(target)
	linkpath = normPath(linkpath)

	if err := validatePath("symlink target", target, true); err != nil {
		return err
	}

	if err := validatePath("symlink linkpath", linkpath, false); err != nil {
		return err
	}

	rdbuf := new(SymbolicLinkReparseDataBuffer)

	if len(target) >= 2 && target[1] == ':' {
		if len(target) == 2 {
			return os.ErrInvalid
		}

		if target[2] != '\\' {
			rdbuf.Flags = SymlinkFlagRelative
		}
		rdbuf.SubstituteName = `\??\` + target
		rdbuf.PrintName = rdbuf.SubstituteName[4:]
	} else {
		if target[0] != '\\' {
			rdbuf.Flags = SymlinkFlagRelative // It's not true on window server.
		}
		rdbuf.SubstituteName = target
		rdbuf.PrintName = rdbuf.SubstituteName
	}

	create := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: Smb2OplockLevelNone,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        FileWriteAttributes | DELETE,
		FileAttributes:       FileAttributeReparsePoint,
		ShareAccess:          FileShareRead | FileShareWrite,
		CreateDisposition:    FileCreate,
		CreateOptions:        FileOpenReparsePoint,
	}

	f, err := s.createFile(linkpath, create, false)
	if err != nil {
		return &os.LinkError{Op: "symlink", Old: target, New: linkpath, Err: err}
	}

	req := &IoctlRequest{
		CtlCode:           FsctlSetReparsePoint,
		OutputOffset:      0,
		OutputCount:       0,
		MaxInputResponse:  0,
		MaxOutputResponse: 0,
		Flags:             Smb20IoctlIsFsctl,
		Input:             rdbuf,
	}

	_, err = f.ioctl(req)
	if err != nil {
		f.remove()
		f.close()

		return &os.PathError{Op: "symlink", Path: f.name, Err: err}
	}

	err = f.close()
	if err != nil {
		return &os.PathError{Op: "symlink", Path: f.name, Err: err}
	}

	return nil
}

func (s *Share) Lstat(name string) (os.FileInfo, error) {
	name = normPath(name)

	if err := validatePath("lstat", name, false); err != nil {
		return nil, err
	}

	create := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: Smb2OplockLevelNone,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        FileReadAttributes,
		FileAttributes:       FileAttributeNormal,
		ShareAccess:          FileShareRead | FileShareWrite,
		CreateDisposition:    FileOpen,
		CreateOptions:        FileOpenReparsePoint,
	}

	f, err := s.createFile(name, create, false)
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: name, Err: err}
	}

	fi, err := f.fileStat, nil
	if e := f.close(); err == nil {
		err = e
	}
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: name, Err: err}
	}
	return fi, nil
}

func (s *Share) Stat(name string) (os.FileInfo, error) {
	name = normPath(name)

	if err := validatePath("stat", name, false); err != nil {
		return nil, err
	}

	create := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: Smb2OplockLevelNone,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        FileReadAttributes,
		FileAttributes:       FileAttributeNormal,
		ShareAccess:          FileShareRead | FileShareWrite,
		CreateDisposition:    FileOpen,
		CreateOptions:        0,
	}

	f, err := s.createFile(name, create, true)
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: name, Err: err}
	}

	fi, err := f.fileStat, nil
	if e := f.close(); err == nil {
		err = e
	}
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: name, Err: err}
	}
	return fi, nil
}

func (s *Share) Truncate(name string, size int64) error {
	name = normPath(name)

	if err := validatePath("truncate", name, false); err != nil {
		return err
	}

	if size < 0 {
		return os.ErrInvalid
	}

	create := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: Smb2OplockLevelNone,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        FileWriteData,
		FileAttributes:       FileAttributeNormal,
		ShareAccess:          FileShareRead | FileShareWrite,
		CreateDisposition:    FileOpen,
		CreateOptions:        FileNonDirectoryFile | FileSynchronousIoNonalert,
	}

	f, err := s.createFile(name, create, true)
	if err != nil {
		return &os.PathError{Op: "truncate", Path: name, Err: err}
	}

	err = f.truncate(size)
	if e := f.close(); err == nil {
		err = e
	}
	if err != nil {
		return &os.PathError{Op: "truncate", Path: name, Err: err}
	}
	return nil
}

func (s *Share) Chtimes(name string, atime time.Time, mtime time.Time) error {
	name = normPath(name)

	if err := validatePath("chtimes", name, false); err != nil {
		return err
	}

	create := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: Smb2OplockLevelNone,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        FileWriteAttributes,
		FileAttributes:       FileAttributeNormal,
		ShareAccess:          FileShareRead | FileShareWrite,
		CreateDisposition:    FileOpen,
		CreateOptions:        0,
	}

	f, err := s.createFile(name, create, true)
	if err != nil {
		return &os.PathError{Op: "chtimes", Path: name, Err: err}
	}

	info := &SetInfoRequest{
		FileInfoClass:         FileBasicInformation,
		AdditionalInformation: 0,
		Input: &FileBasicInformationEncoder{
			LastAccessTime: NsecToFiletime(atime.UnixNano()),
			LastWriteTime:  NsecToFiletime(mtime.UnixNano()),
		},
	}

	err = f.setInfo(info)
	if e := f.close(); err == nil {
		err = e
	}
	if err != nil {
		return &os.PathError{Op: "chtimes", Path: name, Err: err}
	}
	return nil
}

func (s *Share) SetArchive(name string, archive bool) error {
	name = normPath(name)

	if err := validatePath("chmod", name, false); err != nil {
		return err
	}

	create := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: Smb2OplockLevelNone,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        FileReadAttributes | FileWriteAttributes,
		FileAttributes:       FileAttributeNormal,
		ShareAccess:          FileShareRead | FileShareWrite,
		CreateDisposition:    FileOpen,
		CreateOptions:        0,
	}

	f, err := s.createFile(name, create, true)
	if err != nil {
		return &os.PathError{Op: "chmod", Path: name, Err: err}
	}

	req := &QueryInfoRequest{
		InfoType:              Smb20InfoFile,
		FileInfoClass:         FileBasicInformation,
		AdditionalInformation: 0,
		Flags:                 0,
		OutputBufferLength:    40,
	}

	infoBytes, err := f.queryInfo(req)
	if err != nil {
		return err
	}

	base := FileBasicInformationDecoder(infoBytes)
	if base.IsInvalid() {
		return &InvalidResponseError{"broken query info response format"}
	}

	// attrs := base.FileAttributes()

	attrs := FileAttributeNormal
	if archive {
		attrs = FileAttributeArchive
	}
	// if mode&0200 != 0 {
	// attrs &^= FILE_ATTRIBUTE_ARCHIVE
	// attrs &^= FILE_ATTRIBUTE_READONLY
	// } else {
	// attrs |= FILE_ATTRIBUTE_ARCHIVE
	// }

	info := &SetInfoRequest{
		FileInfoClass:         FileBasicInformation,
		AdditionalInformation: 0,
		Input: &FileBasicInformationEncoder{
			FileAttributes: uint32(attrs),
		},
	}

	err = f.setInfo(info)
	if err != nil {
		return err
	}
	return nil
}

func (s *Share) Chmod(name string, mode os.FileMode) error {
	name = normPath(name)

	if err := validatePath("chmod", name, false); err != nil {
		return err
	}

	create := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: Smb2OplockLevelNone,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        FileReadAttributes | FileWriteAttributes,
		FileAttributes:       FileAttributeNormal,
		ShareAccess:          FileShareRead | FileShareWrite,
		CreateDisposition:    FileOpen,
		CreateOptions:        0,
	}

	f, err := s.createFile(name, create, true)
	if err != nil {
		return &os.PathError{Op: "chmod", Path: name, Err: err}
	}

	err = f.chmod(mode)
	if e := f.close(); err == nil {
		err = e
	}
	if err != nil {
		return &os.PathError{Op: "chmod", Path: name, Err: err}
	}
	return nil
}

func (s *Share) ReadDir(dirname string) ([]os.FileInfo, error) {
	f, err := s.Open(dirname)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fis, err := f.Readdir(-1)
	if err != nil {
		return nil, err
	}

	sort.Slice(fis, func(i, j int) bool { return fis[i].Name() < fis[j].Name() })

	return fis, nil
}

const (
	intSize = 32 << (^uint(0) >> 63) // 32 or 64
	maxInt  = 1<<(intSize-1) - 1
)

func (s *Share) ReadFile(filename string) ([]byte, error) {
	f, err := s.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	size64 := f.fileStat.Size() + 1 // one byte for final read at EOF

	var size int

	if size64 <= maxInt {
		size = int(size64)

		// If a file claims a small size, read at least 512 bytes.
		// In particular, files in Linux's /proc claim size 0 but
		// then do not work right if read in small pieces,
		// so an initial read of 1 byte would not work correctly.
		if size < 512 {
			size = 512
		}
	} else {
		size = maxInt
	}

	data := make([]byte, 0, size)
	for {
		if len(data) >= cap(data) {
			d := append(data[:cap(data)], 0)
			data = d[:len(data)]
		}
		n, err := f.Read(data[len(data):cap(data)])
		data = data[:len(data)+n]
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return data, err
		}
	}
}

func (s *Share) WriteFile(filename string, data []byte, perm os.FileMode) error {
	f, err := s.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}

	_, err = f.Write(data)
	if err1 := f.Close(); err == nil {
		err = err1
	}

	return err
}

func (s *Share) Statfs(name string) (FileFsInfo, error) {
	name = normPath(name)

	if err := validatePath("statfs", name, false); err != nil {
		return nil, err
	}

	create := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: Smb2OplockLevelNone,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        FileReadAttributes,
		FileAttributes:       FileAttributeNormal,
		ShareAccess:          FileShareRead | FileShareWrite,
		CreateDisposition:    FileOpen,
		CreateOptions:        FileDirectoryFile,
	}

	f, err := s.createFile(name, create, true)
	if err != nil {
		return nil, &os.PathError{Op: "statfs", Path: name, Err: err}
	}

	fi, err := f.statfs()
	if e := f.close(); err == nil {
		err = e
	}
	if err != nil {
		return nil, &os.PathError{Op: "statfs", Path: name, Err: err}
	}
	return fi, nil
}

func (s *Share) createFile(name string, req *CreateRequest, followSymlinks bool) (f *File, err error) {
	if followSymlinks {
		return s.createFileRec(name, req)
	}

	req.CreditCharge, _, err = s.loanCredit(0)
	defer func() {
		if err != nil {
			s.chargeCredit(req.CreditCharge)
		}
	}()
	if err != nil {
		return nil, err
	}

	req.Name = name

	res, err := s.sendRecv(Smb2Create, req)
	if err != nil {
		return nil, err
	}

	r := CreateResponseDecoder(res)
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken create response format"}
	}

	f = s.newFile(r, name)

	return f, nil
}

func (s *Share) createFileRec(name string, req *CreateRequest) (f *File, err error) {
	for i := 0; i < clientMaxSymlinkDepth; i++ {
		req.CreditCharge, _, err = s.loanCredit(0)
		defer func() {
			if err != nil {
				s.chargeCredit(req.CreditCharge)
			}
		}()
		if err != nil {
			return nil, err
		}

		req.Name = name

		res, err := s.sendRecv(Smb2Create, req)
		if err != nil {
			if rerr, ok := err.(*ResponseError); ok && NtStatus(rerr.Code) == StatusStoppedOnSymlink {
				if len(rerr.data) > 0 {
					name, err = evalSymlinkError(req.Name, rerr.data[0])
					if err != nil {
						return nil, err
					}
					continue
				}
			}
			return nil, err
		}

		r := CreateResponseDecoder(res)
		if r.IsInvalid() {
			return nil, &InvalidResponseError{"broken create response format"}
		}

		f = s.newFile(r, name)

		return f, nil
	}

	return nil, &InternalError{"Too many levels of symbolic links"}
}

func evalSymlinkError(name string, errData []byte) (string, error) {
	d := SymbolicLinkErrorResponseDecoder(errData)
	if d.IsInvalid() {
		return "", &InvalidResponseError{"broken symbolic link error response format"}
	}

	ud, u := d.SplitUnparsedPath(name)
	if ud == "" && u == "" {
		return "", &InvalidResponseError{"broken symbolic link error response format"}
	}

	target := d.SubstituteName()

	switch {
	case strings.HasPrefix(target, `\??\UNC\`):
		target = `\\` + target[8:]
	case strings.HasPrefix(target, `\??\`):
		target = target[4:]
	}

	if d.Flags()&SymlinkFlagRelative == 0 {
		return target + u, nil
	}

	return dir(ud) + target + u, nil
}

func (s *Share) sendRecv(cmd uint16, req Packet) (res []byte, err error) {
	rr, err := s.send(req, s.ctx)
	if err != nil {
		return nil, err
	}

	pkt, err := s.recv(rr)
	if err != nil {
		return nil, err
	}

	return accept(cmd, pkt)
}

func (s *Share) loanCredit(payloadSize int) (creditCharge uint16, grantedPayloadSize int, err error) {
	return s.session.conn.loanCredit(payloadSize, s.ctx)
}

type File struct {
	fs          *Share
	fd          *FileId
	name        string
	fileStat    *FileStat
	dirents     []os.FileInfo
	noMoreFiles bool

	offset int64

	m sync.Mutex
}

func (f *File) Close() error {
	if f == nil {
		return os.ErrInvalid
	}

	err := f.close()
	if err != nil {
		return &os.PathError{Op: "close", Path: f.name, Err: err}
	}
	return nil
}

func (f *File) close() error {
	if f == nil || f.fd == nil {
		return os.ErrInvalid
	}

	req := &CloseRequest{
		Flags: 0,
	}

	req.CreditCharge = 1

	req.FileId = f.fd

	res, err := f.sendRecv(Smb2Close, req)
	if err != nil {
		return err
	}

	r := CloseResponseDecoder(res)
	if r.IsInvalid() {
		return &InvalidResponseError{"broken close response format"}
	}

	f.fd = nil

	runtime.SetFinalizer(f, nil)

	return nil
}

func (f *File) remove() error {
	info := &SetInfoRequest{
		FileInfoClass:         FileDispositionInformation,
		AdditionalInformation: 0,
		Input: &FileDispositionInformationEncoder{
			DeletePending: 1,
		},
	}

	err := f.setInfo(info)
	if err != nil {
		return err
	}
	return nil
}

func (f *File) Name() string {
	return f.name
}

func (f *File) Read(b []byte) (n int, err error) {
	f.m.Lock()
	defer f.m.Unlock()

	off, err := f.seek(0, io.SeekCurrent)
	if err != nil {
		return -1, &os.PathError{Op: "read", Path: f.name, Err: err}
	}

	n, err = f.readAt(b, off)
	if n != 0 {
		if _, e := f.seek(off+int64(n), io.SeekStart); err == nil {
			err = e
		}
	}
	if err != nil {
		if err, ok := err.(*ResponseError); ok && NtStatus(err.Code) == StatusEndOfFile {
			return n, io.EOF
		}
		return n, &os.PathError{Op: "read", Path: f.name, Err: err}
	}

	return
}

// ReadAt implements io.ReaderAt.
func (f *File) ReadAt(b []byte, off int64) (n int, err error) {
	if off < 0 {
		return -1, os.ErrInvalid
	}

	n, err = f.readAt(b, off)
	if err != nil {
		if err, ok := err.(*ResponseError); ok && NtStatus(err.Code) == StatusEndOfFile {
			return n, io.EOF
		}
		return n, &os.PathError{Op: "read", Path: f.name, Err: err}
	}
	return n, nil
}

const winMaxPayloadSize = 1024 * 1024 // windows system don't accept more than 1M bytes request even though they tell us maxXXXSize > 1M
const singleCreditMaxPayloadSize = 64 * 1024

func (f *File) maxReadSize() int {
	size := int(f.fs.maxReadSize)
	if size > winMaxPayloadSize {
		size = winMaxPayloadSize
	}
	if f.fs.conn.capabilities&Smb2GlobalCapLargeMtu == 0 {
		if size > singleCreditMaxPayloadSize {
			size = singleCreditMaxPayloadSize
		}
	}
	return size
}

func (f *File) maxWriteSize() int {
	size := int(f.fs.maxWriteSize)
	if size > winMaxPayloadSize {
		size = winMaxPayloadSize
	}
	if f.fs.conn.capabilities&Smb2GlobalCapLargeMtu == 0 {
		if size > singleCreditMaxPayloadSize {
			size = singleCreditMaxPayloadSize
		}
	}
	return size
}

func (f *File) maxTransactSize() int {
	size := int(f.fs.maxTransactSize)
	if size > winMaxPayloadSize {
		size = winMaxPayloadSize
	}
	if f.fs.conn.capabilities&Smb2GlobalCapLargeMtu == 0 {
		if size > singleCreditMaxPayloadSize {
			size = singleCreditMaxPayloadSize
		}
	}
	return size
}

func (f *File) readAt(b []byte, off int64) (n int, err error) {
	if off < 0 {
		return -1, os.ErrInvalid
	}

	maxReadSize := f.maxReadSize()

	for {
		switch {
		case len(b)-n == 0:
			return n, nil
		case len(b)-n <= maxReadSize:
			bs, isEOF, err := f.readAtChunk(len(b)-n, int64(n)+off)
			if err != nil {
				if err, ok := err.(*ResponseError); ok && NtStatus(err.Code) == StatusEndOfFile && n != 0 {
					return n, nil
				}
				return 0, err
			}

			n += copy(b[n:], bs)

			if isEOF {
				return n, nil
			}
		default:
			bs, isEOF, err := f.readAtChunk(maxReadSize, int64(n)+off)
			if err != nil {
				if err, ok := err.(*ResponseError); ok && NtStatus(err.Code) == StatusEndOfFile && n != 0 {
					return n, nil
				}
				return 0, err
			}

			n += copy(b[n:], bs)

			if isEOF {
				return n, nil
			}
		}
	}
}

func (f *File) readAtChunk(n int, off int64) (bs []byte, isEOF bool, err error) {
	creditCharge, m, err := f.fs.loanCredit(n)
	defer func() {
		if err != nil {
			f.fs.chargeCredit(creditCharge)
		}
	}()
	if err != nil {
		return nil, false, err
	}

	req := &ReadRequest{
		Padding:         0,
		Flags:           0,
		Length:          uint32(m),
		Offset:          uint64(off),
		MinimumCount:    1, // for returning EOF
		Channel:         0,
		RemainingBytes:  0,
		ReadChannelInfo: nil,
	}

	req.FileId = f.fd

	req.CreditCharge = creditCharge

	res, err := f.sendRecv(Smb2Read, req)
	if err != nil {
		return nil, false, err
	}

	r := ReadResponseDecoder(res)
	if r.IsInvalid() {
		return nil, false, &InvalidResponseError{"broken read response format"}
	}

	bs = r.Data()

	return bs, len(bs) < m, nil
}

func (f *File) Readdir(n int) (fi []os.FileInfo, err error) {
	f.m.Lock()
	defer f.m.Unlock()

	if !f.noMoreFiles {
		if f.dirents == nil {
			f.dirents = []os.FileInfo{}
		}
		for n <= 0 || n > len(f.dirents) {
			dirents, err := f.readdir("*")
			if len(dirents) > 0 {
				f.dirents = append(f.dirents, dirents...)
			}
			if err != nil {
				if err, ok := err.(*ResponseError); ok && NtStatus(err.Code) == StatusNoMoreFiles {
					f.noMoreFiles = true
					break
				}
				return nil, &os.PathError{Op: "readdir", Path: f.name, Err: err}
			}
		}
	}

	fi = f.dirents

	if n > 0 {
		if len(fi) == 0 {
			return fi, io.EOF
		}

		if len(fi) < n {
			f.dirents = []os.FileInfo{}
			return fi, nil
		}

		f.dirents = fi[n:]
		return fi[:n], nil

	}

	f.dirents = []os.FileInfo{}

	return fi, nil
}

func (f *File) Readdirnames(n int) (names []string, err error) {
	fi, err := f.Readdir(n)
	if err != nil {
		return nil, err
	}

	names = make([]string, len(fi))

	for i, st := range fi {
		names[i] = st.Name()
	}

	return names, nil
}

// Seek implements io.Seeker.
func (f *File) Seek(offset int64, whence int) (ret int64, err error) {
	f.m.Lock()
	defer f.m.Unlock()

	ret, err = f.seek(offset, whence)
	if err != nil {
		return ret, &os.PathError{Op: "seek", Path: f.name, Err: err}
	}
	return ret, nil
}

func (f *File) seek(offset int64, whence int) (ret int64, err error) {
	switch whence {
	case io.SeekStart:
		f.offset = offset
	case io.SeekCurrent:
		f.offset += offset
	case io.SeekEnd:
		req := &QueryInfoRequest{
			InfoType:              Smb20InfoFile,
			FileInfoClass:         FileStandardInformation,
			AdditionalInformation: 0,
			Flags:                 0,
			OutputBufferLength:    24,
		}

		infoBytes, err := f.queryInfo(req)
		if err != nil {
			return -1, err
		}

		info := FileStandardInformationDecoder(infoBytes)
		if info.IsInvalid() {
			return -1, &InvalidResponseError{"broken query info response format"}
		}

		f.offset = offset + info.EndOfFile()
	default:
		return -1, os.ErrInvalid
	}

	return f.offset, nil
}

func (f *File) Stat() (os.FileInfo, error) {
	fi, err := f.stat()
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: f.name, Err: err}
	}
	return fi, nil
}

func (f *File) stat() (os.FileInfo, error) {
	req := &QueryInfoRequest{
		InfoType:              Smb20InfoFile,
		FileInfoClass:         FileAllInformation,
		AdditionalInformation: 0,
		Flags:                 0,
		OutputBufferLength:    uint32(f.maxTransactSize()),
	}

	infoBytes, err := f.queryInfo(req)
	if err != nil {
		return nil, err
	}

	info := FileAllInformationDecoder(infoBytes)
	if info.IsInvalid() {
		return nil, &InvalidResponseError{"broken query info response format"}
	}

	basic := info.BasicInformation()
	std := info.StandardInformation()

	return &FileStat{
		CreationTime:   time.Unix(0, basic.CreationTime().Nanoseconds()),
		LastAccessTime: time.Unix(0, basic.LastAccessTime().Nanoseconds()),
		LastWriteTime:  time.Unix(0, basic.LastWriteTime().Nanoseconds()),
		ChangeTime:     time.Unix(0, basic.ChangeTime().Nanoseconds()),
		EndOfFile:      std.EndOfFile(),
		AllocationSize: std.AllocationSize(),
		FileAttributes: basic.FileAttributes(),
		FileName:       base(f.name),
	}, nil
}

func (f *File) Statfs() (FileFsInfo, error) {
	fi, err := f.statfs()
	if err != nil {
		return nil, &os.PathError{Op: "statfs", Path: f.name, Err: err}
	}
	return fi, nil
}

type FileFsInfo interface {
	BlockSize() uint64
	FragmentSize() uint64
	TotalBlockCount() uint64
	FreeBlockCount() uint64
	AvailableBlockCount() uint64
}

type fileFsFullSizeInformation struct {
	TotalAllocationUnits           int64
	CallerAvailableAllocationUnits int64
	ActualAvailableAllocationUnits int64
	SectorsPerAllocationUnit       uint32
	BytesPerSector                 uint32
}

func (fi *fileFsFullSizeInformation) BlockSize() uint64 {
	return uint64(fi.BytesPerSector)
}

func (fi *fileFsFullSizeInformation) FragmentSize() uint64 {
	return uint64(fi.SectorsPerAllocationUnit)
}

func (fi *fileFsFullSizeInformation) TotalBlockCount() uint64 {
	return uint64(fi.TotalAllocationUnits)
}

func (fi *fileFsFullSizeInformation) FreeBlockCount() uint64 {
	return uint64(fi.ActualAvailableAllocationUnits)
}

func (fi *fileFsFullSizeInformation) AvailableBlockCount() uint64 {
	return uint64(fi.CallerAvailableAllocationUnits)
}

func (f *File) statfs() (FileFsInfo, error) {
	req := &QueryInfoRequest{
		InfoType:              Smb20InfoFilesystem,
		FileInfoClass:         FileFsFullSizeInformation,
		AdditionalInformation: 0,
		Flags:                 0,
		OutputBufferLength:    32,
	}

	infoBytes, err := f.queryInfo(req)
	if err != nil {
		return nil, err
	}

	info := FileFsFullSizeInformationDecoder(infoBytes)
	if info.IsInvalid() {
		return nil, &InvalidResponseError{"broken query info response format"}
	}

	return &fileFsFullSizeInformation{
		TotalAllocationUnits:           info.TotalAllocationUnits(),
		CallerAvailableAllocationUnits: info.CallerAvailableAllocationUnits(),
		ActualAvailableAllocationUnits: info.ActualAvailableAllocationUnits(),
		SectorsPerAllocationUnit:       info.SectorsPerAllocationUnit(),
		BytesPerSector:                 info.BytesPerSector(),
	}, nil
}

func (f *File) Sync() (err error) {
	req := new(FlushRequest)
	req.FileId = f.fd

	req.CreditCharge, _, err = f.fs.loanCredit(0)
	defer func() {
		if err != nil {
			f.fs.chargeCredit(req.CreditCharge)
		}
	}()
	if err != nil {
		return &os.PathError{Op: "sync", Path: f.name, Err: err}
	}

	res, err := f.sendRecv(Smb2Flush, req)
	if err != nil {
		return &os.PathError{Op: "sync", Path: f.name, Err: err}
	}

	r := FlushResponseDecoder(res)
	if r.IsInvalid() {
		return &os.PathError{Op: "sync", Path: f.name, Err: &InvalidResponseError{"broken flush response format"}}
	}

	return nil
}

func (f *File) Truncate(size int64) error {
	if size < 0 {
		return os.ErrInvalid
	}

	err := f.truncate(size)
	if err != nil {
		return &os.PathError{Op: "truncate", Path: f.name, Err: err}
	}
	return nil
}

func (f *File) truncate(size int64) error {
	info := &SetInfoRequest{
		FileInfoClass:         FileEndOfFileInformation,
		AdditionalInformation: 0,
		Input: &FileEndOfFileInformationEncoder{
			EndOfFile: size,
		},
	}

	err := f.setInfo(info)
	if err != nil {
		return err
	}
	return nil
}

func (f *File) Chmod(mode os.FileMode) error {
	err := f.chmod(mode)
	if err != nil {
		return &os.PathError{Op: "chmod", Path: f.name, Err: err}
	}
	return nil
}

func (f *File) chmod(mode os.FileMode) error {
	req := &QueryInfoRequest{
		InfoType:              Smb20InfoFile,
		FileInfoClass:         FileBasicInformation,
		AdditionalInformation: 0,
		Flags:                 0,
		OutputBufferLength:    40,
	}

	infoBytes, err := f.queryInfo(req)
	if err != nil {
		return err
	}

	base := FileBasicInformationDecoder(infoBytes)
	if base.IsInvalid() {
		return &InvalidResponseError{"broken query info response format"}
	}

	attrs := base.FileAttributes()

	if mode&0200 != 0 {
		attrs &^= FileAttributeReadonly
	} else {
		attrs |= FileAttributeReadonly
	}

	info := &SetInfoRequest{
		FileInfoClass:         FileBasicInformation,
		AdditionalInformation: 0,
		Input: &FileBasicInformationEncoder{
			FileAttributes: attrs,
		},
	}

	err = f.setInfo(info)
	if err != nil {
		return err
	}
	return nil
}

func (f *File) Write(b []byte) (n int, err error) {
	f.m.Lock()
	defer f.m.Unlock()

	off, err := f.seek(0, io.SeekCurrent)
	if err != nil {
		return -1, &os.PathError{Op: "write", Path: f.name, Err: err}
	}

	n, err = f.writeAt(b, off)
	if n != 0 {
		if _, e := f.seek(off+int64(n), io.SeekStart); err == nil {
			err = e
		}
	}
	if err != nil {
		return n, &os.PathError{Op: "write", Path: f.name, Err: err}
	}

	return n, nil
}

// WriteAt implements io.WriterAt.
func (f *File) WriteAt(b []byte, off int64) (n int, err error) {
	n, err = f.writeAt(b, off)
	if err != nil {
		return n, &os.PathError{Op: "write", Path: f.name, Err: err}
	}
	return n, nil
}

func (f *File) writeAt(b []byte, off int64) (n int, err error) {
	if off < 0 {
		return -1, os.ErrInvalid
	}

	if len(b) == 0 {
		return 0, nil
	}

	maxWriteSize := f.maxWriteSize()

	for {
		switch {
		case len(b)-n == 0:
			return n, nil
		case len(b)-n <= maxWriteSize:
			m, err := f.writeAtChunk(b[n:], int64(n)+off)
			if err != nil {
				return -1, err
			}

			n += m
		default:
			m, err := f.writeAtChunk(b[n:n+maxWriteSize], int64(n)+off)
			if err != nil {
				return -1, err
			}

			n += m
		}
	}
}

// writeAt allows partial write
func (f *File) writeAtChunk(b []byte, off int64) (n int, err error) {
	creditCharge, m, err := f.fs.loanCredit(len(b))
	defer func() {
		if err != nil {
			f.fs.chargeCredit(creditCharge)
		}
	}()
	if err != nil {
		return 0, err
	}

	req := &WriteRequest{
		Flags:            0,
		Channel:          0,
		RemainingBytes:   0,
		Offset:           uint64(off),
		WriteChannelInfo: nil,
		Data:             b[:m],
	}

	req.FileId = f.fd

	req.CreditCharge = creditCharge

	res, err := f.sendRecv(Smb2Write, req)
	if err != nil {
		return 0, err
	}

	r := WriteResponseDecoder(res)
	if r.IsInvalid() {
		return 0, &InvalidResponseError{"broken write response format"}
	}

	return int(r.Count()), nil
}

func copyBuffer(r io.Reader, w io.Writer, buf []byte) (n int64, err error) {
	for {
		nr, er := r.Read(buf)
		if nr > 0 {
			nw, ew := w.Write(buf[:nr])
			if nw > 0 {
				n += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return
}

func (f *File) copyTo(wf *File) (supported bool, n int64, err error) {
	f.m.Lock()
	defer f.m.Unlock()

	req := &IoctlRequest{
		CtlCode:           FsctlSrvRequestResumeKey,
		OutputOffset:      0,
		OutputCount:       0,
		MaxInputResponse:  0,
		MaxOutputResponse: 32,
		Flags:             Smb20IoctlIsFsctl,
	}

	output, err := f.ioctl(req)
	if err != nil {
		if rerr, ok := err.(*ResponseError); ok && NtStatus(rerr.Code) == StatusNotSupported {
			return false, -1, nil
		}

		return true, -1, &os.LinkError{Op: "copy", Old: f.name, New: wf.name, Err: err}

	}

	sr := SrvRequestResumeKeyResponseDecoder(output)
	if sr.IsInvalid() {
		return true, -1, &os.LinkError{Op: "copy", Old: f.name, New: wf.name, Err: &InvalidResponseError{"broken srv request resume key response format"}}
	}

	off, err := f.seek(0, io.SeekCurrent)
	if err != nil {
		return true, -1, &os.LinkError{Op: "copy", Old: f.name, New: wf.name, Err: err}
	}

	end, err := f.seek(0, io.SeekEnd)
	if err != nil {
		return true, -1, &os.LinkError{Op: "copy", Old: f.name, New: wf.name, Err: err}
	}

	woff, err := wf.seek(0, io.SeekCurrent)
	if err != nil {
		return true, -1, &os.LinkError{Op: "copy", Old: f.name, New: wf.name, Err: err}
	}

	var chunks []*SrvCopychunk

	remains := end

	for {
		const maxChunkSize = 1024 * 1024
		const maxTotalSize = 16 * 1024 * 1024
		// https://msdn.microsoft.com/en-us/library/cc512134(v=vs.85).aspx

		if remains < maxTotalSize {
			nchunks := remains / maxChunkSize

			chunks = make([]*SrvCopychunk, nchunks, nchunks+1)
			for i := range chunks {
				chunks[i] = &SrvCopychunk{
					SourceOffset: off + int64(i)*maxChunkSize,
					TargetOffset: woff + int64(i)*maxChunkSize,
					Length:       maxChunkSize,
				}
			}

			remains %= maxChunkSize
			if remains != 0 {
				chunks = append(chunks, &SrvCopychunk{
					SourceOffset: off + int64(nchunks)*maxChunkSize,
					TargetOffset: woff + int64(nchunks)*maxChunkSize,
					Length:       uint32(remains),
				})
				remains = 0
			}
		} else {
			chunks = make([]*SrvCopychunk, 16)
			for i := range chunks {
				chunks[i] = &SrvCopychunk{
					SourceOffset: off + int64(i)*maxChunkSize,
					TargetOffset: woff + int64(i)*maxChunkSize,
					Length:       maxChunkSize,
				}
			}

			remains -= maxTotalSize
		}

		scc := &SrvCopychunkCopy{
			Chunks: chunks,
		}

		copy(scc.SourceKey[:], sr.ResumeKey())

		cReq := &IoctlRequest{
			CtlCode:           FsctlSrvCopychunk,
			OutputOffset:      0,
			OutputCount:       0,
			MaxInputResponse:  0,
			MaxOutputResponse: 24,
			Flags:             Smb20IoctlIsFsctl,
			Input:             scc,
		}

		output, err = wf.ioctl(cReq)
		if err != nil {
			return true, -1, &os.LinkError{Op: "copy", Old: f.name, New: wf.name, Err: err}
		}

		c := SrvCopychunkResponseDecoder(output)
		if c.IsInvalid() {
			return true, -1, &os.LinkError{Op: "copy", Old: f.name, New: wf.name, Err: &InvalidResponseError{"broken srv copy chunk response format"}}
		}

		n += int64(c.TotalBytesWritten())

		if remains == 0 {
			return true, n, nil
		}
	}
}

// ReadFrom implements io.ReadFrom.
// If r is *File on the same *Share as f, it invokes server-side copy.
func (f *File) ReadFrom(r io.Reader) (n int64, err error) {
	rf, ok := r.(*File)
	if ok && rf.fs == f.fs {
		if supported, n, err := rf.copyTo(f); supported {
			return n, err
		}

		maxBufferSize := f.maxReadSize()
		if maxWriteSize := f.maxWriteSize(); maxWriteSize < maxBufferSize {
			maxBufferSize = maxWriteSize
		}

		return copyBuffer(r, f, make([]byte, maxBufferSize))
	}

	return copyBuffer(r, f, make([]byte, f.maxWriteSize()))
}

// WriteTo implements io.WriteTo.
// If w is *File on the same *Share as f, it invokes server-side copy.
func (f *File) WriteTo(w io.Writer) (n int64, err error) {
	wf, ok := w.(*File)
	if ok && wf.fs == f.fs {
		if supported, n, err := f.copyTo(wf); supported {
			return n, err
		}

		maxBufferSize := f.maxReadSize()
		if maxWriteSize := f.maxWriteSize(); maxWriteSize < maxBufferSize {
			maxBufferSize = maxWriteSize
		}

		return copyBuffer(f, w, make([]byte, maxBufferSize))
	}

	return copyBuffer(f, w, make([]byte, f.maxReadSize()))
}

func (f *File) WriteString(s string) (n int, err error) {
	return f.Write([]byte(s))
}

func (f *File) encodeSize(e Encoder) int {
	if e == nil {
		return 0
	}
	return e.Size()
}

func (f *File) ioctl(req *IoctlRequest) (output []byte, err error) {
	payloadSize := f.encodeSize(req.Input) + int(req.OutputCount)
	if payloadSize < int(req.MaxOutputResponse+req.MaxInputResponse) {
		payloadSize = int(req.MaxOutputResponse + req.MaxInputResponse)
	}

	if f.maxTransactSize() < payloadSize {
		return nil, &InternalError{fmt.Sprintf("payload size %d exceeds max transact size %d", payloadSize, f.maxTransactSize())}
	}

	req.CreditCharge, _, err = f.fs.loanCredit(payloadSize)
	defer func() {
		if err != nil {
			f.fs.chargeCredit(req.CreditCharge)
		}
	}()
	if err != nil {
		return nil, err
	}

	req.FileId = f.fd

	res, err := f.sendRecv(Smb2Ioctl, req)
	if err != nil {
		r := IoctlResponseDecoder(res)
		if r.IsInvalid() {
			return nil, err
		}
		return r.Output(), err
	}

	r := IoctlResponseDecoder(res)
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken ioctl response format"}
	}

	return r.Output(), nil
}

func (f *File) readdir(pattern string) (fi []os.FileInfo, err error) {
	req := &QueryDirectoryRequest{
		FileInfoClass:      FileDirectoryInformation,
		Flags:              0,
		FileIndex:          0,
		OutputBufferLength: uint32(f.maxTransactSize()),
		FileName:           pattern,
	}

	payloadSize := int(req.OutputBufferLength)

	if f.maxTransactSize() < payloadSize {
		return nil, &InternalError{fmt.Sprintf("payload size %d exceeds max transact size %d", payloadSize, f.maxTransactSize())}
	}

	req.CreditCharge, _, err = f.fs.loanCredit(payloadSize)
	defer func() {
		if err != nil {
			f.fs.chargeCredit(req.CreditCharge)
		}
	}()
	if err != nil {
		return nil, err
	}

	req.FileId = f.fd

	res, err := f.sendRecv(Smb2QueryDirectory, req)
	if err != nil {
		return nil, err
	}

	r := QueryDirectoryResponseDecoder(res)
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken query directory response format"}
	}

	output := r.OutputBuffer()

	for {
		info := FileDirectoryInformationDecoder(output)
		if info.IsInvalid() {
			return nil, &InvalidResponseError{"broken query directory response format"}
		}

		name := info.FileName()

		if name != "." && name != ".." {
			fi = append(fi, &FileStat{
				CreationTime:   time.Unix(0, info.CreationTime().Nanoseconds()),
				LastAccessTime: time.Unix(0, info.LastAccessTime().Nanoseconds()),
				LastWriteTime:  time.Unix(0, info.LastWriteTime().Nanoseconds()),
				ChangeTime:     time.Unix(0, info.ChangeTime().Nanoseconds()),
				EndOfFile:      info.EndOfFile(),
				AllocationSize: info.AllocationSize(),
				FileAttributes: info.FileAttributes(),
				FileName:       name,
			})
		}

		next := info.NextEntryOffset()
		if next == 0 {
			return fi, nil
		}

		output = output[next:]
	}
}

func (f *File) queryInfo(req *QueryInfoRequest) (infoBytes []byte, err error) {
	payloadSize := f.encodeSize(req.Input)
	if payloadSize < int(req.OutputBufferLength) {
		payloadSize = int(req.OutputBufferLength)
	}

	if f.maxTransactSize() < payloadSize {
		return nil, &InternalError{fmt.Sprintf("payload size %d exceeds max transact size %d", payloadSize, f.maxTransactSize())}
	}

	req.CreditCharge, _, err = f.fs.loanCredit(payloadSize)
	defer func() {
		if err != nil {
			f.fs.chargeCredit(req.CreditCharge)
		}
	}()
	if err != nil {
		return nil, err
	}

	req.FileId = f.fd

	res, err := f.sendRecv(Smb2QueryInfo, req)
	if err != nil {
		return nil, err
	}

	r := QueryInfoResponseDecoder(res)
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken query info response format"}
	}

	return r.OutputBuffer(), nil
}

func (f *File) setInfo(req *SetInfoRequest) (err error) {
	payloadSize := f.encodeSize(req.Input)

	if f.maxTransactSize() < payloadSize {
		return &InternalError{fmt.Sprintf("payload size %d exceeds max transact size %d", payloadSize, f.maxTransactSize())}
	}

	req.CreditCharge, _, err = f.fs.loanCredit(payloadSize)
	defer func() {
		if err != nil {
			f.fs.chargeCredit(req.CreditCharge)
		}
	}()
	if err != nil {
		return err
	}

	req.FileId = f.fd

	req.InfoType = Smb20InfoFile

	res, err := f.sendRecv(Smb2SetInfo, req)
	if err != nil {
		return err
	}

	r := SetInfoResponseDecoder(res)
	if r.IsInvalid() {
		return &InvalidResponseError{"broken set info response format"}
	}

	return nil
}

func (f *File) sendRecv(cmd uint16, req Packet) (res []byte, err error) {
	return f.fs.sendRecv(cmd, req)
}

type FileStat struct {
	CreationTime   time.Time
	LastAccessTime time.Time
	LastWriteTime  time.Time
	ChangeTime     time.Time
	EndOfFile      int64
	AllocationSize int64
	FileAttributes uint32
	FileName       string
}

func (fs *FileStat) Name() string {
	return fs.FileName
}

func (fs *FileStat) Size() int64 {
	return fs.EndOfFile
}

func (fs *FileStat) Mode() os.FileMode {
	var m os.FileMode

	if fs.FileAttributes&FileAttributeDirectory != 0 {
		m |= os.ModeDir | 0111
	}

	if fs.FileAttributes&FileAttributeReadonly != 0 {
		m |= 0444
	} else {
		m |= 0666
	}

	if fs.FileAttributes&FileAttributeReparsePoint != 0 {
		m |= os.ModeSymlink
	}

	return m
}

func (fs *FileStat) ModTime() time.Time {
	return fs.LastWriteTime
}

func (fs *FileStat) IsDir() bool {
	return fs.Mode().IsDir()
}

func (fs *FileStat) Sys() interface{} {
	return fs
}
