package u2fserver

// #cgo LDFLAGS: -lu2f-server
// #include <stdlib.h>
// #include <u2f-server/u2f-server.h>
import "C"
import (
	"encoding/base64"
	"unsafe"
)

// Mode Library initialization mode
type Mode C.u2fs_initflags

const (
	// Production mode (no debuginfo printed)
	Production Mode = 0

	// Debug mode (debuginfo printed to console)
	Debug = 1
)

// Server U2F marker struct
type Server struct{}

// Context object
type Context struct {
	ctx *C.u2fs_ctx_t
}

// RegistrationResult relevant data for a well formed request.
type registrationResult struct {
	rr *C.u2fs_reg_res_t
}

// AuthenticationResult  relevant data for a well formed request.
type authenticationResult struct {
	ar *C.u2fs_auth_res_t
}

// Client data
type Client struct {
	Handle string
	PubKey string
}

// Start Must be called successfully before using any other functions.
func Start(mode Mode) (Server, error) {
	rc := C.u2fs_global_init(C.u2fs_initflags(mode))
	return Server{}, iToErr(rc)
}

// Stop Must be called to clen-up system.
func (u2f Server) Stop() {
	C.u2fs_global_done()
}

// Open Create context before registration/authentication calls.
func (u2f Server) Open() (*Context, error) {
	ctx := &Context{}
	rc := C.u2fs_init(&ctx.ctx)
	if rc == 0 {
		return ctx, nil
	}
	return nil, iToErr(rc)
}

// Close Destroy context
func (ctx *Context) Close() {
	C.u2fs_done(ctx.ctx)
}

// SetOrigin - set origin parameter of context
func (ctx *Context) setOrigin(origin string) error {
	txt := C.CString(origin)
	defer C.free(unsafe.Pointer(txt))
	return iToErr(
		C.u2fs_set_origin(ctx.ctx, txt))
}

// SetAppID - set application ID parameter of context
func (ctx *Context) setAppID(appid string) error {
	txt := C.CString(appid)
	defer C.free(unsafe.Pointer(txt))
	return iToErr(
		C.u2fs_set_appid(ctx.ctx, txt))
}

// SetChallenge - set challenge parameter of context
func (ctx *Context) setChallenge(challenge string) error {
	txt := C.CString(challenge)
	defer C.free(unsafe.Pointer(txt))
	return iToErr(
		C.u2fs_set_challenge(ctx.ctx, txt))
}

// SetKeyHandle - set key handle parameter of context
func (ctx *Context) setKeyHandle(keyHandle string) error {
	txt := C.CString(string(keyHandle))
	defer C.free(unsafe.Pointer(txt))
	return iToErr(
		C.u2fs_set_keyHandle(ctx.ctx, txt))
}

// SetPublicKey - set public key parameter of context
func (ctx *Context) setPublicKey(publicKeyT string) error {
	publicKey, err := base64.StdEncoding.DecodeString(publicKeyT)
	if err != nil {
		return ErrBase64
	}
	if len(publicKey) != 65 {
		return ErrInvalidPubKey
	}

	data := C.CBytes(publicKey)
	defer C.free(data)
	return iToErr(
		C.u2fs_set_publicKey(ctx.ctx, (*C.uchar)(data)))
}

// RegistrationChallenge Get a U2F RegistrationData JSON structure, used as the
// challenge in a U2F device registration.
func (ctx *Context) registrationChallenge() (string, error) {
	var output *C.char
	rc := C.u2fs_registration_challenge(ctx.ctx, &output)
	if rc != 0 {
		return "", iToErr(rc)
	}
	return C.GoString(output), nil
}

// RegistrationChallenge Get a U2F RegistrationData JSON structure, used as the
// challenge in a U2F device registration.
func (ctx *Context) RegistrationChallenge(origin string, appid string) (string, error) {
	if err := ctx.setAppID(appid); err != nil {
		return "", err
	}
	if err := ctx.setOrigin(origin); err != nil {
		return "", err
	}
	return ctx.registrationChallenge()
}

// RegistrationVerify Get a U2F registration response and check its validity.
func (ctx *Context) registrationVerify(response string) (*registrationResult, error) {
	output := &registrationResult{}
	txt := C.CString(response)
	defer C.free(unsafe.Pointer(txt))

	rc := C.u2fs_registration_verify(ctx.ctx, txt, &output.rr)
	if rc != 0 {
		return nil, iToErr(rc)
	}
	return output, nil
}

// GetKeyHandle Get the Base64 keyHandle obtained during the U2F registration
// operation.
func (rr *registrationResult) getKeyHandle() string {
	str := C.u2fs_get_registration_keyHandle(rr.rr)
	return C.GoString(str)
}

// GetPublicKey Extract the raw user public key obtained during the U2F
// registration operation.
func (rr *registrationResult) getPublicKey() string {
	data := C.u2fs_get_registration_publicKey(rr.rr)
	slice := C.GoBytes(unsafe.Pointer(data), 65)
	return base64.StdEncoding.EncodeToString(slice)
}

// Free Deallocate resources
func (rr *registrationResult) free() {
	C.u2fs_free_reg_res(rr.rr)
}

// RegistrationVerify Get a U2F registration response and check its validity.
func (ctx *Context) RegistrationVerify(response string) (Client, error) {

	rr, err := ctx.registrationVerify(response)
	if err != nil {
		return Client{}, err
	}
	defer rr.free()

	return Client{Handle: rr.getKeyHandle(), PubKey: rr.getPublicKey()}, nil
}

// AuthenticationChallenge Get a U2F AuthenticationData JSON structure, used as
// the challenge in a U2F authentication procedure.
func (ctx *Context) authenticationChallenge() (string, error) {
	var output *C.char
	rc := C.u2fs_authentication_challenge(ctx.ctx, &output)
	if rc != 0 {
		return "", iToErr(rc)
	}
	return C.GoString(output), nil
}

// AuthenticationChallenge Get a U2F AuthenticationData JSON structure, used as
// the challenge in a U2F authentication procedure.
func (ctx *Context) AuthenticationChallenge(origin string, appid string, client Client) (string, error) {
	if err := ctx.setAppID(appid); err != nil {
		return "", err
	}
	if err := ctx.setOrigin(origin); err != nil {
		return "", err
	}
	if err := ctx.setKeyHandle(client.Handle); err != nil {
		return "", err
	}
	if err := ctx.setPublicKey(client.PubKey); err != nil {
		return "", err
	}
	return ctx.authenticationChallenge()
}

// AuthenticationVerify Get a U2F authentication response and check its validity.
func (ctx *Context) authenticationVerify(response string) (*authenticationResult, error) {
	output := &authenticationResult{}
	txt := C.CString(response)
	defer C.free(unsafe.Pointer(txt))

	rc := C.u2fs_authentication_verify(ctx.ctx, txt, &output.ar)
	if rc != 0 {
		return nil, iToErr(rc)
	}
	return output, nil
}

func (ar *authenticationResult) getResult() (uint32, bool, error) {
	var (
		ver     C.u2fs_rc
		ctr     C.uint32_t
		present C.uint8_t
	)
	rc := C.u2fs_get_authentication_result(ar.ar, &ver, &ctr, &present)
	if rc != 0 {
		return 0, false, iToErr(rc)
	}
	p := present != 0
	return uint32(ctr), p, nil
}

func (ar *authenticationResult) free() {
	C.u2fs_free_auth_res(ar.ar)
}

// AuthenticationVerify Get a U2F authentication response and check its validity.
func (ctx *Context) AuthenticationVerify(response string) (uint32, bool, error) {
	ar, err := ctx.authenticationVerify(response)
	if err != nil {
		return 0, false, err
	}
	defer ar.free()
	return ar.getResult()
}
