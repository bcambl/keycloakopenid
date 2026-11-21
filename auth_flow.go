package keycloakopenid

import (
	"container/list"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// loginLifetime is how long a pending login transaction remains valid.
	loginLifetime = 10 * time.Minute
	// loginCapacity is the fixed number of pending login transactions retained
	// per client before the least recently used are evicted.
	loginCapacity = 1000
	// loginCleanupInterval is how often each shared login store sweeps expired
	// transactions in the background.
	loginCleanupInterval = time.Minute
)

// loginTransaction is one pending authorization-code login. It is single-use:
// Consume removes it atomically so a replayed callback cannot redeem it twice.
type loginTransaction struct {
	nonce        string
	verifier     string
	callbackURI  string
	returnTarget string
	expiresAt    time.Time
}

// loginEntry links a stored transaction to its position in the LRU order.
type loginEntry struct {
	state string
	tx    *loginTransaction
	elem  *list.Element
}

// loginStore is a capacity-bounded, TTL store of pending login transactions
// keyed by state. Transactions are immutable once created, so the store lock
// alone is enough for atomic single-use consumption.
type loginStore struct {
	mu          sync.Mutex
	capacity    int
	callbackURI string
	order       *list.List
	byState     map[string]*list.Element
	startOnce   sync.Once
}

// newLoginStore returns an empty store for one client's fixed callback URI.
func newLoginStore(callbackURI string, capacity int) *loginStore {
	return &loginStore{
		capacity:    capacity,
		callbackURI: callbackURI,
		order:       list.New(),
		byState:     make(map[string]*list.Element),
	}
}

func (l *loginStore) startCleanup() {
	l.startOnce.Do(func() {
		go l.cleanupLoop(loginCleanupInterval)
	})
}

func (l *loginStore) cleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		l.Cleanup(time.Now())
	}
}

// Begin creates a new pending login transaction for the given validated
// relative return target and returns its state, nonce, and PKCE verifier. The
// target is re-validated here as defense in depth so a caller cannot bypass
// safeReturnTarget and store an unsafe redirect.
func (l *loginStore) Begin(returnTarget string) (state, nonce, verifier string, err error) {
	if !isSafeReturnTarget(returnTarget) {
		return "", "", "", errors.New("return target must be a relative path")
	}
	state, err = randomLoginValue()
	if err != nil {
		return "", "", "", err
	}
	nonce, err = randomLoginValue()
	if err != nil {
		return "", "", "", err
	}
	verifier, err = randomLoginValue()
	if err != nil {
		return "", "", "", err
	}

	tx := &loginTransaction{
		nonce:        nonce,
		verifier:     verifier,
		callbackURI:  l.callbackURI,
		returnTarget: returnTarget,
		expiresAt:    time.Now().Add(loginLifetime),
	}

	l.mu.Lock()
	l.setLocked(state, tx)
	l.mu.Unlock()
	return state, nonce, verifier, nil
}

// Consume atomically removes and returns the transaction for state. It reports
// false when the state is unknown or has expired, so a replayed callback can
// never redeem the same transaction twice.
func (l *loginStore) Consume(state string) (loginTransaction, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	elem, ok := l.byState[state]
	if !ok {
		return loginTransaction{}, false
	}
	tx := elem.Value.(*loginEntry).tx
	if !time.Now().Before(tx.expiresAt) {
		l.removeLocked(elem)
		return loginTransaction{}, false
	}
	l.removeLocked(elem)
	return *tx, true
}

func (l *loginStore) setLocked(state string, tx *loginTransaction) {
	entry := &loginEntry{state: state, tx: tx}
	entry.elem = l.order.PushFront(entry)
	l.byState[state] = entry.elem
	l.trimLocked()
}

func (l *loginStore) removeLocked(elem *list.Element) {
	entry := elem.Value.(*loginEntry)
	l.order.Remove(elem)
	delete(l.byState, entry.state)
}

// trimLocked evicts the least recently used transactions until the store is
// within its capacity. The caller must hold the store lock.
func (l *loginStore) trimLocked() {
	for l.order.Len() > l.capacity {
		back := l.order.Back()
		if back == nil {
			return
		}
		l.removeLocked(back)
	}
}

// Cleanup deletes every transaction that has expired as of now.
func (l *loginStore) Cleanup(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for elem := l.order.Front(); elem != nil; {
		next := elem.Next()
		if !now.Before(elem.Value.(*loginEntry).tx.expiresAt) {
			l.removeLocked(elem)
		}
		elem = next
	}
}

// randomLoginValue returns a fresh 256-bit value encoded as unpadded URL-safe
// base64, suitable for a state, nonce, or PKCE verifier.
func randomLoginValue() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// sessionCookieName derives a deterministic host-only cookie name for one
// client. The name depends on the normalized URL, realm, and client encoded in
// clientKey, so every middleware instance for the same client issues the same
// cookie while distinct clients never collide.
func sessionCookieName(clientKey string) string {
	return "__Host-" + cookieDigest(clientKey)
}

// loginCookieName derives a host-only cookie name for one pending login. The
// state is folded into the name so parallel tabs each carry their own login
// cookie without overwriting one another.
func loginCookieName(clientKey, state string) string {
	return "__Host-" + cookieDigest(clientKey+"\x00"+state)
}

func cookieDigest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// loginCookie issues the browser-bound cookie that ties a pending login to its
// state. The value equals the callback state so a callback can locate its
// transaction.
func loginCookie(clientKey, state string) *http.Cookie {
	return &http.Cookie{
		Name:     loginCookieName(clientKey, state),
		Value:    state,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(loginLifetime / time.Second),
	}
}

// clearLoginCookie clears a login cookie, mirroring the issuance attributes so
// the browser matches and deletes the same cookie.
func clearLoginCookie(clientKey, state string) *http.Cookie {
	return &http.Cookie{
		Name:     loginCookieName(clientKey, state),
		Value:    "",
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
}

// sessionCookie issues the host-only cookie that carries a session id.
func sessionCookie(clientKey, sessionID string) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName(clientKey),
		Value:    sessionID,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// clearSessionCookie clears a session cookie, mirroring the issuance
// attributes so the browser matches and deletes the same cookie.
func clearSessionCookie(clientKey string) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName(clientKey),
		Value:    "",
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
}

// safeReturnTarget returns the relative path and query of a request URL as a
// same-origin return target, rejecting absolute, protocol-relative, backslash,
// control-character, and malformed references.
func safeReturnTarget(requestURL *url.URL) (string, error) {
	if requestURL == nil {
		return "", errors.New("return target must not be nil")
	}
	if requestURL.Scheme != "" || requestURL.Host != "" {
		return "", errors.New("return target must be relative")
	}
	if unsafeReturnTarget(requestURL.Path) || unsafeReturnTarget(requestURL.RawPath) || unsafeReturnTarget(requestURL.RawQuery) {
		return "", errors.New("return target contains unsafe characters")
	}
	if requestURL.RawPath != "" {
		if _, err := url.PathUnescape(requestURL.RawPath); err != nil {
			return "", errors.New("return target contains malformed escapes")
		}
	}
	path := requestURL.EscapedPath()
	if path == "" {
		path = "/"
	} else if strings.HasPrefix(path, "//") {
		return "", errors.New("return target must not be protocol-relative")
	} else if !strings.HasPrefix(path, "/") {
		return "", errors.New("return target must be an absolute path")
	}
	target := path
	if requestURL.RawQuery != "" {
		target += "?" + requestURL.RawQuery
	}
	if !isSafeReturnTarget(target) {
		return "", errors.New("return target is unsafe")
	}
	return target, nil
}

// isSafeReturnTarget reports whether s is a safe same-origin return target: a
// non-empty path beginning with exactly one slash (never "//") and containing
// no backslash or control characters. It is the final check applied to both the
// normalized target from safeReturnTarget and the string stored by Begin.
func isSafeReturnTarget(s string) bool {
	if !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") {
		return false
	}
	return !unsafeReturnTarget(s)
}

// unsafeReturnTarget reports whether s contains a backslash or a control
// character, either of which must not appear in a return target.
func unsafeReturnTarget(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' || c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}
