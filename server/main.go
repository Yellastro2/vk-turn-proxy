package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

type streamEntry struct {
	id   byte
	conn net.Conn
}

const (
	handshakeTimeout   = 30 * time.Second
	streamIdleTimeout  = 5 * time.Minute
	sessionIdleTimeout = 5 * time.Minute
)

var pendingHandshakes atomic.Int64

type UserSession struct {
	ID               string
	Conns            []streamEntry
	BackendConn      net.Conn
	Lock             sync.RWMutex
	Ctx              context.Context
	Cancel           context.CancelFunc
	Manager          *SessionManager
	Closing          bool
	CleanupOnce      sync.Once
	idleCleanupTimer *time.Timer
}

type SessionManager struct {
	Sessions map[string]*UserSession
	Lock     sync.RWMutex
}

type sessionStats struct {
	sessions int
	streams  int
}

func (s *SessionManager) Stats() sessionStats {
	s.Lock.RLock()
	defer s.Lock.RUnlock()

	stats := sessionStats{
		sessions: len(s.Sessions),
	}
	for _, session := range s.Sessions {
		session.Lock.RLock()
		stats.streams += len(session.Conns)
		session.Lock.RUnlock()
	}
	return stats
}

func (s *SessionManager) GetOrCreate(ctx context.Context, id string, connectAddr string) (*UserSession, error) {
	s.Lock.Lock()
	defer s.Lock.Unlock()

	if session, ok := s.Sessions[id]; ok {
		session.Lock.RLock()
		closing := session.Closing
		session.Lock.RUnlock()
		if !closing {
			return session, nil
		}
		delete(s.Sessions, id)
	}

	backendConn, err := net.Dial("udp", connectAddr)
	if err != nil {
		return nil, err
	}

	sessionCtx, cancel := context.WithCancel(ctx)
	session := &UserSession{
		ID:          id,
		Conns:       make([]streamEntry, 0),
		BackendConn: backendConn,
		Manager:     s,
		Ctx:         sessionCtx,
		Cancel:      cancel,
	}
	s.Sessions[id] = session
	go session.backendReaderLoop()

	return session, nil
}

func (s *UserSession) backendReaderLoop() {
	defer s.Cleanup()
	buf := make([]byte, 1600)
	var lastUsed uint32 = 0
	for {
		select {
		case <-s.Ctx.Done():
			return
		default:
		}

		s.BackendConn.SetReadDeadline(time.Now().Add(streamIdleTimeout))
		n, err := s.BackendConn.Read(buf)
		if err != nil {
			log.Printf("Session %s backend read error: %v", s.ID, err)
			return
		}

		s.Lock.RLock()
		nConns := uint32(len(s.Conns))
		if nConns == 0 {
			s.Lock.RUnlock()
			continue
		}

		// Fast Round-robin selection using local variable
		lastUsed = (lastUsed + 1) % nConns
		conn := s.Conns[lastUsed].conn
		s.Lock.RUnlock()

		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))

		_, err = conn.Write(buf[:n])
		if err != nil {
			log.Printf("Session %s DTLS write error: %v", s.ID, err)
			conn.Close()
		}
	}
}

func (s *UserSession) AddConn(id byte, conn net.Conn) error {
	s.Lock.Lock()
	defer s.Lock.Unlock()

	if s.Closing {
		return net.ErrClosed
	}
	if s.idleCleanupTimer != nil {
		s.idleCleanupTimer.Stop()
		s.idleCleanupTimer = nil
	}

	// Evict existing connection with same ID
	for i, entry := range s.Conns {
		if entry.id == id {
			//log.Printf("Session %s: Evicting old stream %d", s.ID, id)
			entry.conn.Close()
			s.Conns[i].conn = conn
			return nil
		}
	}

	s.Conns = append(s.Conns, streamEntry{id: id, conn: conn})
	return nil
}

func (s *UserSession) RemoveConn(id byte, conn net.Conn) {
	s.Lock.Lock()
	defer s.Lock.Unlock()
	if s.Closing {
		return
	}
	for i, entry := range s.Conns {
		if entry.id == id && entry.conn == conn {
			s.Conns = append(s.Conns[:i], s.Conns[i+1:]...)
			break
		}
	}
	if len(s.Conns) == 0 {
		s.scheduleIdleCleanupLocked()
	}
}

func (s *UserSession) scheduleIdleCleanupLocked() {
	if s.idleCleanupTimer != nil {
		s.idleCleanupTimer.Stop()
	}
	s.idleCleanupTimer = time.AfterFunc(sessionIdleTimeout, func() {
		s.Lock.Lock()
		shouldCleanup := !s.Closing && len(s.Conns) == 0
		if shouldCleanup {
			s.Closing = true
		}
		s.Lock.Unlock()

		if shouldCleanup {
			log.Printf("Session %s idle without streams for %v, cleaning up", s.ID, sessionIdleTimeout)
			s.Cleanup()
		}
	})
}

func (s *UserSession) Cleanup() {
	s.CleanupOnce.Do(func() {
		s.Lock.Lock()
		s.Closing = true
		if s.idleCleanupTimer != nil {
			s.idleCleanupTimer.Stop()
			s.idleCleanupTimer = nil
		}
		conns := s.Conns
		s.Conns = nil
		s.Lock.Unlock()

		s.Cancel()
		_ = s.BackendConn.Close()

		s.Manager.Lock.Lock()
		if current, ok := s.Manager.Sessions[s.ID]; ok && current == s {
			delete(s.Manager.Sessions, s.ID)
		}
		s.Manager.Lock.Unlock()

		for _, entry := range conns {
			entry.conn.Close()
		}
	})
}

func processFDStats() (int, int) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1, -1
	}

	socketFDs := 0
	for _, entry := range entries {
		target, err := os.Readlink("/proc/self/fd/" + entry.Name())
		if err != nil {
			continue
		}
		if len(target) >= len("socket:[") && target[:len("socket:[")] == "socket:[" {
			socketFDs++
		}
	}
	return len(entries), socketFDs
}

func diagnosticsLoop(ctx context.Context, manager *SessionManager, relay *wrappedUDPRelay) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stats := manager.Stats()
			fdCount, socketFDs := processFDStats()
			relayClients := 0
			relayUniqueIPs := 0
			if relay != nil {
				relayStats := relay.Stats()
				relayClients = relayStats.clients
				relayUniqueIPs = relayStats.uniqueIPs
			}

			log.Printf(
				"[diagnostics] active_clients~=%d sessions=%d streams=%d pending_handshakes=%d wrap_relay_clients=%d wrap_relay_unique_ips=%d fd=%d socket_fd=%d goroutines=%d",
				stats.sessions,
				stats.sessions,
				stats.streams,
				pendingHandshakes.Load(),
				relayClients,
				relayUniqueIPs,
				fdCount,
				socketFDs,
				runtime.NumGoroutine(),
			)
		}
	}
}

func main() {
	listen := flag.String("listen", "0.0.0.0:56000", "listen on ip:port")
	connect := flag.String("connect", "", "connect to ip:port")
	wrapKeyHex := flag.String("wrap-key", "", "WRAP key as 64 hex characters; empty disables WRAP")
	noDTLS := flag.Bool("no-dtls", false, "accept WRAP datagrams without DTLS")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signalChan
		log.Printf("Terminating...\n")
		cancel()
		<-signalChan
		log.Fatalf("Exit...\n")
	}()

	addr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		panic(err)
	}
	if len(*connect) == 0 {
		log.Panicf("server address is required")
	}

	certificate, genErr := selfsign.GenerateSelfSigned()
	if genErr != nil {
		panic(genErr)
	}

	config := &dtls.Config{
		Certificates:          []tls.Certificate{certificate},
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.RandomCIDGenerator(8),
	}

	manager := &SessionManager{
		Sessions: make(map[string]*UserSession),
	}

	if *wrapKeyHex != "" {
		wrapKey, err := decodeWrapKey(*wrapKeyHex)
		if err != nil {
			log.Fatalf("Invalid WRAP key: %v", err)
		}

		publicConn, err := net.ListenPacket("udp", *listen)
		if err != nil {
			panic(err)
		}
		context.AfterFunc(ctx, func() {
			publicConn.Close()
		})

		if *noDTLS {
			log.Printf("Listening on %s with WRAP/no-DTLS, forwarding to %s", *listen, *connect)
			go diagnosticsLoop(ctx, manager, nil)
			serveWrappedNoDTLS(ctx, publicConn, manager, *connect, wrapKey)
			return
		}

		internalAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		if err != nil {
			panic(err)
		}
		listener, err := dtls.Listen("udp", internalAddr, config)
		if err != nil {
			panic(err)
		}
		context.AfterFunc(ctx, func() {
			listener.Close()
		})

		relay := newWrappedUDPRelay(publicConn, listener.Addr(), wrapKey)
		go relay.Run(ctx)
		log.Printf("Listening on %s with WRAP/DTLS, forwarding to %s", *listen, *connect)
		go diagnosticsLoop(ctx, manager, relay)
		serveDTLS(ctx, listener, manager, *connect)
		return
	}

	listener, err := dtls.Listen("udp", addr, config)
	if err != nil {
		panic(err)
	}
	context.AfterFunc(ctx, func() {
		listener.Close()
	})
	log.Printf("Listening on %s with DTLS, forwarding to %s", *listen, *connect)
	go diagnosticsLoop(ctx, manager, nil)
	serveDTLS(ctx, listener, manager, *connect)
}

func serveDTLS(ctx context.Context, listener net.Listener, manager *SessionManager, connectAddr string) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Println("Accept error:", err)
				continue
			}
		}

		go func(conn net.Conn) {
			defer conn.Close()

			dtlsConn, ok := conn.(*dtls.Conn)
			if !ok {
				return
			}

			handshakeCtx, hCancel := context.WithTimeout(ctx, handshakeTimeout)
			defer hCancel()

			pendingHandshakes.Add(1)
			if err := dtlsConn.HandshakeContext(handshakeCtx); err != nil {
				pendingHandshakes.Add(-1)
				stats := manager.Stats()
				fdCount, socketFDs := processFDStats()
				log.Printf(
					"Handshake failed from %s: %v (sessions=%d streams=%d pending_handshakes=%d fd=%d socket_fd=%d goroutines=%d)",
					conn.RemoteAddr(),
					err,
					stats.sessions,
					stats.streams,
					pendingHandshakes.Load(),
					fdCount,
					socketFDs,
					runtime.NumGoroutine(),
				)
				return
			}
			pendingHandshakes.Add(-1)

			// Phase 1: Read Session ID + Stream ID (17 bytes)
			idBuf := make([]byte, 17)
			conn.SetReadDeadline(time.Now().Add(time.Second * 5))
			_, err := io.ReadFull(conn, idBuf)
			if err != nil {
				log.Printf("Failed to read session ID from %s: %v", conn.RemoteAddr(), err)
				return
			}
			sessionID := fmt.Sprintf("%x", idBuf[:16])
			streamID := idBuf[16]

			session, err := manager.GetOrCreate(ctx, sessionID, connectAddr)
			if err != nil {
				log.Println("Failed to get/create session:", err)
				return
			}

			if err := session.AddConn(streamID, conn); err != nil {
				log.Printf("Failed to add stream %d for session %s from %s: %v", streamID, sessionID, conn.RemoteAddr(), err)
				return
			}
			defer session.RemoveConn(streamID, conn)

			log.Printf("New stream %d for session %s from %s", streamID, sessionID, conn.RemoteAddr())

			// Upstream Loop: DTLS -> Backend
			buf := make([]byte, 1600)
			for {
				conn.SetReadDeadline(time.Now().Add(streamIdleTimeout))
				n, err := conn.Read(buf)
				if err != nil {
					log.Printf("Stream %s closed: %v", sessionID, err)
					return
				}

				session.BackendConn.SetWriteDeadline(time.Now().Add(time.Second * 5))
				_, err = session.BackendConn.Write(buf[:n])
				if err != nil {
					log.Printf("Session %s backend write error: %v", sessionID, err)
					return
				}
			}
		}(conn)
	}
}
