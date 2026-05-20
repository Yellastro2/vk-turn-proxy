package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

const wrapPacketBufferSize = 8192

type wrappedUDPRelay struct {
	public      net.PacketConn
	internal    *net.UDPAddr
	key         []byte
	clients     map[string]*wrappedUDPClient
	clientsLock sync.Mutex
}

type wrappedUDPClient struct {
	id         string
	public     net.PacketConn
	publicAddr net.Addr
	internal   *net.UDPConn
	key        []byte
	relay      *wrappedUDPRelay
	closeOnce  sync.Once
}

// newWrappedUDPRelay bridges public WRAP datagrams to an internal DTLS UDP listener.
func newWrappedUDPRelay(public net.PacketConn, internal net.Addr, key []byte) *wrappedUDPRelay {
	internalUDP, ok := internal.(*net.UDPAddr)
	if !ok {
		panic(fmt.Sprintf("internal DTLS listener has non-UDP address %T", internal))
	}
	return &wrappedUDPRelay{
		public:   public,
		internal: internalUDP,
		key:      key,
		clients:  make(map[string]*wrappedUDPClient),
	}
}

// Run unwraps public packets and forwards them to the internal DTLS listener.
func (r *wrappedUDPRelay) Run(ctx context.Context) {
	buf := make([]byte, wrapPacketBufferSize)
	plain := make([]byte, wrapPacketBufferSize)
	for {
		n, addr, err := r.public.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("WRAP relay read error: %v", err)
				continue
			}
		}

		plainN, err := unwrapPacket(r.key, buf[:n], plain)
		if err != nil {
			log.Printf("WRAP relay: failed to unwrap packet from %s: %v", addr, err)
			continue
		}
		if plainN == 0 {
			continue
		}

		client, err := r.getClient(ctx, addr)
		if err != nil {
			log.Printf("WRAP relay: failed to create client for %s: %v", addr, err)
			continue
		}
		if _, err := client.internal.Write(plain[:plainN]); err != nil {
			log.Printf("WRAP relay: failed to forward packet from %s to DTLS listener: %v", addr, err)
			client.Close()
		}
	}
}

func (r *wrappedUDPRelay) getClient(ctx context.Context, addr net.Addr) (*wrappedUDPClient, error) {
	id := addr.String()
	r.clientsLock.Lock()
	defer r.clientsLock.Unlock()

	if client, ok := r.clients[id]; ok {
		return client, nil
	}

	internalConn, err := net.DialUDP("udp", nil, r.internal)
	if err != nil {
		return nil, err
	}

	client := &wrappedUDPClient{
		id:         id,
		public:     r.public,
		publicAddr: addr,
		internal:   internalConn,
		key:        r.key,
		relay:      r,
	}
	r.clients[id] = client
	go client.readInternal(ctx)
	return client, nil
}

func (r *wrappedUDPRelay) removeClient(id string, client *wrappedUDPClient) {
	r.clientsLock.Lock()
	defer r.clientsLock.Unlock()
	if current, ok := r.clients[id]; ok && current == client {
		delete(r.clients, id)
	}
}

func (c *wrappedUDPClient) readInternal(ctx context.Context) {
	defer c.Close()
	buf := make([]byte, wrapPacketBufferSize)
	for {
		_ = c.internal.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, err := c.internal.Read(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("WRAP relay: internal DTLS read error for %s: %v", c.id, err)
				return
			}
		}

		wrapped, err := wrapPacket(c.key, buf[:n])
		if err != nil {
			log.Printf("WRAP relay: failed to wrap DTLS response for %s: %v", c.id, err)
			return
		}
		if _, err := c.public.WriteTo(wrapped, c.publicAddr); err != nil {
			log.Printf("WRAP relay: failed to write public response to %s: %v", c.id, err)
			return
		}
	}
}

func (c *wrappedUDPClient) Close() {
	c.closeOnce.Do(func() {
		_ = c.internal.Close()
		c.relay.removeClient(c.id, c)
	})
}

type plainWrappedConn struct {
	public net.PacketConn
	addr   net.Addr
	key    []byte
}

// Read is unused for plain WRAP sessions; upstream packets are handled by serveWrappedNoDTLS.
func (c *plainWrappedConn) Read(_ []byte) (int, error) {
	return 0, net.ErrClosed
}

// Write wraps backend payload and sends it to the public client address.
func (c *plainWrappedConn) Write(p []byte) (int, error) {
	wrapped, err := wrapPacket(c.key, p)
	if err != nil {
		return 0, err
	}
	_, err = c.public.WriteTo(wrapped, c.addr)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close satisfies net.Conn; removing the stream is handled by the session owner.
func (c *plainWrappedConn) Close() error { return nil }

// LocalAddr returns the public listener address.
func (c *plainWrappedConn) LocalAddr() net.Addr { return c.public.LocalAddr() }

// RemoteAddr returns the client relay address.
func (c *plainWrappedConn) RemoteAddr() net.Addr { return c.addr }

// SetDeadline is accepted for compatibility with UserSession backend writes.
func (c *plainWrappedConn) SetDeadline(_ time.Time) error { return nil }

// SetReadDeadline is unused for plain WRAP sessions.
func (c *plainWrappedConn) SetReadDeadline(_ time.Time) error { return nil }

// SetWriteDeadline is accepted for compatibility with UserSession backend writes.
func (c *plainWrappedConn) SetWriteDeadline(_ time.Time) error { return nil }

type plainWrappedStream struct {
	session  *UserSession
	streamID byte
	conn     *plainWrappedConn
}

// serveWrappedNoDTLS accepts client WRAP datagrams without a DTLS layer.
func serveWrappedNoDTLS(ctx context.Context, public net.PacketConn, manager *SessionManager, connectAddr string, key []byte) {
	streams := make(map[string]*plainWrappedStream)
	streamsLock := sync.Mutex{}
	buf := make([]byte, wrapPacketBufferSize)
	plain := make([]byte, wrapPacketBufferSize)

	context.AfterFunc(ctx, func() {
		streamsLock.Lock()
		defer streamsLock.Unlock()
		for _, stream := range streams {
			stream.session.RemoveConn(stream.streamID, stream.conn)
		}
	})

	for {
		n, addr, err := public.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("WRAP/no-DTLS read error: %v", err)
				continue
			}
		}

		plainN, err := unwrapPacket(key, buf[:n], plain)
		if err != nil {
			log.Printf("WRAP/no-DTLS: failed to unwrap packet from %s: %v", addr, err)
			continue
		}
		if plainN == 0 {
			continue
		}

		id := addr.String()
		streamsLock.Lock()
		stream := streams[id]
		streamsLock.Unlock()

		if stream == nil {
			if plainN != 17 {
				log.Printf("WRAP/no-DTLS: dropping packet from %s before session handshake, len=%d", addr, plainN)
				continue
			}

			sessionID := fmt.Sprintf("%x", plain[:16])
			streamID := plain[16]
			session, err := manager.GetOrCreate(ctx, sessionID, connectAddr)
			if err != nil {
				log.Printf("WRAP/no-DTLS: failed to get/create session %s: %v", sessionID, err)
				continue
			}
			conn := &plainWrappedConn{public: public, addr: addr, key: key}
			session.AddConn(streamID, conn)

			stream = &plainWrappedStream{
				session:  session,
				streamID: streamID,
				conn:     conn,
			}
			streamsLock.Lock()
			streams[id] = stream
			streamsLock.Unlock()
			log.Printf("New WRAP/no-DTLS stream %d for session %s from %s", streamID, sessionID, addr)
			continue
		}

		stream.session.BackendConn.SetWriteDeadline(time.Now().Add(time.Second * 5))
		if _, err := stream.session.BackendConn.Write(plain[:plainN]); err != nil {
			log.Printf("WRAP/no-DTLS: backend write error for %s: %v", id, err)
			stream.session.RemoveConn(stream.streamID, stream.conn)
			streamsLock.Lock()
			delete(streams, id)
			streamsLock.Unlock()
		}
	}
}
