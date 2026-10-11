// Command xds-conformance-fixture is a minimal ADS server built directly on
// go-control-plane's own cache and server packages -- not a reimplementation
// of the xDS wire protocol, which would defeat the entire point of the
// conformance check (see testing/xds-conformance/README.md). It serves ONE fixed,
// node-scoped CDS snapshot and exits; there is no scripting or reconfiguring
// at runtime, because this fixture's only job is to be a real third-party
// ADS server our client either agrees with or doesn't.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sync"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cachetypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	serverv3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"google.golang.org/grpc"
)

// The one node ID this fixture's snapshot is set for. go-control-plane's
// SnapshotCache is keyed by node ID (see cachev3.IDHash{}) and, left to
// itself, simply never replies to a client announcing any other ID --
// a silent hang, not a failure. A real bug once had
// our client sent no node at all, and this is precisely the class of
// mistake a node-scoped snapshot is meant to catch: see nodeGuard below,
// which turns that silent hang into an immediate, named gRPC error.
const expectedNodeID = "llm-proxy-conformance-test"

// nodeGuard rejects any stream whose FIRST request does not carry
// node.id == expectedNodeID.
//
// Rust note for the repo owner reading this Go file for the first time:
// this plays the same role a guard clause at the top of a function does in
// Rust -- fail fast, on the exact condition that would otherwise cause a
// silent hang, before falling through to real logic.
type nodeGuard struct {
	mu   sync.Mutex
	seen map[int64]bool
}

func newNodeGuard() *nodeGuard {
	return &nodeGuard{seen: make(map[int64]bool)}
}

func (g *nodeGuard) checkRequest(streamID int64, req *discoveryv3.DiscoveryRequest) error {
	g.mu.Lock()
	first := !g.seen[streamID]
	g.seen[streamID] = true
	g.mu.Unlock()

	if !first {
		// Only the FIRST request of a stream is required to carry node
		// (S8 / Envoy's own GrpcMuxImpl); later requests on the same
		// stream legitimately omit it, and rejecting those would break
		// every ACK/NACK that follows the first request.
		return nil
	}
	if req.Node == nil || req.Node.Id == "" {
		return fmt.Errorf("first DiscoveryRequest on stream %d carried no node.id; this fixture's snapshot is scoped to %q", streamID, expectedNodeID)
	}
	if req.Node.Id != expectedNodeID {
		return fmt.Errorf("stream %d sent node.id %q, this fixture's snapshot is only set for %q", streamID, req.Node.Id, expectedNodeID)
	}
	log.Printf("stream %d: accepted node.id %q", streamID, req.Node.Id)
	return nil
}

func main() {
	listenAddr := os.Getenv("GCP_LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":18000"
	}

	snapshotCache := cachev3.NewSnapshotCache(false, cachev3.IDHash{}, nil)

	// The one resource this fixture serves: a single STATIC cluster over
	// CDS. Minimal on purpose -- the bar is "we interop with
	// a real third-party ADS server", not "we exercise every resource shape".
	cluster := &clusterv3.Cluster{
		Name:                 "conformance-cluster",
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STATIC},
	}

	snap, err := cachev3.NewSnapshot("1", map[string][]cachetypes.Resource{
		resourcev3.ClusterType: {cluster},
	})
	if err != nil {
		log.Fatalf("build snapshot: %v", err)
	}
	if err := snap.Consistent(); err != nil {
		log.Fatalf("inconsistent snapshot: %v", err)
	}
	// Set ONLY for expectedNodeID: see the doc comment on that constant.
	if err := snapshotCache.SetSnapshot(context.Background(), expectedNodeID, snap); err != nil {
		log.Fatalf("set snapshot: %v", err)
	}

	guard := newNodeGuard()
	callbacks := &serverv3.CallbackFuncs{
		StreamOpenFunc: func(_ context.Context, streamID int64, typeURL string) error {
			log.Printf("stream %d opened, typeURL=%q", streamID, typeURL)
			return nil
		},
		StreamRequestFunc: guard.checkRequest,
		StreamResponseFunc: func(_ context.Context, streamID int64, req *discoveryv3.DiscoveryRequest, resp *discoveryv3.DiscoveryResponse) {
			log.Printf("stream %d: sending response version=%s nonce=%s", streamID, resp.VersionInfo, resp.Nonce)
		},
	}

	srv := serverv3.NewServer(context.Background(), snapshotCache, callbacks)
	grpcServer := grpc.NewServer()
	discoveryv3.RegisterAggregatedDiscoveryServiceServer(grpcServer, srv)

	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("listen on %s: %v", listenAddr, err)
	}
	// The Rust test polls for this exact substring in `docker logs` as its
	// readiness check (see testing/xds-conformance/tests/go_control_plane.rs)
	// -- do not reword "READY" without updating it there too.
	log.Printf("READY go-control-plane conformance fixture listening on %s (node.id=%q)", listenAddr, expectedNodeID)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
