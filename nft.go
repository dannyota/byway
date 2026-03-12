package main

import (
	"encoding/binary"
	"fmt"
	"log/slog"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

const (
	nftTableName = "byway"
	nftChainName = "output"
)

// NFT manages the nftables table, chain, and rule for cgroup-based fwmark.
type NFT struct {
	conn   *nftables.Conn
	table  *nftables.Table
	chain  *nftables.Chain
	logger *slog.Logger
}

func NewNFT(logger *slog.Logger) *NFT {
	return &NFT{
		conn:   &nftables.Conn{},
		logger: logger,
	}
}

// Adopt checks if a valid byway nftables table already exists (e.g. from a
// previous crashed run) and adopts it, avoiding a brief routing gap on restart.
// Returns true if the table was adopted. Must only be called at daemon startup.
func (n *NFT) Adopt() bool {
	table, chain, ok := n.verify()
	if !ok {
		return false
	}
	n.table = table
	n.chain = chain
	n.logger.Info("adopted existing nftables table")
	return true
}

// Setup creates the inet byway table with a route chain and cgroup mark rule.
// Always deletes any existing table first and creates fresh — use Adopt() at
// daemon startup to skip this if the existing table is valid.
//
// Equivalent nftables ruleset:
//
//	table inet byway {
//	    chain output {
//	        type route hook output priority mangle;
//	        socket cgroupv2 level 1 <cgroupID> meta mark set 0x100
//	    }
//	}
//
// Chain type MUST be "route" (not "filter") so the kernel re-evaluates
// routing after the fwmark is set.
func (n *NFT) Setup(cgroupID uint64, fwmark uint32) error {
	// Delete any existing table for idempotency.
	n.conn.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: nftTableName})
	n.conn.Flush() // ignore error — table may not exist

	n.table = n.conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   nftTableName,
	})

	n.chain = n.conn.AddChain(&nftables.Chain{
		Name:     nftChainName,
		Table:    n.table,
		Type:     nftables.ChainTypeRoute,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityMangle,
	})

	// Cgroup ID as 4-byte native-endian uint32.
	// The kernfs node ID (from stat().Ino) fits in 32 bits; nftables
	// stores it as uint32 in the register.
	cgBytes := make([]byte, 4)
	binary.NativeEndian.PutUint32(cgBytes, uint32(cgroupID))

	fwBytes := make([]byte, 4)
	binary.NativeEndian.PutUint32(fwBytes, fwmark)

	n.conn.AddRule(&nftables.Rule{
		Table: n.table,
		Chain: n.chain,
		Exprs: []expr.Any{
			// Load the socket's cgroup v2 ID at ancestor level 1 into register 1.
			// Level 1 = direct child of cgroupfs root = /sys/fs/cgroup/byway.
			&expr.Socket{
				Key:      expr.SocketKeyCgroupv2,
				Level:    1,
				Register: 1,
			},
			// Compare register 1 against our cgroup's ID.
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     cgBytes,
			},
			// Load the fwmark value into register 1.
			&expr.Immediate{
				Register: 1,
				Data:     fwBytes,
			},
			// Set the packet mark from register 1.
			&expr.Meta{
				Key:            expr.MetaKeyMARK,
				SourceRegister: true,
				Register:       1,
			},
		},
	})

	if err := n.conn.Flush(); err != nil {
		return fmt.Errorf("nftables flush: %w", err)
	}
	return nil
}

// Teardown deletes the byway table and all its chains/rules.
func (n *NFT) Teardown() error {
	if n.table == nil {
		// No local reference — try to delete by name (crash recovery).
		// Flush error is ignored: table may not exist.
		n.conn.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: nftTableName})
		n.conn.Flush()
		return nil
	}
	n.conn.DelTable(n.table)
	if err := n.conn.Flush(); err != nil {
		return fmt.Errorf("nftables teardown: %w", err)
	}
	n.table = nil
	n.chain = nil
	return nil
}

// Verify checks that the byway table, output chain, and at least one rule exist.
func (n *NFT) Verify() (bool, error) {
	_, _, ok := n.verify()
	return ok, nil
}

// verify does the actual kernel lookup and returns the found table/chain.
func (n *NFT) verify() (*nftables.Table, *nftables.Chain, bool) {
	tables, err := n.conn.ListTables()
	if err != nil {
		return nil, nil, false
	}
	table := findTable(tables)
	if table == nil {
		return nil, nil, false
	}

	chains, err := n.conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return nil, nil, false
	}
	chain := findChain(chains)
	if chain == nil {
		return nil, nil, false
	}

	rules, err := n.conn.GetRules(table, chain)
	if err != nil {
		// Stale reference — treat as missing, Setup will recreate.
		return nil, nil, false
	}
	if len(rules) == 0 {
		return nil, nil, false
	}

	return table, chain, true
}

func findTable(tables []*nftables.Table) *nftables.Table {
	for _, t := range tables {
		if t.Name == nftTableName && t.Family == nftables.TableFamilyINet {
			return t
		}
	}
	return nil
}

func findChain(chains []*nftables.Chain) *nftables.Chain {
	for _, c := range chains {
		if c.Table.Name == nftTableName && c.Name == nftChainName {
			return c
		}
	}
	return nil
}
