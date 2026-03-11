// Generates test vectors for the sia_sdk Rust crate's consensus/merkle tests.
// Output is JSON written to stdout; pipe it to the test vectors file:
//
//	cd sia_sdk/testutil/go-vectors && go run . > ../../src/test_vectors.json
package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	cblake "go.sia.tech/core/blake2b"
	"go.sia.tech/core/types"
)

// Replicate unexported hashAll from types/hash.go
func hashAll(elems ...interface{}) types.Hash256 {
	h := types.NewHasher()
	for _, e := range elems {
		if et, ok := e.(types.EncoderTo); ok {
			et.EncodeTo(h.E)
		} else {
			switch e := e.(type) {
			case string:
				h.WriteDistinguisher(e)
			case uint8:
				h.E.WriteUint8(e)
			case int:
				h.E.WriteUint64(uint64(e))
			case uint64:
				h.E.WriteUint64(e)
			case bool:
				h.E.WriteBool(e)
			default:
				panic(fmt.Sprintf("unhandled type: %T", e))
			}
		}
	}
	return h.Sum()
}

// Replicate unexported leafHash from consensus/merkle.go
func leafHash(eh types.Hash256, leafIndex uint64, spent bool) types.Hash256 {
	buf := make([]byte, 1+32+8+1)
	buf[0] = 0x00 // leafHashPrefix
	copy(buf[1:], eh[:])
	binary.LittleEndian.PutUint64(buf[33:], leafIndex)
	if spent {
		buf[41] = 1
	}
	return types.HashBytes(buf)
}

func h2s(h types.Hash256) string {
	return hex.EncodeToString(h[:])
}

// Test vector types
type ElementHashVector struct {
	IDHex          string `json:"id_hex"`
	ValueLo        uint64 `json:"value_lo"`
	ValueHi        uint64 `json:"value_hi"`
	AddressHex     string `json:"address_hex"`
	MaturityHeight uint64 `json:"maturity_height"`
	ResultHex      string `json:"result_hex"`
}

type LeafHashVector struct {
	ElementHashHex string `json:"element_hash_hex"`
	LeafIndex      uint64 `json:"leaf_index"`
	Spent          bool   `json:"spent"`
	ResultHex      string `json:"result_hex"`
}

type SumPairVector struct {
	LeftHex  string `json:"left_hex"`
	RightHex string `json:"right_hex"`
	ResultHex string `json:"result_hex"`
}

type AccumulatorStep struct {
	LeafHashHex string   `json:"leaf_hash_hex"`
	NumLeaves   uint64   `json:"num_leaves"`
	TreesHex    []string `json:"trees_hex"` // only non-zero trees
}

type ProofRootVector struct {
	LeafHashHex string   `json:"leaf_hash_hex"`
	LeafIndex   uint64   `json:"leaf_index"`
	ProofHex    []string `json:"proof_hex"`
	ResultHex   string   `json:"result_hex"`
}

type ChainIndexHashVector struct {
	IDHex         string `json:"id_hex"`
	IndexHeight   uint64 `json:"index_height"`
	IndexIDHex    string `json:"index_id_hex"`
	ResultHex     string `json:"result_hex"`
}

type MinerOutputIDVector struct {
	BlockIDHex string `json:"block_id_hex"`
	Index      uint64 `json:"index"`
	ResultHex  string `json:"result_hex"`
}

type FoundationOutputIDVector struct {
	BlockIDHex string `json:"block_id_hex"`
	ResultHex  string `json:"result_hex"`
}

type AllVectors struct {
	UnassignedLeafIndex uint64              `json:"unassigned_leaf_index"`
	ElementHashes       []ElementHashVector `json:"element_hashes"`
	LeafHashes          []LeafHashVector    `json:"leaf_hashes"`
	SumPairs            []SumPairVector     `json:"sum_pairs"`
	Accumulator         []AccumulatorStep   `json:"accumulator"`
	ProofRoots          []ProofRootVector   `json:"proof_roots"`
	ChainIndexHashes    []ChainIndexHashVector    `json:"chain_index_hashes"`
	MinerOutputIDs      []MinerOutputIDVector     `json:"miner_output_ids"`
	FoundationOutputIDs []FoundationOutputIDVector `json:"foundation_output_ids"`
}

func makeID(b byte) types.SiacoinOutputID {
	var id types.SiacoinOutputID
	id[0] = b
	return id
}

func makeAddress(b byte) types.Address {
	var addr types.Address
	addr[0] = b
	return addr
}

func main() {
	var vectors AllVectors
	vectors.UnassignedLeafIndex = types.UnassignedLeafIndex

	// === Element Hash Vectors ===
	testCases := []struct {
		id             types.SiacoinOutputID
		value          types.Currency
		address        types.Address
		maturityHeight uint64
	}{
		// Case 1: zero values
		{types.SiacoinOutputID{}, types.ZeroCurrency, types.VoidAddress, 0},
		// Case 2: simple values
		{makeID(0x01), types.Siacoins(100), types.VoidAddress, 0},
		// Case 3: with maturity height
		{makeID(0x42), types.Siacoins(500), makeAddress(0xAB), 185},
		// Case 4: large currency value
		{makeID(0xFF), types.Siacoins(1000000), makeAddress(0xDE), 144},
		// Case 5: small currency (1 hasting)
		{makeID(0x10), types.NewCurrency64(1), makeAddress(0x01), 0},
	}

	for _, tc := range testCases {
		output := types.SiacoinOutput{
			Value:   tc.value,
			Address: tc.address,
		}
		elemHash := hashAll("leaf/siacoin", tc.id, types.V2SiacoinOutput(output), tc.maturityHeight)

		vectors.ElementHashes = append(vectors.ElementHashes, ElementHashVector{
			IDHex:          h2s(types.Hash256(tc.id)),
			ValueLo:        tc.value.Lo,
			ValueHi:        tc.value.Hi,
			AddressHex:     h2s(types.Hash256(tc.address)),
			MaturityHeight: tc.maturityHeight,
			ResultHex:      h2s(elemHash),
		})
	}

	// === Leaf Hash Vectors ===
	leafCases := []struct {
		elemHash  types.Hash256
		leafIndex uint64
		spent     bool
	}{
		// Use the element hashes we just computed
		{hashAll("leaf/siacoin", types.SiacoinOutputID{}, types.V2SiacoinOutput(types.SiacoinOutput{Value: types.ZeroCurrency, Address: types.VoidAddress}), uint64(0)), 0, false},
		{hashAll("leaf/siacoin", makeID(0x01), types.V2SiacoinOutput(types.SiacoinOutput{Value: types.Siacoins(100), Address: types.VoidAddress}), uint64(0)), 5, true},
		{hashAll("leaf/siacoin", makeID(0x42), types.V2SiacoinOutput(types.SiacoinOutput{Value: types.Siacoins(500), Address: makeAddress(0xAB)}), uint64(185)), 1000, false},
		// Edge case: unassigned leaf index
		{hashAll("leaf/siacoin", makeID(0x01), types.V2SiacoinOutput(types.SiacoinOutput{Value: types.Siacoins(100), Address: types.VoidAddress}), uint64(0)), types.UnassignedLeafIndex, false},
	}

	for _, lc := range leafCases {
		lh := leafHash(lc.elemHash, lc.leafIndex, lc.spent)
		vectors.LeafHashes = append(vectors.LeafHashes, LeafHashVector{
			ElementHashHex: h2s(lc.elemHash),
			LeafIndex:      lc.leafIndex,
			Spent:          lc.spent,
			ResultHex:      h2s(lh),
		})
	}

	// === SumPair Vectors ===
	pairCases := []struct {
		left, right types.Hash256
	}{
		{types.Hash256{}, types.Hash256{}},
		{types.Hash256{0x01}, types.Hash256{0x02}},
	}
	// Also use some real leaf hashes
	lh0 := leafHash(hashAll("leaf/siacoin", types.SiacoinOutputID{}, types.V2SiacoinOutput(types.SiacoinOutput{Value: types.ZeroCurrency, Address: types.VoidAddress}), uint64(0)), 0, false)
	lh1 := leafHash(hashAll("leaf/siacoin", makeID(0x01), types.V2SiacoinOutput(types.SiacoinOutput{Value: types.Siacoins(100), Address: types.VoidAddress}), uint64(0)), 1, false)
	pairCases = append(pairCases, struct{ left, right types.Hash256 }{lh0, lh1})

	for _, pc := range pairCases {
		result := cblake.SumPair(pc.left, pc.right)
		vectors.SumPairs = append(vectors.SumPairs, SumPairVector{
			LeftHex:   h2s(pc.left),
			RightHex:  h2s(pc.right),
			ResultHex: h2s(result),
		})
	}

	// === Accumulator Vectors ===
	// Add 10 elements to an empty accumulator and record state after each
	var acc cblake.Accumulator
	for i := 0; i < 10; i++ {
		id := makeID(byte(i))
		output := types.SiacoinOutput{
			Value:   types.Siacoins(uint32(100 * (i + 1))),
			Address: makeAddress(byte(i + 1)),
		}
		elemHash := hashAll("leaf/siacoin", id, types.V2SiacoinOutput(output), uint64(0))
		lh := leafHash(elemHash, uint64(i), false)

		acc.AddLeaf(lh)

		// Record non-zero trees
		var treesHex []string
		for j := 0; j < 64; j++ {
			if acc.Trees[j] != (types.Hash256{}) {
				treesHex = append(treesHex, fmt.Sprintf("%d:%s", j, h2s(acc.Trees[j])))
			}
		}

		vectors.Accumulator = append(vectors.Accumulator, AccumulatorStep{
			LeafHashHex: h2s(lh),
			NumLeaves:   acc.NumLeaves,
			TreesHex:    treesHex,
		})
	}

	// === ProofRoot Vectors ===
	// Build a small accumulator with 4 elements and verify proof roots
	var acc2 cblake.Accumulator
	var leafHashes [4]types.Hash256
	for i := 0; i < 4; i++ {
		id := makeID(byte(i + 0x80))
		output := types.SiacoinOutput{
			Value:   types.Siacoins(uint32(50 * (i + 1))),
			Address: makeAddress(byte(i + 0x80)),
		}
		elemHash := hashAll("leaf/siacoin", id, types.V2SiacoinOutput(output), uint64(0))
		leafHashes[i] = leafHash(elemHash, uint64(i), false)
		acc2.AddLeaf(leafHashes[i])
	}
	// Now acc2 has 4 leaves: tree at height 2 has the root
	// Proofs for each leaf:
	// leaf 0: proof = [leaf1_hash, node(leaf2, leaf3)]
	// leaf 1: proof = [leaf0_hash, node(leaf2, leaf3)]
	// etc.
	// We can compute proofs manually:
	node01 := cblake.SumPair(leafHashes[0], leafHashes[1])
	node23 := cblake.SumPair(leafHashes[2], leafHashes[3])
	root := cblake.SumPair(node01, node23)

	proofCases := []struct {
		leafHash  types.Hash256
		leafIndex uint64
		proof     []types.Hash256
	}{
		{leafHashes[0], 0, []types.Hash256{leafHashes[1], node23}},
		{leafHashes[1], 1, []types.Hash256{leafHashes[0], node23}},
		{leafHashes[2], 2, []types.Hash256{leafHashes[3], node01}},
		{leafHashes[3], 3, []types.Hash256{leafHashes[2], node01}},
	}

	for _, pc := range proofCases {
		// Verify using our own proofRoot
		computedRoot := pc.leafHash
		for i, h := range pc.proof {
			if pc.leafIndex&(1<<i) == 0 {
				computedRoot = cblake.SumPair(computedRoot, h)
			} else {
				computedRoot = cblake.SumPair(h, computedRoot)
			}
		}

		var proofHex []string
		for _, h := range pc.proof {
			proofHex = append(proofHex, h2s(h))
		}

		vectors.ProofRoots = append(vectors.ProofRoots, ProofRootVector{
			LeafHashHex: h2s(pc.leafHash),
			LeafIndex:   pc.leafIndex,
			ProofHex:    proofHex,
			ResultHex:   h2s(computedRoot),
		})

		// Sanity check
		if computedRoot != root {
			fmt.Fprintf(os.Stderr, "SANITY CHECK FAILED: proof root != expected root for leaf %d\n", pc.leafIndex)
		}
	}

	// === Chain Index Hash Vectors ===
	ciCases := []struct {
		id    types.BlockID
		index types.ChainIndex
	}{
		// Case 1: zero values
		{types.BlockID{}, types.ChainIndex{Height: 0, ID: types.BlockID{}}},
		// Case 2: same ID for element and chain index (typical case)
		{types.BlockID{0x42}, types.ChainIndex{Height: 51, ID: types.BlockID{0x42}}},
		// Case 3: different height
		{types.BlockID{0xAB}, types.ChainIndex{Height: 1000, ID: types.BlockID{0xAB}}},
	}

	for _, cc := range ciCases {
		h := hashAll("leaf/chainindex", types.Hash256(cc.id), cc.index)
		vectors.ChainIndexHashes = append(vectors.ChainIndexHashes, ChainIndexHashVector{
			IDHex:       h2s(types.Hash256(cc.id)),
			IndexHeight: cc.index.Height,
			IndexIDHex:  h2s(types.Hash256(cc.index.ID)),
			ResultHex:   h2s(h),
		})
	}

	// === Miner Output ID Vectors ===
	minerCases := []struct {
		blockID types.BlockID
		index   int
	}{
		{types.BlockID{}, 0},
		{types.BlockID{0x42}, 0},
		{types.BlockID{0x42}, 1},
		{types.BlockID{0xFF}, 3},
	}

	for _, mc := range minerCases {
		id := mc.blockID.MinerOutputID(mc.index)
		vectors.MinerOutputIDs = append(vectors.MinerOutputIDs, MinerOutputIDVector{
			BlockIDHex: h2s(types.Hash256(mc.blockID)),
			Index:      uint64(mc.index),
			ResultHex:  h2s(types.Hash256(id)),
		})
	}

	// === Foundation Output ID Vectors ===
	foundationCases := []types.BlockID{
		{},
		{0x42},
		{0xFF},
	}

	for _, bid := range foundationCases {
		id := bid.FoundationOutputID()
		vectors.FoundationOutputIDs = append(vectors.FoundationOutputIDs, FoundationOutputIDVector{
			BlockIDHex: h2s(types.Hash256(bid)),
			ResultHex:  h2s(types.Hash256(id)),
		})
	}

	// Output as JSON
	data, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}
