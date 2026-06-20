/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
)

type domainRoutingOwnerSnapshot struct {
	bitmap   bpfDomainRouting
	decision domainRoutingDecision
	ips      map[[4]uint32]struct{}
}

type domainRoutingDecision struct {
	Valid    bool
	Outbound uint8
	Mark     uint32
	Must     bool
	Drop     bool
}

type domainRoutingOwnerRoute struct {
	bitmap   bpfDomainRouting
	decision domainRoutingDecision
}

type domainRoutingIPState struct {
	owners map[string]domainRoutingOwnerRoute
	merged bpfDomainRouting
}

type domainRoutingTracker struct {
	mu                       sync.Mutex
	owners                   map[string]domainRoutingOwnerSnapshot
	ips                      map[[4]uint32]*domainRoutingIPState
	decisionFromMergedBitmap func([]uint32) domainRoutingDecision
}

func newDomainRoutingTracker() *domainRoutingTracker {
	return &domainRoutingTracker{
		owners: make(map[string]domainRoutingOwnerSnapshot),
		ips:    make(map[[4]uint32]*domainRoutingIPState),
	}
}

func (t *domainRoutingTracker) setDecisionFromMergedBitmap(fn func([]uint32) domainRoutingDecision) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.decisionFromMergedBitmap = fn
	t.mu.Unlock()
}

func cloneDomainRoutingIPSet(src map[[4]uint32]struct{}) map[[4]uint32]struct{} {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[[4]uint32]struct{}, len(src))
	for key := range src {
		dst[key] = struct{}{}
	}
	return dst
}

func isZeroDomainRoutingBitmap(bitmap bpfDomainRouting) bool {
	for _, word := range bitmap.Bitmap {
		if word != 0 {
			return false
		}
	}
	return true
}

func orDomainRoutingBitmap(dst *bpfDomainRouting, src bpfDomainRouting) {
	for i := range dst.Bitmap {
		dst.Bitmap[i] |= src.Bitmap[i]
	}
}

func (t *domainRoutingTracker) mergeDomainRoutingOwnerBitmaps(owners map[string]domainRoutingOwnerRoute) bpfDomainRouting {
	var merged bpfDomainRouting
	for _, owner := range owners {
		orDomainRoutingBitmap(&merged, owner.bitmap)
	}
	if t.domainRoutingOwnersAmbiguous(owners, merged.Bitmap[:]) {
		merged.Ambiguous = 1
	}
	return merged
}

func equalDomainRoutingBitmap(a, b bpfDomainRouting) bool {
	return a.Bitmap == b.Bitmap
}

func equalDomainRoutingDecision(a, b domainRoutingDecision) bool {
	return a.Valid == b.Valid &&
		a.Outbound == b.Outbound &&
		a.Mark == b.Mark &&
		a.Must == b.Must &&
		a.Drop == b.Drop
}

func (t *domainRoutingTracker) domainRoutingOwnersAmbiguous(owners map[string]domainRoutingOwnerRoute, mergedBitmap []uint32) bool {
	var first bpfDomainRouting
	var firstDecision domainRoutingDecision
	haveFirst := false
	allDecisionsValidAndEqual := true
	hasDifferentBitmap := false
	for _, owner := range owners {
		if !haveFirst {
			first = owner.bitmap
			firstDecision = owner.decision
			allDecisionsValidAndEqual = firstDecision.Valid
			haveFirst = true
			continue
		}
		if !equalDomainRoutingBitmap(first, owner.bitmap) {
			hasDifferentBitmap = true
			if !owner.decision.Valid ||
				!equalDomainRoutingDecision(firstDecision, owner.decision) {
				allDecisionsValidAndEqual = false
			}
		}
	}
	if !haveFirst || !hasDifferentBitmap {
		return false
	}
	if !allDecisionsValidAndEqual || t.decisionFromMergedBitmap == nil {
		return true
	}

	// OR-ing domain bitmaps can synthesize a rule match that none of the
	// individual domains produced, for example domain(A) && domain(B). Keep the
	// kernel fast path only when the merged bitmap still resolves to the exact
	// same routing decision as every owner.
	mergedDecision := t.decisionFromMergedBitmap(mergedBitmap)
	return !mergedDecision.Valid || !equalDomainRoutingDecision(firstDecision, mergedDecision)
}

func buildDomainRoutingOwnerSnapshot(cache *DnsCache) (domainRoutingOwnerSnapshot, error) {
	if cache == nil {
		return domainRoutingOwnerSnapshot{}, nil
	}
	if len(cache.DomainBitmap) != len(bpfDomainRouting{}.Bitmap) {
		return domainRoutingOwnerSnapshot{}, fmt.Errorf("domain bitmap length not sync with kern program")
	}
	var snapshot domainRoutingOwnerSnapshot
	copy(snapshot.bitmap.Bitmap[:], cache.DomainBitmap)
	snapshot.decision = cache.DomainRoutingDecision
	ips := extractIPsFromDnsCache(cache)
	if len(ips) == 0 {
		return snapshot, nil
	}
	snapshot.ips = make(map[[4]uint32]struct{}, len(ips))
	for _, ip := range ips {
		ip6 := ip.As16()
		snapshot.ips[common.Ipv6ByteSliceToUint32Array(ip6[:])] = struct{}{}
	}
	return snapshot, nil
}

func (t *domainRoutingTracker) desiredBitmapForKeyLocked(
	key [4]uint32,
	ownerKey string,
	snapshot domainRoutingOwnerSnapshot,
) (bitmap bpfDomainRouting, present bool) {
	owners := make(map[string]domainRoutingOwnerRoute)
	if state := t.ips[key]; state != nil {
		for existingOwnerKey, existingBitmap := range state.owners {
			if existingOwnerKey == ownerKey {
				continue
			}
			owners[existingOwnerKey] = existingBitmap
		}
	}
	if len(snapshot.ips) > 0 {
		if _, ok := snapshot.ips[key]; ok {
			owners[ownerKey] = domainRoutingOwnerRoute{
				bitmap:   snapshot.bitmap,
				decision: snapshot.decision,
			}
		}
	}
	if len(owners) == 0 {
		return bitmap, false
	}
	bitmap = t.mergeDomainRoutingOwnerBitmaps(owners)
	return bitmap, !isZeroDomainRoutingBitmap(bitmap)
}

func (t *domainRoutingTracker) applyOwnerSnapshotLocked(ownerKey string, snapshot domainRoutingOwnerSnapshot) {
	if ownerKey == "" {
		return
	}
	if old, ok := t.owners[ownerKey]; ok {
		for key := range old.ips {
			state := t.ips[key]
			if state == nil {
				continue
			}
			delete(state.owners, ownerKey)
			if len(state.owners) == 0 {
				delete(t.ips, key)
				continue
			}
			state.merged = t.mergeDomainRoutingOwnerBitmaps(state.owners)
		}
		delete(t.owners, ownerKey)
	}
	if len(snapshot.ips) == 0 {
		return
	}
	cloned := domainRoutingOwnerSnapshot{
		bitmap:   snapshot.bitmap,
		decision: snapshot.decision,
		ips:      cloneDomainRoutingIPSet(snapshot.ips),
	}
	t.owners[ownerKey] = cloned
	for key := range cloned.ips {
		state := t.ips[key]
		if state == nil {
			state = &domainRoutingIPState{
				owners: make(map[string]domainRoutingOwnerRoute),
			}
			t.ips[key] = state
		}
		state.owners[ownerKey] = domainRoutingOwnerRoute{
			bitmap:   cloned.bitmap,
			decision: cloned.decision,
		}
		state.merged = t.mergeDomainRoutingOwnerBitmaps(state.owners)
	}
}

func (t *domainRoutingTracker) syncOwner(
	m *ebpf.Map,
	ownerKey string,
	snapshot domainRoutingOwnerSnapshot,
) error {
	if ownerKey == "" {
		return fmt.Errorf("empty domain routing owner key")
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	oldSnapshot := t.owners[ownerKey]
	affected := make(map[[4]uint32]struct{}, len(oldSnapshot.ips)+len(snapshot.ips))
	for key := range oldSnapshot.ips {
		affected[key] = struct{}{}
	}
	for key := range snapshot.ips {
		affected[key] = struct{}{}
	}

	keysToUpdate := make([][4]uint32, 0, len(affected))
	valuesToUpdate := make([]bpfDomainRouting, 0, len(affected))
	keysToDelete := make([][4]uint32, 0, len(affected))

	for key := range affected {
		desiredBitmap, present := t.desiredBitmapForKeyLocked(key, ownerKey, snapshot)
		current := t.ips[key]
		switch {
		case !present:
			if current != nil && !isZeroDomainRoutingBitmap(current.merged) {
				keysToDelete = append(keysToDelete, key)
			}
		case current == nil || current.merged != desiredBitmap:
			keysToUpdate = append(keysToUpdate, key)
			valuesToUpdate = append(valuesToUpdate, desiredBitmap)
		}
	}

	if m != nil {
		if len(keysToUpdate) > 0 {
			if _, err := BpfMapBatchUpdate(m, keysToUpdate, valuesToUpdate, &ebpf.BatchOptions{
				ElemFlags: uint64(ebpf.UpdateAny),
			}); err != nil {
				return fmt.Errorf("update domain_routing_map: %w", err)
			}
		}
		if len(keysToDelete) > 0 {
			if _, err := BpfMapBatchDelete(m, keysToDelete); err != nil {
				return fmt.Errorf("delete domain_routing_map: %w", err)
			}
		}
	}

	t.applyOwnerSnapshotLocked(ownerKey, snapshot)
	return nil
}
