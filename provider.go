// Package libdnsspaceship implements a DNS record management client compatible
// with the libdns interfaces for Spaceship. This package allows you to manage
// DNS records using the Spaceship DNS API.
package libdnsspaceship

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/libdns/libdns"
)

// recordKeyDelimiter is used to create composite keys for record identification (name|type)
const recordKeyDelimiter = "|"

// makeRecordKey creates a composite key from record name and type for comparison purposes
func makeRecordKey(name, recordType string) string {
	return name + recordKeyDelimiter + recordType
}

// convertToLibdnsRecord moved to conversions.go

// convertFromLibdnsRecord moved to conversions.go

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	if err := p.validateCredentials(); err != nil {
		return nil, err
	}

	// Clean zone name
	zone = strings.TrimSuffix(zone, ".")

	var records []libdns.Record
	// API requires pagination parameters 'take' and 'skip'. We'll page through all records.
	take := 100
	if p.PageSize > 0 {
		take = p.PageSize
	}
	skip := 0
	for {
		endpoint := fmt.Sprintf("/v1/dns/records/%s?take=%d&skip=%d", zone, take, skip)
		body, _, err := p.doRequest(ctx, "GET", endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to get records: %w", err)
		}
		var lr listResponse
		if err := json.Unmarshal(body, &lr); err != nil {
			return nil, fmt.Errorf("failed to unmarshal records response: %w", err)
		}
		for _, sr := range lr.Items {
			if record := p.toLibdnsRR(sr, zone); record != nil {
				records = append(records, record)
			}
		}
		if skip+len(lr.Items) >= lr.Total {
			break
		}
		skip += take
	}

	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
// If a record with the same name and type already exists in the zone, the existing record
// will be deleted before appending the new records. This prevents unintended duplicates from
// existing zone records, but allows the caller to append multiple records with the same
// name/type in a single call (they will all be appended after any existing conflicts are deleted).
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if err := p.validateCredentials(); err != nil {
		return nil, err
	}

	// Clean zone name
	zone = strings.TrimSuffix(zone, ".")

	var items []spaceshipRecordUnion
	for _, r := range records {
		if item := p.fromLibdnsRR(r, zone); item != nil {
			items = append(items, *item)
		}
	}

	// To avoid duplicates, check if records with the same name and type already exist
	// and delete them before appending the new ones.
	existingRecords, err := p.GetRecords(ctx, zone)
	if err == nil {
		// Create a map of record identifiers (name+type) for the records we're appending
		toAppendKeys := make(map[string]bool)
		for _, item := range items {
			key := makeRecordKey(item.Name, item.Type)
			toAppendKeys[key] = true
		}

		// Find existing records that conflict with the ones we're appending
		var recordsToDelete []libdns.Record
		for _, existingRecord := range existingRecords {
			rr := existingRecord.RR()
			// Normalize the name to match what will be in items
			normalizedName := libdns.RelativeName(rr.Name, zone)
			if normalizedName == "" {
				normalizedName = "@"
			}
			key := makeRecordKey(normalizedName, rr.Type)
			if toAppendKeys[key] {
				recordsToDelete = append(recordsToDelete, existingRecord)
			}
		}

		// Delete conflicting records if any
		if len(recordsToDelete) > 0 {
			_, _ = p.DeleteRecords(ctx, zone, recordsToDelete)
			// Intentionally ignore deletion errors to continue with the append operation.
			// This is best-effort; in rare cases where deletion fails, duplicate records may
			// persist. Future improvements could add logging infrastructure to track these cases.
		}
	}
	// If GetRecords fails, we continue anyway as a best-effort attempt to append.
	// The duplicate prevention check is skipped but the append operation proceeds.

	payload := map[string]interface{}{
		"force": false,
		"items": items,
	}

	endpoint := fmt.Sprintf("/v1/dns/records/%s", zone)
	_, status, err := p.doRequest(ctx, "PUT", endpoint, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to append records: %w", err)
	}
	if status != 204 {
		// In case API returns body with created data we could parse it; but it should be 204
		// Fall back to returning the input records
	}

	// Return records converted from the request payload as the representation of what was created
	var added []libdns.Record
	for _, it := range items {
		if record := p.toLibdnsRR(it, zone); record != nil {
			added = append(added, record)
		}
	}
	return added, nil
}

// SetRecords sets the records in the zone by saving the provided records.
// It implements a simple and consistent strategy:
// 1. Get all current records in the zone
// 2. For each requested record:
//    - If it already exists with the same data, leave it alone
//    - If a record with the same Name+Type exists but different data, mark old for deletion
//    - If the record is new, mark it for addition
// 3. Add the new/replacement records (PUT with force:false)
// 4. Remove the old records that were replaced (DELETE)
// This ensures we only touch the requested hosts (by Name+Type) and leave everything else untouched.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if err := p.validateCredentials(); err != nil {
		return nil, err
	}

	zone = strings.TrimSuffix(zone, ".")

	// Convert requested records to spaceshipRecordUnion format
	var requestedItems []spaceshipRecordUnion
	for _, r := range records {
		if item := p.fromLibdnsRR(r, zone); item != nil {
			// Clear the ID since we want to match by Name+Type, not by ID
			item.ID = ""
			requestedItems = append(requestedItems, *item)
		}
	}

	// Get all current records in the zone
	existingRecords, err := p.GetRecords(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("failed to get current records: %w", err)
	}

	// Build a map of existing records by Name+Type for matching
	existingByNameType := make(map[string][]spaceshipRecordUnion)
	for _, existingRecord := range existingRecords {
		rr := existingRecord.RR()
		normalizedName := libdns.RelativeName(rr.Name, zone)
		if normalizedName == "" {
			normalizedName = "@"
		}
		recordType := strings.ToUpper(rr.Type)
		key := makeRecordKey(normalizedName, recordType)

		// Extract the spaceshipRecordUnion from ProviderData
		if existingSR := getSpaceshipRecordUnion(existingRecord); existingSR != nil {
			existingByNameType[key] = append(existingByNameType[key], *existingSR)
		}
	}

	// Determine which records to add and which to remove
	var recordsToAdd []spaceshipRecordUnion
	var recordsToRemove []libdns.Record

	for _, requestedItem := range requestedItems {
		recordType := strings.ToUpper(requestedItem.Type)
		key := makeRecordKey(requestedItem.Name, recordType)

		existingRecordsForKey, found := existingByNameType[key]
		if found {
			// Found existing records with the same Name+Type
			// Check if any of them match exactly (same data)
			var exactMatch bool
			for _, existingSR := range existingRecordsForKey {
				if recordsAreEqual(requestedItem, existingSR) {
					// Exact match found, no need to change this record
					exactMatch = true
					break
				}
			}

			if !exactMatch {
				// No exact match, so we need to replace all existing records with this Name+Type
				for _, existingSR := range existingRecordsForKey {
					if existingRecord := p.toLibdnsRR(existingSR, zone); existingRecord != nil {
						recordsToRemove = append(recordsToRemove, existingRecord)
					}
				}
				// Add the requested record
				recordsToAdd = append(recordsToAdd, requestedItem)
			}
			// If exact match is found, we don't add or remove anything for this record
		} else {
			// No existing record with this Name+Type, so add it
			recordsToAdd = append(recordsToAdd, requestedItem)
		}
	}

	// Add new/replacement records using PUT with force:false
	if len(recordsToAdd) > 0 {
		payload := map[string]interface{}{
			"force": false,
			"items": recordsToAdd,
		}
		endpoint := fmt.Sprintf("/v1/dns/records/%s", zone)
		_, status, err := p.doRequest(ctx, "PUT", endpoint, payload)
		if err != nil {
			return nil, fmt.Errorf("failed to add records: %w", err)
		}
		if status != 204 {
			// API should return 204. If not, still continue as best-effort.
		}
	}

	// Remove old records that were replaced using DELETE
	if len(recordsToRemove) > 0 {
		_, err := p.DeleteRecords(ctx, zone, recordsToRemove)
		if err != nil {
			return nil, fmt.Errorf("failed to remove old records: %w", err)
		}
	}

	// Return the records that were set
	var result []libdns.Record
	for _, item := range requestedItems {
		if record := p.toLibdnsRR(item, zone); record != nil {
			result = append(result, record)
		}
	}
	return result, nil
}

// recordsAreEqual compares two spaceshipRecordUnion records to determine if they represent
// the same DNS record (same Name, Type, and data-specific fields).
func recordsAreEqual(r1, r2 spaceshipRecordUnion) bool {
	// Check basic fields
	if r1.Name != r2.Name || strings.ToUpper(r1.Type) != strings.ToUpper(r2.Type) || r1.TTL != r2.TTL {
		return false
	}

	// Check type-specific fields based on record type
	recordType := strings.ToUpper(r1.Type)
	switch recordType {
	case "A", "AAAA":
		return r1.Address == r2.Address
	case "TXT":
		return r1.Value == r2.Value
	case "CNAME":
		return r1.Cname == r2.Cname
	case "MX":
		return r1.Exchange == r2.Exchange && r1.Preference == r2.Preference
	case "SRV":
		return r1.Service == r2.Service && r1.Protocol == r2.Protocol &&
			r1.Priority == r2.Priority && r1.Weight == r2.Weight &&
			r1.PortInt == r2.PortInt && r1.Target == r2.Target
	case "NS":
		return r1.Nameserver == r2.Nameserver
	case "CAA":
		flag1 := 0
		if r1.Flag != nil {
			flag1 = *r1.Flag
		}
		flag2 := 0
		if r2.Flag != nil {
			flag2 = *r2.Flag
		}
		return flag1 == flag2 && r1.Tag == r2.Tag && r1.Value == r2.Value
	case "HTTPS":
		return r1.SvcPriority == r2.SvcPriority &&
			(r1.SvcTarget == r2.SvcTarget || r1.TargetName == r2.TargetName) &&
			r1.SvcParams == r2.SvcParams
	default:
		// For unknown types, just compare the union fields
		return r1 == r2
	}
}

// DeleteRecords deletes the specified records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if err := p.validateCredentials(); err != nil {
		return nil, err
	}

	zone = strings.TrimSuffix(zone, ".")
	var items []spaceshipRecordUnion
	for _, rec := range records {
		item := p.fromLibdnsRR(rec, zone)
		if item == nil {
			rr := rec.RR()
			return nil, fmt.Errorf("unsupported record type for deletion: %s", rr.Type)
		}
		items = append(items, *item)
	}
	endpoint := fmt.Sprintf("/v1/dns/records/%s", zone)
	_, status, err := p.doRequest(ctx, "DELETE", endpoint, items)
	if err != nil {
		return nil, fmt.Errorf("failed to delete records: %w", err)
	}
	if status != 204 {
		// API should return 204. If not, proceed anyway.
	}
	return records, nil
}


// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
