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
// It implements a "Lookup-before-Update" strategy:
// 1. Records with IDs are updated via PATCH
// 2. Records without IDs trigger a GetRecords call to find matches by Name and Type
// 3. Matched records are updated via PATCH using the retrieved ID
// 4. Unmatched records are created via PUT with force:false
// This strategy prevents duplicate records even when ProviderData is dropped by the controller.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if err := p.validateCredentials(); err != nil {
		return nil, err
	}

	zone = strings.TrimSuffix(zone, ".")

	// Separate records into two groups: those with IDs (updates) and those without (might be updates or creates)
	var recordsWithIDs []spaceshipRecordUnion
	var recordsWithoutIDs []spaceshipRecordUnion
	var recordsToUpdate []spaceshipRecordUnion
	var recordsToCreate []spaceshipRecordUnion

	for _, r := range records {
		if item := p.fromLibdnsRR(r, zone); item != nil {
			if item.ID != "" {
				// Record has an ID, so it's definitely an existing record that needs to be updated
				recordsWithIDs = append(recordsWithIDs, *item)
			} else {
				// Record has no ID, so we need to look it up by Name and Type
				recordsWithoutIDs = append(recordsWithoutIDs, *item)
			}
		}
	}

	// For records without IDs, perform lookup-before-update strategy
	if len(recordsWithoutIDs) > 0 {
		existingRecords, err := p.GetRecords(ctx, zone)
		if err != nil {
			// If GetRecords fails, treat all records without IDs as creates (best-effort)
			// This is a fallback strategy when we cannot perform the lookup-before-update.
			// Note: This may result in duplicate records if the failure is transient and
			// the records already exist in the zone. In production, error handling/logging
			// could be improved to track and retry these cases.
			recordsToCreate = append(recordsToCreate, recordsWithoutIDs...)
		} else {
			// Build a map of existing records by normalized Name and Type for fast lookup
			// We store ALL records with each Name+Type key (not just the last one) to handle
			// multiple records with the same name and type (e.g., multiple A records for round-robin).
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
				if existingSR := getSpaceshipRecordUnion(existingRecord); existingSR != nil && existingSR.ID != "" {
					existingByNameType[key] = append(existingByNameType[key], *existingSR)
				}
			}

			// Match incoming records without IDs with existing records
			// Note: item.Name is already normalized by fromLibdnsRR to use "@" for apex
			for _, item := range recordsWithoutIDs {
				recordType := strings.ToUpper(item.Type)
				key := makeRecordKey(item.Name, recordType)

				if existingRecordsForKey, found := existingByNameType[key]; found {
					// Found matching records by Name and Type
					// Delete all existing records with this Name+Type before creating the new one
					var recordsToDelete []libdns.Record
					for _, existingSR := range existingRecordsForKey {
						if existingRecord := p.toLibdnsRR(existingSR, zone); existingRecord != nil {
							recordsToDelete = append(recordsToDelete, existingRecord)
						}
					}
					if len(recordsToDelete) > 0 {
						_, _ = p.DeleteRecords(ctx, zone, recordsToDelete)
						// Intentionally ignore deletion errors to continue with the set operation.
						// This is best-effort; in rare cases where deletion fails, duplicate records may
						// persist. Future improvements could add logging infrastructure to track these cases.
					}
					// Treat as a new record to create after deletion
					recordsToCreate = append(recordsToCreate, item)
				} else {
					// No match found, treat as a new record to create
					recordsToCreate = append(recordsToCreate, item)
				}
			}
		}
	}

	// Add records that already had IDs to the update list
	recordsToUpdate = append(recordsToUpdate, recordsWithIDs...)

	// Process updates first - use PATCH endpoint for individual records
	for _, item := range recordsToUpdate {
		endpoint := fmt.Sprintf("/v1/dns/records/%s/%s", zone, item.ID)
		_, status, err := p.doRequest(ctx, "PATCH", endpoint, item)
		if err != nil {
			return nil, fmt.Errorf("failed to update record %s (ID: %s): %w", item.Name, item.ID, err)
		}
		if status != 200 && status != 204 {
			return nil, fmt.Errorf("API returned unexpected status %d when updating record %s (ID: %s)", status, item.Name, item.ID)
		}
	}

	// Process creates - use PUT endpoint for new records with force:false to avoid
	// accidentally overwriting other records in the zone.
	if len(recordsToCreate) > 0 {
		payload := map[string]interface{}{
			"force": false,
			"items": recordsToCreate,
		}
		endpoint := fmt.Sprintf("/v1/dns/records/%s", zone)
		_, status, err := p.doRequest(ctx, "PUT", endpoint, payload)
		if err != nil {
			return nil, fmt.Errorf("failed to create records: %w", err)
		}
		if status != 204 {
			// API should return 204. If not, still continue as best-effort.
		}
	}

	// Return all records (both created and updated)
	var updated []libdns.Record
	for _, item := range recordsToCreate {
		if record := p.toLibdnsRR(item, zone); record != nil {
			updated = append(updated, record)
		}
	}
	for _, item := range recordsToUpdate {
		if record := p.toLibdnsRR(item, zone); record != nil {
			updated = append(updated, record)
		}
	}
	return updated, nil
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
