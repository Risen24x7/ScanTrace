package db

import (
	"database/sql"
	"fmt"
	"time"
)

// ===========================================================================
// KNOWN DEVICE CRUD
// ===========================================================================

// UpsertKnownDevice inserts or updates a device registry entry keyed on IP
// (if non-empty) or MAC. Caller must set DeviceID (UUID v4) on insert.
func (db *DB) UpsertKnownDevice(d *KnownDevice) error {
	now := time.Now().UTC()
	if d.CreatedAt.IsZero() {
		d.CreatedAt = now
	}
	d.UpdatedAt = now

	_, err := db.conn.Exec(`
		INSERT INTO known_devices
		  (device_id, ip, mac, hostname, label, trust_label,
		   network_zone, org_unit, owner, auto_suppress,
		   first_seen, last_seen, notes, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(device_id) DO UPDATE SET
		  ip=excluded.ip,
		  mac=excluded.mac,
		  hostname=excluded.hostname,
		  label=excluded.label,
		  trust_label=excluded.trust_label,
		  network_zone=excluded.network_zone,
		  org_unit=excluded.org_unit,
		  owner=excluded.owner,
		  auto_suppress=excluded.auto_suppress,
		  last_seen=excluded.last_seen,
		  notes=excluded.notes,
		  updated_at=excluded.updated_at`,
		d.DeviceID, d.IP, d.MAC, d.Hostname, d.Label, d.TrustLabel,
		d.NetworkZone, d.OrgUnit, d.Owner, boolToInt(d.AutoSuppress),
		formatTime(d.FirstSeen), formatTime(d.LastSeen),
		d.Notes, formatTime(d.CreatedAt), formatTime(d.UpdatedAt),
	)
	return err
}

// GetKnownDeviceByIP returns the registry entry for an IP, or nil if not found.
func (db *DB) GetKnownDeviceByIP(ip string) (*KnownDevice, error) {
	row := db.conn.QueryRow(`
		SELECT device_id, ip, mac, hostname, label, trust_label,
		       network_zone, org_unit, owner, auto_suppress,
		       first_seen, last_seen, notes, created_at, updated_at
		FROM known_devices WHERE ip = ?`, ip)
	return scanKnownDevice(row)
}

// GetKnownDeviceByMAC returns the registry entry for a MAC address.
func (db *DB) GetKnownDeviceByMAC(mac string) (*KnownDevice, error) {
	row := db.conn.QueryRow(`
		SELECT device_id, ip, mac, hostname, label, trust_label,
		       network_zone, org_unit, owner, auto_suppress,
		       first_seen, last_seen, notes, created_at, updated_at
		FROM known_devices WHERE mac = ?`, mac)
	return scanKnownDevice(row)
}

// ListKnownDevices returns all registered devices, optionally filtered by
// trust_label. Pass "" to return all labels.
func (db *DB) ListKnownDevices(trustLabel string, limit int) ([]*KnownDevice, error) {
	if limit <= 0 {
		limit = 200
	}
	var (
		rows *sql.Rows
		err  error
	)
	if trustLabel != "" {
		rows, err = db.conn.Query(`
			SELECT device_id, ip, mac, hostname, label, trust_label,
			       network_zone, org_unit, owner, auto_suppress,
			       first_seen, last_seen, notes, created_at, updated_at
			FROM known_devices
			WHERE trust_label = ?
			ORDER BY updated_at DESC LIMIT ?`, trustLabel, limit)
	} else {
		rows, err = db.conn.Query(`
			SELECT device_id, ip, mac, hostname, label, trust_label,
			       network_zone, org_unit, owner, auto_suppress,
			       first_seen, last_seen, notes, created_at, updated_at
			FROM known_devices
			ORDER BY updated_at DESC LIMIT ?`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*KnownDevice
	for rows.Next() {
		d, err := scanKnownDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// TouchKnownDevice bumps last_seen to now for a device matched by IP or MAC.
// Safe to call on every DHCP/WiFi event — used by the collector to keep
// last_seen current without a full upsert.
func (db *DB) TouchKnownDevice(ip, mac string) error {
	now := formatTime(time.Now().UTC())
	var err error
	if ip != "" {
		_, err = db.conn.Exec(
			`UPDATE known_devices SET last_seen=?, updated_at=? WHERE ip=?`,
			now, now, ip)
	} else if mac != "" {
		_, err = db.conn.Exec(
			`UPDATE known_devices SET last_seen=?, updated_at=? WHERE mac=?`,
			now, now, mac)
	}
	return err
}

// DeleteKnownDevice removes a registry entry by device_id.
func (db *DB) DeleteKnownDevice(deviceID string) error {
	_, err := db.conn.Exec(`DELETE FROM known_devices WHERE device_id = ?`, deviceID)
	return err
}

// IsSuppressed returns true if a device matching ip or mac has auto_suppress=1.
// Used by the correlator to skip case creation for trusted devices.
func (db *DB) IsSuppressed(ip, mac string) (bool, error) {
	var count int
	var err error
	switch {
	case ip != "" && mac != "":
		err = db.conn.QueryRow(
			`SELECT COUNT(*) FROM known_devices WHERE auto_suppress=1 AND (ip=? OR mac=?)`,
			ip, mac).Scan(&count)
	case ip != "":
		err = db.conn.QueryRow(
			`SELECT COUNT(*) FROM known_devices WHERE auto_suppress=1 AND ip=?`,
			ip).Scan(&count)
	case mac != "":
		err = db.conn.QueryRow(
			`SELECT COUNT(*) FROM known_devices WHERE auto_suppress=1 AND mac=?`,
			mac).Scan(&count)
	default:
		return false, fmt.Errorf("IsSuppressed: ip and mac both empty")
	}
	return count > 0, err
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

type knownDeviceScanner interface {
	Scan(dest ...any) error
}

func scanKnownDevice(r knownDeviceScanner) (*KnownDevice, error) {
	var d KnownDevice
	var autoSuppress int
	var firstSeen, lastSeen, createdAt, updatedAt string
	err := r.Scan(
		&d.DeviceID, &d.IP, &d.MAC, &d.Hostname, &d.Label, &d.TrustLabel,
		&d.NetworkZone, &d.OrgUnit, &d.Owner, &autoSuppress,
		&firstSeen, &lastSeen, &d.Notes, &createdAt, &updatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	d.AutoSuppress = autoSuppress == 1
	d.FirstSeen = mustParseTime(firstSeen)
	d.LastSeen = mustParseTime(lastSeen)
	d.CreatedAt = mustParseTime(createdAt)
	d.UpdatedAt = mustParseTime(updatedAt)
	return &d, nil
}
