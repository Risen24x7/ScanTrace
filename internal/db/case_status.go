package db

import "time"

// SetCaseStatus updates only the status field of a case and bumps updated_at.
// Valid values are "open", "closed", "resolved".
func (db *DB) SetCaseStatus(caseID, status string) error {
	_, err := db.conn.Exec(
		`UPDATE cases SET status=?, updated_at=? WHERE case_id=?`,
		status, formatTime(time.Now().UTC()), caseID,
	)
	return err
}
