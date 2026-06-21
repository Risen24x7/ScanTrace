package collector

import (
    "time"
    "github.com/Risen24x7/scantrace/internal/db"
    "github.com/google/uuid"
)

// Collector reads raw input and writes normalized Events to the DB.
type Collector struct {
    store    *db.DB
    sensorID string
}

func New(store *db.DB, sensorID string) *Collector {
    return &Collector{store: store, sensorID: sensorID}
}

// IngestLine parses one raw log line and writes an Event.
// You'll replace the stub parse logic with real parsing next.
func (c *Collector) IngestLine(raw string) error {
    now := time.Now().UTC()
    e := &db.Event{
        EventID:   uuid.New().String(),
        Timestamp: now,
        FirstSeen: now,
        LastSeen:  now,
        SensorID:  c.sensorID,
        RawRef:    raw,
        Confidence: 0.7,
        Tags:      db.StringSlice{},
    }
    return c.store.InsertEvent(e)
}