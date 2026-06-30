// Package enricher adds infrastructure context to Event source IPs via ipinfo.io.
// Results cached in entities table for DefaultTTL (24h) to avoid repeat lookups.
package enricher

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Risen24x7/scantrace/internal/db"
	"github.com/google/uuid"
)

const (
	DefaultTTL    = 24 * time.Hour
	ipinfoBaseURL = "https://ipinfo.io"
)

type Enricher struct {
	store  *db.DB
	client *http.Client
	token  string
	ttl    time.Duration
}

type Option func(*Enricher)

func WithToken(t string) Option { return func(e *Enricher) { e.token = t } }
func WithTTL(d time.Duration) Option  { return func(e *Enricher) { e.ttl = d } }

func New(store *db.DB, opts ...Option) *Enricher {
	e := &Enricher{
		store:  store,
		client: &http.Client{Timeout: 8 * time.Second},
		ttl:    DefaultTTL,
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

func (e *Enricher) EnrichIP(ip string) (*db.Entity, error) {
	if isPrivate(ip) {
		return stubEntity(ip, "private"), nil
	}
	existing, err := e.store.GetEntityByIP(ip)
	if err == nil && existing != nil {
		if time.Since(existing.LastEnriched) < e.ttl {
			return existing, nil
		}
	}
	info, err := e.fetchIPInfo(ip)
	if err != nil {
		log.Printf("[enricher] ipinfo lookup failed for %s: %v — using stub", ip, err)
		stub := stubEntity(ip, "lookup-failed")
		_ = e.store.UpsertEntity(stub)
		return stub, nil
	}
	entity := &db.Entity{
		EntityID:         entityID(existing),
		EntityType:       "ip",
		IP:               ip,
		ASN:              info.ASN(),
		ASName:           info.OrgName(),
		Provider:         info.OrgName(),
		RDNS:             info.Hostname,
		AbuseContact:     info.AbuseContact(),
		GeoCountry:       info.Country,
		ReputationLabels: db.StringSlice{},
		LastEnriched:     time.Now().UTC(),
	}
	if err := e.store.UpsertEntity(entity); err != nil {
		return entity, fmt.Errorf("enricher: upsert: %w", err)
	}
	return entity, nil
}

// EnrichAndLink enriches ip (fetching from ipinfo.io or returning a cached
// entity if within TTL), then links the resulting entity to caseID.
// It is safe to call even when the entity already exists — the link is
// idempotent via LinkEntityToCase.
func (e *Enricher) EnrichAndLink(caseID, ip string) (*db.Entity, error) {
	ent, err := e.EnrichIP(ip)
	if err != nil {
		return nil, err
	}
	if linkErr := e.store.LinkEntityToCase(caseID, ent.EntityID); linkErr != nil {
		log.Printf("[enricher] EnrichAndLink: link failed case=%s ip=%s: %v", caseID[:8], ip, linkErr)
	}
	return ent, nil
}

func (e *Enricher) EnrichEvents(events []*db.Event) map[string]*db.Entity {
	seen := make(map[string]*db.Entity, len(events))
	for _, ev := range events {
		if _, ok := seen[ev.SrcIP]; ok {
			continue
		}
		ent, err := e.EnrichIP(ev.SrcIP)
		if err != nil {
			log.Printf("[enricher] %s: %v", ev.SrcIP, err)
		}
		seen[ev.SrcIP] = ent
	}
	return seen
}

type ipInfoResponse struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Country  string `json:"country"`
	Org      string `json:"org"`
	Abuse    *struct {
		Email string `json:"email"`
	} `json:"abuse,omitempty"`
}

func (r *ipInfoResponse) ASN() string {
	parts := strings.SplitN(r.Org, " ", 2)
	if len(parts) > 0 {
		return parts[0]
	}
	return r.Org
}

func (r *ipInfoResponse) OrgName() string {
	parts := strings.SplitN(r.Org, " ", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return r.Org
}

func (r *ipInfoResponse) AbuseContact() string {
	if r.Abuse != nil {
		return r.Abuse.Email
	}
	return ""
}

func (e *Enricher) fetchIPInfo(ip string) (*ipInfoResponse, error) {
	url := fmt.Sprintf("%s/%s/json", ipinfoBaseURL, ip)
	if e.token != "" {
		url += "?token=" + e.token
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("ipinfo returned %d", resp.StatusCode)
	}
	var info ipInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("json decode: %w", err)
	}
	return &info, nil
}

func isPrivate(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"} {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func stubEntity(ip, reason string) *db.Entity {
	return &db.Entity{
		EntityID:         uuid.New().String(),
		EntityType:       "ip",
		IP:               ip,
		ReputationLabels: db.StringSlice{reason},
		LastEnriched:     time.Now().UTC(),
	}
}

func entityID(existing *db.Entity) string {
	if existing != nil && existing.EntityID != "" {
		return existing.EntityID
	}
	return uuid.New().String()
}
