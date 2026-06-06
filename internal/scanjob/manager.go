package scanjob

import (
	"context"
	"strconv"
	"sync"
	"time"
)

// Event is broadcast whenever a job changes state. Job is always a fresh,
// safe-to-read snapshot (never the live record).
type Event struct {
	Type string `json:"type"`
	Job  *Job   `json:"job"`
}

// Scanner runs one plugin-version scan. *Runner is the production implementation;
// the interface exists so the manager can be tested without network/subprocess.
type Scanner interface {
	Run(ctx context.Context, slug, version string, setStatus func(Status)) (*Result, error)
}

// Config configures a Manager.
type Config struct {
	Concurrency int
	Runner      Scanner
	MaxJobs     int // cap on retained job history (0 = 5000)
	MaxCache    int // cap on cached results (0 = 4000)
}

// Manager owns the job queue, worker pool, result cache, and event bus.
//
// Concurrency model: every read or write of a Job's fields happens while holding
// m.mu. The runner never touches the shared Job — it returns a Result that
// runJob applies under m.mu. Readers (Get/List) and the event bus hand out
// deep-ish clones, so HTTP handlers never marshal a record that a worker is
// mutating.
type Manager struct {
	runner   Scanner
	maxJobs  int
	maxCache int

	mu         sync.RWMutex
	jobs       map[string]*Job
	order      []string
	cache      map[string]*Job // cacheKey -> completed job (immutable once stored)
	cacheOrder []string
	cancels    map[string]context.CancelFunc

	qmu     sync.Mutex
	qcond   *sync.Cond
	pending []*Job
	closed  bool

	subMu  sync.Mutex
	subs   map[int]chan Event
	subSeq int

	seq   uint64
	seqMu sync.Mutex
	nowFn func() time.Time
}

// New builds a Manager and starts its worker pool.
func New(cfg Config) *Manager {
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 4
	}
	if cfg.MaxJobs < 1 {
		cfg.MaxJobs = 5000
	}
	if cfg.MaxCache < 1 {
		cfg.MaxCache = 4000
	}
	m := &Manager{
		runner:   cfg.Runner,
		maxJobs:  cfg.MaxJobs,
		maxCache: cfg.MaxCache,
		jobs:     make(map[string]*Job),
		cache:    make(map[string]*Job),
		cancels:  make(map[string]context.CancelFunc),
		subs:     make(map[int]chan Event),
		nowFn:    time.Now,
	}
	m.qcond = sync.NewCond(&m.qmu)
	for i := 0; i < cfg.Concurrency; i++ {
		go m.worker()
	}
	return m
}

func (m *Manager) now() time.Time { return m.nowFn() }

func (m *Manager) nextSeq() uint64 {
	m.seqMu.Lock()
	defer m.seqMu.Unlock()
	m.seq++
	return m.seq
}

func (m *Manager) nextID() string {
	n := m.nextSeq()
	return "j" + strconv.FormatUint(n, 36) + strconv.FormatInt(m.now().UnixNano()%1296, 36)
}

// cloneJob returns a snapshot safe to hand out / send on the event bus. Findings
// are copied because the slice header would otherwise alias the live record.
func cloneJob(j *Job) *Job {
	c := *j
	if j.Findings != nil {
		c.Findings = append([]Finding(nil), j.Findings...)
	}
	return &c
}

// Enqueue schedules a scan. On a cache hit (same slug+version already scanned)
// it returns a completed clone immediately unless force is set.
func (m *Manager) Enqueue(slug, name, version, batchID string, force bool) *Job {
	job := &Job{
		ID:         m.nextID(),
		BatchID:    batchID,
		Slug:       slug,
		PluginName: name,
		Version:    version,
		Status:     StatusQueued,
		QueuedAt:   m.now(),
	}

	m.mu.Lock()
	if !force {
		if cached, ok := m.cache[cacheKey(slug, version)]; ok {
			job.Status = StatusDone
			job.Findings = cached.Findings
			job.Counts = cached.Counts
			job.EngineMS = cached.EngineMS
			job.Truncated = cached.Truncated
			job.FromCache = true
			job.StartedAt = m.now()
			job.FinishedAt = m.now()
			m.store(job)
			snap := cloneJob(job)
			m.mu.Unlock()
			m.broadcast(snap)
			return snap
		}
	}
	m.store(job)
	snap := cloneJob(job)
	m.mu.Unlock()

	m.broadcast(snap)
	m.dispatch(job)
	return snap
}

// EnqueueBatch schedules many versions of one plugin under a shared batch id.
func (m *Manager) EnqueueBatch(slug, name string, versions []string, force bool) (string, []*Job) {
	batchID := "b" + strconv.FormatUint(m.nextSeq(), 36) + strconv.FormatInt(m.now().Unix(), 36)
	jobs := make([]*Job, 0, len(versions))
	for _, v := range versions {
		jobs = append(jobs, m.Enqueue(slug, name, v, batchID, force))
	}
	return batchID, jobs
}

// store records a job (caller holds m.mu), evicting the oldest TERMINAL jobs when
// over capacity. In-flight jobs are never evicted (no orphaning).
func (m *Manager) store(job *Job) {
	if _, exists := m.jobs[job.ID]; !exists {
		m.order = append(m.order, job.ID)
	}
	m.jobs[job.ID] = job
	if len(m.order) <= m.maxJobs {
		return
	}
	kept := m.order[:0:0]
	overflow := len(m.order) - m.maxJobs
	for _, id := range m.order {
		j := m.jobs[id]
		if overflow > 0 && (j == nil || j.Status.Terminal()) {
			delete(m.jobs, id)
			delete(m.cancels, id)
			overflow--
			continue
		}
		kept = append(kept, id)
	}
	m.order = kept
}

// cacheStore records a completed job's result (caller holds m.mu) with a cap.
func (m *Manager) cacheStore(job *Job) {
	key := cacheKey(job.Slug, job.Version)
	if _, exists := m.cache[key]; !exists {
		m.cacheOrder = append(m.cacheOrder, key)
	}
	m.cache[key] = job
	for len(m.cacheOrder) > m.maxCache {
		oldest := m.cacheOrder[0]
		m.cacheOrder = m.cacheOrder[1:]
		delete(m.cache, oldest)
	}
}

func (m *Manager) dispatch(job *Job) {
	m.qmu.Lock()
	m.pending = append(m.pending, job)
	m.qmu.Unlock()
	m.qcond.Signal()
}

func (m *Manager) worker() {
	for {
		m.qmu.Lock()
		for len(m.pending) == 0 && !m.closed {
			m.qcond.Wait()
		}
		if m.closed && len(m.pending) == 0 {
			m.qmu.Unlock()
			return
		}
		job := m.pending[0]
		m.pending = m.pending[1:]
		m.qmu.Unlock()
		m.runJob(job)
	}
}

func (m *Manager) runJob(job *Job) {
	m.mu.Lock()
	if job.Status.Terminal() { // canceled while queued
		m.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancels[job.ID] = cancel
	job.StartedAt = m.now()
	m.mu.Unlock()

	setStatus := func(s Status) {
		m.mu.Lock()
		if job.Status.Terminal() { // don't regress a canceled/finished job
			m.mu.Unlock()
			return
		}
		job.Status = s
		snap := cloneJob(job)
		m.mu.Unlock()
		m.broadcast(snap)
	}

	res, err := m.runner.Run(ctx, job.Slug, job.Version, setStatus)

	m.mu.Lock()
	delete(m.cancels, job.ID)
	job.FinishedAt = m.now()
	job.DurationMS = job.FinishedAt.Sub(job.StartedAt).Milliseconds()
	switch {
	case job.Status == StatusCanceled:
		// already canceled; keep terminal state
	case err == context.Canceled:
		job.Status = StatusCanceled
	case err != nil:
		job.Status = StatusFailed
		job.Error = err.Error()
	case res != nil && res.Skipped:
		job.Status = StatusSkipped
		job.Error = res.SkipMsg
	default:
		job.Status = StatusDone
		if res != nil {
			job.Findings = res.Findings
			job.Counts = res.Counts
			job.EngineMS = res.EngineMS
			job.Truncated = res.Truncated
		}
		m.cacheStore(job)
	}
	snap := cloneJob(job)
	m.mu.Unlock()
	cancel()
	m.broadcast(snap)
}

// Get returns a snapshot of a job by id.
func (m *Manager) Get(id string) (*Job, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	j, ok := m.jobs[id]
	if !ok {
		return nil, false
	}
	return cloneJob(j), true
}

// List returns job snapshots newest-first, optionally filtered by batch id.
func (m *Manager) List(batchID string) []*Job {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Job, 0, len(m.order))
	for i := len(m.order) - 1; i >= 0; i-- {
		j := m.jobs[m.order[i]]
		if j == nil {
			continue
		}
		if batchID != "" && j.BatchID != batchID {
			continue
		}
		out = append(out, cloneJob(j))
	}
	return out
}

// Cancel cancels a queued or running job. Returns false if unknown/terminal.
func (m *Manager) Cancel(id string) bool {
	m.mu.Lock()
	j, ok := m.jobs[id]
	if !ok || j.Status.Terminal() {
		m.mu.Unlock()
		return false
	}
	if j.Status == StatusQueued {
		j.Status = StatusCanceled
		j.FinishedAt = m.now()
	}
	cancel := m.cancels[id]
	snap := cloneJob(j)
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	m.broadcast(snap)
	return true
}

// ScannedVersions returns the set of versions of slug with a cached result.
func (m *Manager) ScannedVersions(slug string) map[string]SeverityCounts {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]SeverityCounts)
	for _, j := range m.cache {
		if j.Slug == slug {
			out[j.Version] = j.Counts
		}
	}
	return out
}

// Stats is a global rollup for the dashboard.
type Stats struct {
	TotalJobs      int            `json:"total_jobs"`
	Running        int            `json:"running"`
	Queued         int            `json:"queued"`
	Done           int            `json:"done"`
	Failed         int            `json:"failed"`
	Skipped        int            `json:"skipped"`
	PluginsScanned int            `json:"plugins_scanned"`
	Findings       SeverityCounts `json:"findings"`
}

// Stats computes a snapshot of aggregate counters.
func (m *Manager) Stats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var s Stats
	for _, j := range m.jobs {
		s.TotalJobs++
		switch j.Status {
		case StatusQueued:
			s.Queued++
		case StatusDownloading, StatusScanning:
			s.Running++
		case StatusDone:
			s.Done++
		case StatusFailed:
			s.Failed++
		case StatusSkipped:
			s.Skipped++
		}
	}
	for _, j := range m.cache {
		s.Findings.Critical += j.Counts.Critical
		s.Findings.High += j.Counts.High
		s.Findings.Medium += j.Counts.Medium
		s.Findings.Low += j.Counts.Low
		s.Findings.Info += j.Counts.Info
		s.Findings.Total += j.Counts.Total
	}
	s.PluginsScanned = len(m.cache)
	return s
}

// Subscribe registers an event listener; call the returned cancel to release it.
func (m *Manager) Subscribe() (<-chan Event, func()) {
	m.subMu.Lock()
	defer m.subMu.Unlock()
	id := m.subSeq
	m.subSeq++
	ch := make(chan Event, 128)
	m.subs[id] = ch
	return ch, func() {
		m.subMu.Lock()
		defer m.subMu.Unlock()
		if c, ok := m.subs[id]; ok {
			delete(m.subs, id)
			close(c)
		}
	}
}

func (m *Manager) broadcast(snap *Job) {
	m.subMu.Lock()
	defer m.subMu.Unlock()
	for _, ch := range m.subs {
		select {
		case ch <- Event{Type: "job", Job: snap}:
		default: // drop for slow consumers
		}
	}
}

// Close stops the worker pool after draining queued jobs (for tests/shutdown).
func (m *Manager) Close() {
	m.qmu.Lock()
	m.closed = true
	m.qmu.Unlock()
	m.qcond.Broadcast()
}

// Diff compares findings between two scanned versions of a plugin.
type Diff struct {
	Slug     string    `json:"slug"`
	VersionA string    `json:"version_a"`
	VersionB string    `json:"version_b"`
	Added    []Finding `json:"added"`   // present in B, not A (introduced)
	Removed  []Finding `json:"removed"` // present in A, not B (fixed)
	Common   []Finding `json:"common"`  // present in both
}

// Diff computes the finding delta between two cached versions.
func (m *Manager) Diff(slug, a, b string) (*Diff, bool) {
	m.mu.RLock()
	ja, oka := m.cache[cacheKey(slug, a)]
	jb, okb := m.cache[cacheKey(slug, b)]
	m.mu.RUnlock()
	if !oka || !okb {
		return nil, false
	}
	setA := make(map[string]Finding, len(ja.Findings))
	for _, f := range ja.Findings {
		setA[f.Key] = f
	}
	setB := make(map[string]Finding, len(jb.Findings))
	for _, f := range jb.Findings {
		setB[f.Key] = f
	}
	d := &Diff{Slug: slug, VersionA: a, VersionB: b}
	for _, f := range jb.Findings {
		if _, ok := setA[f.Key]; ok {
			d.Common = append(d.Common, f)
		} else {
			d.Added = append(d.Added, f)
		}
	}
	for _, f := range ja.Findings {
		if _, ok := setB[f.Key]; !ok {
			d.Removed = append(d.Removed, f)
		}
	}
	sortFindings(d.Added)
	sortFindings(d.Removed)
	sortFindings(d.Common)
	return d, true
}
