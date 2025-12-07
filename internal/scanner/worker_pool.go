package scanner

import (
	"context"
	"sync"
	"time"

	"github.com/react2shell/scanner/pkg/models"
)

type Job struct {
	URL     string
	Options *models.ScanOptions
	Mode    models.ScanMode
}

type Result struct {
	ScanResult *models.ScanResult
	Error      error
}

type WorkerPool struct {
	scanner      Scanner
	workerCount  int
	jobQueue     chan Job
	resultQueue  chan Result
	wg           sync.WaitGroup
	ctx          context.Context
	cancel       context.CancelFunc
}

func NewWorkerPool(scanner Scanner, workerCount int) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())
	return &WorkerPool{
		scanner:     scanner,
		workerCount: workerCount,
		jobQueue:    make(chan Job, workerCount*2),
		resultQueue: make(chan Result, workerCount*2),
		ctx:         ctx,
		cancel:      cancel,
	}
}

func (wp *WorkerPool) Start() {
	for i := 0; i < wp.workerCount; i++ {
		wp.wg.Add(1)
		go wp.worker()
	}
}

func (wp *WorkerPool) worker() {
	defer wp.wg.Done()

	for {
		select {
		case <-wp.ctx.Done():
			return
		case job, ok := <-wp.jobQueue:
			if !ok {
				return
			}

			ctx, cancel := context.WithTimeout(wp.ctx, 30*time.Second)
			var result Result

			switch job.Mode {
			case models.ModeVersion:
				result.ScanResult, result.Error = wp.scanner.ScanVersion(ctx, job.URL)
			case models.ModeSafe:
				result.ScanResult, result.Error = wp.scanner.ScanSafe(ctx, job.URL)
			case models.ModeRCE:
				result.ScanResult, result.Error = wp.scanner.ScanRCE(ctx, job.URL, job.Options)
			case models.ModeComprehensive:
				result.ScanResult, result.Error = wp.scanner.ScanComprehensive(ctx, job.URL, job.Options)
			}

			cancel()

			select {
			case wp.resultQueue <- result:
			case <-wp.ctx.Done():
				return
			}
		}
	}
}

func (wp *WorkerPool) Submit(job Job) error {
	select {
	case wp.jobQueue <- job:
		return nil
	case <-wp.ctx.Done():
		return wp.ctx.Err()
	}
}

func (wp *WorkerPool) Results() <-chan Result {
	return wp.resultQueue
}

func (wp *WorkerPool) Close() {
	close(wp.jobQueue)
	wp.cancel()
	wp.wg.Wait()
	close(wp.resultQueue)
}

func (wp *WorkerPool) Shutdown() {
	wp.Close()
}

