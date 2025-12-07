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
	scanner     Scanner
	maxWorkers  int
	semaphore   chan struct{}
	resultQueue chan Result
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
}

func NewWorkerPool(scanner Scanner, maxWorkers int) *WorkerPool {
	if maxWorkers <= 0 {
		maxWorkers = 100
	}
	if maxWorkers > 500 {
		maxWorkers = 500
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &WorkerPool{
		scanner:     scanner,
		maxWorkers:  maxWorkers,
		semaphore:   make(chan struct{}, maxWorkers),
		resultQueue: make(chan Result),
		ctx:         ctx,
		cancel:      cancel,
	}
}

func (wp *WorkerPool) ProcessJobs(ctx context.Context, jobs <-chan Job) <-chan Result {
	go func() {
		defer close(wp.resultQueue)

		for {
			select {
			case <-ctx.Done():
				return
			case <-wp.ctx.Done():
				return
			case job, ok := <-jobs:
				if !ok {
					return
				}

				wp.wg.Add(1)

				select {
				case wp.semaphore <- struct{}{}:
				case <-ctx.Done():
					wp.wg.Done()
					return
				case <-wp.ctx.Done():
					wp.wg.Done()
					return
				}

				go func(j Job) {
					defer func() {
						<-wp.semaphore
						wp.wg.Done()
					}()

					scanCtx, cancel := context.WithTimeout(wp.ctx, time.Duration(j.Options.Timeout+5)*time.Second)
					defer cancel()

					var result Result

					switch j.Mode {
					case models.ModeVersion:
						result.ScanResult, result.Error = wp.scanner.ScanVersion(scanCtx, j.URL)
					case models.ModeSafe:
						result.ScanResult, result.Error = wp.scanner.ScanSafe(scanCtx, j.URL)
					case models.ModeRCE:
						result.ScanResult, result.Error = wp.scanner.ScanRCE(scanCtx, j.URL, j.Options)
					case models.ModeComprehensive:
						result.ScanResult, result.Error = wp.scanner.ScanComprehensive(scanCtx, j.URL, j.Options)
					}

					if result.ScanResult == nil && result.Error == nil {
						result.ScanResult = &models.ScanResult{
							URL:   j.URL,
							Error: "scan returned nil result",
						}
					}

					select {
					case wp.resultQueue <- result:
					case <-wp.ctx.Done():
					case <-ctx.Done():
					case <-time.After(2 * time.Second):
					}
				}(job)
			}
		}
	}()

	return wp.resultQueue
}

func (wp *WorkerPool) Close() {
	wp.cancel()
	wp.wg.Wait()
}
