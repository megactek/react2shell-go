package utils

import (
	"context"
	"io"
	"time"
)

type timeoutReader struct {
	reader  io.Reader
	timeout time.Duration
}

func NewTimeoutReader(reader io.Reader, timeout time.Duration) io.Reader {
	return &timeoutReader{
		reader:  reader,
		timeout: timeout,
	}
}

func (tr *timeoutReader) Read(p []byte) (n int, err error) {
	type result struct {
		n   int
		err error
	}

	done := make(chan result, 1)

	go func() {
		n, err := tr.reader.Read(p)
		done <- result{n: n, err: err}
	}()

	select {
	case res := <-done:
		return res.n, res.err
	case <-time.After(tr.timeout):
		return 0, context.DeadlineExceeded
	}
}

func ReadAllWithTimeout(reader io.Reader, timeout time.Duration, maxSize int) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	type result struct {
		data []byte
		err  error
	}

	done := make(chan result, 1)

	go func() {
		limitedReader := io.LimitReader(reader, int64(maxSize))
		data, err := io.ReadAll(limitedReader)
		done <- result{data: data, err: err}
	}()

	select {
	case res := <-done:
		return res.data, res.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

