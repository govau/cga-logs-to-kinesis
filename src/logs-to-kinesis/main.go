package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cloudfoundry/sonde-go/events"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	kinesis "github.com/sendgridlabs/go-kinesis"
	"github.com/sendgridlabs/go-kinesis/batchproducer"
)

var (
	bufferSize = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "firehose_to_kinesis_buffer_size",
	}, []string{"system"})
	errorCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "firehose_to_kinesis_errors_count",
	}, []string{"system"})
	successCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "firehose_to_kinesis_sent_count",
	}, []string{"system"})
	droppedCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "firehose_to_kinesis_dropped_count",
	}, []string{"system"})
)

func init() {
	prometheus.MustRegister(bufferSize)
	prometheus.MustRegister(errorCount)
	prometheus.MustRegister(successCount)
	prometheus.MustRegister(droppedCount)
}

// LogWatcher will watch a bunfh of files and write to Kinesis
type LogWatcher struct {
	options *LogWatchOptions
	ctx     context.Context
	cx      context.CancelFunc
	wg      sync.WaitGroup

	thingsMonitored map[string]bool
	thingsMU        sync.Mutex
}

// NewKinesisProducer creates a new producer that pushes to Kinesis
func NewKinesisProducer(options KinesisOptions) (batchproducer.Producer, error) {
	var err error
	var kinAuth kinesis.Auth
	if options.AWSAccessKey == "" {
		kinAuth, err = kinesis.NewAuthFromMetadata()
		if err != nil {
			return nil, err
		}
	} else {
		kinAuth = kinesis.NewAuth(options.AWSAccessKey, options.AWSAccessSecret, "")
	}

	// assume role if needed
	if options.AWSRole != "" {
		kinAuth, err = kinesis.NewAuthWithAssumedRole(options.AWSRole, options.AWSRegion, kinAuth)
		if err != nil {
			return nil, err
		}
	}

	bpCB := &bpCallback{
		options: &options,
	}
	kinBP, err := batchproducer.New(kinesis.NewWithClient(options.AWSRegion, kinesis.NewClient(kinAuth)), options.AWSStreamName, batchproducer.Config{
		AddBlocksWhenBufferFull: true,
		BatchSize:               batchproducer.MaxKinesisBatchSize,
		BufferSize:              batchproducer.MaxKinesisBatchSize * 10,
		FlushInterval:           5 * time.Second,
		MaxAttemptsPerRecord:    5,
		Logger:                  bpCB,
		StatInterval:            5 * time.Second,
		StatReceiver:            bpCB,
	})
	if err != nil {
		return nil, err
	}
	return kinBP, nil
}

// LogWatchOptions has options for creating the LogWatch
type LogWatchOptions struct {
	// Instance is stamped into messages
	Instance string

	// Producer
	Producer batchproducer.Producer
}

// KinesisOptions has the options for Kinesis
type KinesisOptions struct {
	// AWSRegion where the stream is
	AWSRegion string

	// AWSRole optional role to assume
	AWSRole string

	// AWSStreamName which stream to write to
	AWSStreamName string

	// AWSAccessKey is optional. If left emtpty, instance profile is used
	AWSAccessKey string

	// AWSAccessSecret must be set if key is set
	AWSAccessSecret string

	// Instance is stamped into metrics
	Instance string

	// Verbose
	Verbose bool
}

type bpCallback struct {
	options *KinesisOptions
}

func (b *bpCallback) Printf(fmt string, args ...interface{}) {
	// enable for debugging, but leave off in prod else we'll get into a log spiral
	if b.options.Verbose {
		log.Printf(fmt, args...)
	}
}

func (b *bpCallback) Receive(sb batchproducer.StatsBatch) {
	errorCount.WithLabelValues(b.options.Instance).Add(float64(sb.KinesisErrorsSinceLastStat))
	successCount.WithLabelValues(b.options.Instance).Add(float64(sb.RecordsSentSuccessfullySinceLastStat))
	droppedCount.WithLabelValues(b.options.Instance).Add(float64(sb.RecordsDroppedSinceLastStat))
	bufferSize.WithLabelValues(b.options.Instance).Set(float64(sb.BufferSize))
}

// NewLogWatcher creates a new LogWatcher and starts background processes.
// Call Close() to release these
func NewLogWatcher(ctx context.Context, options LogWatchOptions) (*LogWatcher, error) {
	c, cx := context.WithCancel(ctx)
	rv := &LogWatcher{
		options:         &options,
		ctx:             c,
		cx:              cx,
		thingsMonitored: make(map[string]bool),
	}
	err := rv.startBackground()
	if err != nil {
		return nil, err
	}

	return rv, nil
}

func (w *LogWatcher) startBackground() error {
	// start the batchproducer
	err := w.options.Producer.Start()
	if err != nil {
		return err
	}
	w.wg.Add(1)

	// wait for our context to close, and when it does,
	// stop all the processes and mark as done
	go func() {
		<-w.ctx.Done()
		w.options.Producer.Flush(time.Second*10, true)
		w.wg.Done()
	}()

	return nil
}

// Close will release resources
func (w *LogWatcher) Close() {
	// cancel our context
	w.cx()

	// and wait for it to close all our stuff
	w.wg.Wait()
}

// tryLickCookie returns true if able to successfully "lick the cookie", ie
// get first dibs on this key. If someone else has already "licked" it, return
// false.
func (w *LogWatcher) tryLickCookie(key string) bool {
	w.thingsMU.Lock()
	defer w.thingsMU.Unlock()
	watched, ok := w.thingsMonitored[key]
	if ok && watched {
		return false
	}
	w.thingsMonitored[key] = true
	return true
}

func (w *LogWatcher) runTail(path string) error {
	cmd := exec.CommandContext(w.ctx, "tail", "--follow=name", "--retry", path)
	stdOut, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	err = cmd.Start()
	if err != nil {
		return err
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	br := bufio.NewReader(stdOut)
	for {
		line, err := br.ReadBytes('\n')
		switch err {
		case nil:
			err = w.processLine(path, line)
			if err != nil {
				return err
			}
		case io.EOF:
			if len(line) != 0 {
				err = w.processLine(path, line)
				if err != nil {
					return err
				}
			}
			return nil
		default:
			return err
		}
	}
}

// WatchFile will watch the given file. It's OK if it doesn't exist yet
func (w *LogWatcher) WatchFile(path string) error {
	if !w.tryLickCookie(fmt.Sprintf("file:%s", hex.EncodeToString([]byte(path)))) {
		return nil
	}

	// make tail do the hard work for us
	go func() {
		// start right away, then if we fail, wait for a short period before retry..
		for t := time.NewTimer(time.Millisecond * 1); true; t.Reset(time.Second * 5) {
			select {
			case <-w.ctx.Done():
				return // we're done
			case <-t.C:
				log.Printf("starting tail for: %s", path)
				err := w.runTail(path)
				if err != nil {
					log.Printf("tail finished for %s with err: %s", path, err)
				}
			}
		}
	}()

	return nil
}

// WatchDir will look for files matching fglob in the dir path, rescanning every minute
func (w *LogWatcher) WatchDir(path, fglob string) error {
	if !w.tryLickCookie(fmt.Sprintf("dir:%s,glob:%s", hex.EncodeToString([]byte(path)), hex.EncodeToString([]byte(fglob)))) {
		return nil
	}

	// start monitoring
	go func() {
		for t := time.NewTimer(time.Second * 0); true; t.Reset(time.Minute) {
			select {
			case <-w.ctx.Done():
				return // we're done
			case <-t.C:
				err := filepath.Walk(path, func(childPath string, info os.FileInfo, e error) error {
					// we don't care for errors
					if e != nil {
						return e
					}

					// if not a file, we don't care about it
					if !info.Mode().IsRegular() {
						return nil
					}

					// if it doesn't match our glob, then we don't care
					match, err := filepath.Match(fglob, info.Name())
					if err != nil {
						return err
					}
					if !match {
						return nil
					}

					// ok, we must care - let's watch it then
					return w.WatchFile(childPath)
				})
				if err != nil {
					log.Printf("error (which we'll ignore) walking %s: %s", path, err)
				}
			}
		}
	}()

	return nil
}

var (
	logMessage  = events.Envelope_LogMessage
	messageType = events.LogMessage_OUT
	sourceType  = "bosh"
)

func (w *LogWatcher) processLine(fpath string, line []byte) error {
	ts := time.Now().UnixNano()
	b, err := (&events.Envelope{
		EventType: &logMessage,
		Origin:    &w.options.Instance,
		LogMessage: &events.LogMessage{
			Timestamp:      &ts,
			SourceType:     &sourceType,
			SourceInstance: &fpath,
			Message:        line,
			MessageType:    &messageType,
		},
	}).Marshal()
	if err != nil {
		return err
	}
	return w.options.Producer.Add(b, fpath)
}

type logProducer struct{}

func (*logProducer) Add(data []byte, pkey string) error {
	log.Printf("Add: %s to %s", data, pkey)
	return nil
}

func (*logProducer) Flush(time.Duration, bool) (int, int, error) {
	log.Println("Flushing...")
	return 0, 0, nil
}

func (*logProducer) Start() error {
	log.Println("Starting producer...")
	return nil
}

func (*logProducer) Stop() error {
	log.Println("Stopping producer...")
	return nil
}

func run() error {
	log.Println("starting app...")
	defer log.Println("stopping app...")

	kp, err := NewKinesisProducer(KinesisOptions{
		AWSStreamName:   os.Getenv("AWS_KINESIS_DATA_STREAM"),
		AWSRegion:       os.Getenv("AWS_REGION"),
		AWSRole:         os.Getenv("AWS_ROLE"),
		AWSAccessKey:    os.Getenv("AWS_ACCESS_KEY_ID"),
		AWSAccessSecret: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		Instance:        os.Getenv("INSTANCE"),
		Verbose:         os.Getenv("DEBUG") == "1",
	})
	if err != nil {
		return err
	}
	w, err := NewLogWatcher(context.Background(), LogWatchOptions{
		Instance: os.Getenv("INSTANCE"),
		Producer: kp,
	})
	if err != nil {
		return err
	}
	for _, fpath := range strings.Split(os.Getenv("FILES_TO_WATCH"), ":") {
		err = w.WatchFile(fpath)
		if err != nil {
			return err
		}
	}
	for _, dpath := range strings.Split(os.Getenv("DIRS_TO_WATCH"), ":") {
		bits := strings.SplitN(dpath, "/**/", 2)
		err = w.WatchDir(bits[0], bits[1])
		if err != nil {
			return err
		}
	}
	defer w.Close()

	go func() {
		http.Handle("/metrics", promhttp.Handler())
		http.ListenAndServe(":"+os.Getenv("PORT"), nil)
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	return nil
}

func main() {
	err := run()
	if err != nil {
		log.Fatal(err)
	}
}
