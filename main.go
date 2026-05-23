package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/parquet-go/parquet-go"
	"github.com/parquet-go/parquet-go/compress/snappy"
)

type LogEntry struct {
	ID               string  `parquet:"id"`
	DeploymentID     *string `parquet:"deployment_id"`
	Source           *string `parquet:"source"`
	Host             *string `parquet:"host"`
	Timestamp        *int64  `parquet:"timestamp"`
	ProjectID        *string `parquet:"project_id"`
	Level            *string `parquet:"level"`
	Message          *string `parquet:"message"`
	ProjectName      *string `parquet:"project_name"`
	BuildID          *string `parquet:"build_id"`
	Type             *string `parquet:"type"`
	Entrypoint       *string `parquet:"entrypoint"`
	RequestID        *string `parquet:"request_id"`
	StatusCode       *int32  `parquet:"status_code"`
	Path             *string `parquet:"path"`
	ExecutionRegion  *string `parquet:"execution_region"`
	Environment      *string `parquet:"environment"`
	TraceID          *string `parquet:"trace_id"`
	SpanID           *string `parquet:"span_id"`
	ProxyTimestamp   *int64  `parquet:"proxy_timestamp"`
	ProxyMethod      *string `parquet:"proxy_method"`
	ProxyHost        *string `parquet:"proxy_host"`
	ProxyPath        *string `parquet:"proxy_path"`
	ProxyUserAgent   *string `parquet:"proxy_user_agent"`
	ProxyReferer     *string `parquet:"proxy_referer"`
	ProxyRegion      *string `parquet:"proxy_region"`
	ProxyStatusCode  *int32  `parquet:"proxy_status_code"`
	ProxyClientIP    *string `parquet:"proxy_client_ip"`
	ProxyScheme      *string `parquet:"proxy_scheme"`
	ProxyVercelCache *string `parquet:"proxy_vercel_cache"`
}

type vercelLog struct {
	ID               string                 `json:"id"`
	DeploymentID     string                 `json:"deploymentId"`
	Source           string                 `json:"source"`
	Host             string                 `json:"host"`
	Timestamp        int64                  `json:"timestamp"`
	ProjectID        string                 `json:"projectId"`
	Level            string                 `json:"level"`
	Message          json.RawMessage        `json:"message"`
	ProjectName      string                 `json:"projectName"`
	BuildID          string                 `json:"buildId"`
	Type             string                 `json:"type"`
	Entrypoint       string                 `json:"entrypoint"`
	RequestID        string                 `json:"requestId"`
	StatusCode       *int32                 `json:"statusCode"`
	Path             string                 `json:"path"`
	ExecutionRegion  string                 `json:"executionRegion"`
	Environment      string                 `json:"environment"`
	TraceID          string                 `json:"traceId"`
	SpanID           string                 `json:"spanId"`
	TraceDotID       string                 `json:"trace.id"`
	SpanDotID        string                 `json:"span.id"`
	Proxy            map[string]interface{} `json:"proxy"`
}

func optInt32(i *int32) *int32 {
	if i == nil {
		return nil
	}
	v := *i
	return &v
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func intPtr(v int64) *int64 {
	return &v
}

func normalizeMessage(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	var obj interface{}
	if err := json.Unmarshal(raw, &obj); err == nil {
		switch obj.(type) {
		case map[string]interface{}, []interface{}:
			enc, _ := json.Marshal(obj)
			return string(enc)
		}
	}

	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		enc, _ := json.Marshal(map[string]string{"text": text})
		return string(enc)
	}

	return ""
}

func getProxyString(p map[string]interface{}, key string) *string {
	if p == nil {
		return nil
	}
	v, ok := p[key]
	if !ok {
		return nil
	}
	s, ok := v.(string)
	if !ok {
		return nil
	}
	return &s
}

func getProxyInt64(p map[string]interface{}, key string) *int64 {
	if p == nil {
		return nil
	}
	v, ok := p[key]
	if !ok {
		return nil
	}
	switch n := v.(type) {
	case float64:
		i := int64(n)
		return &i
	case int64:
		return &n
	}
	return nil
}

func getProxyInt32(p map[string]interface{}, key string) *int32 {
	if p == nil {
		return nil
	}
	v, ok := p[key]
	if !ok {
		return nil
	}
	n, ok := v.(float64)
	if !ok {
		return nil
	}
	i := int32(n)
	return &i
}

func getProxyUserAgent(p map[string]interface{}) *string {
	if p == nil {
		return nil
	}
	v, ok := p["userAgent"]
	if !ok {
		return nil
	}
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	var agents []string
	for _, a := range arr {
		if s, ok := a.(string); ok {
			agents = append(agents, s)
		}
	}
	if len(agents) == 0 {
		return nil
	}
	enc, _ := json.Marshal(agents)
	s := string(enc)
	return &s
}

func toLogEntry(v vercelLog) LogEntry {
	traceID := v.TraceID
	if traceID == "" {
		traceID = v.TraceDotID
	}
	spanID := v.SpanID
	if spanID == "" {
		spanID = v.SpanDotID
	}

	return LogEntry{
		ID:               v.ID,
		DeploymentID:     strPtr(v.DeploymentID),
		Source:           strPtr(v.Source),
		Host:             strPtr(v.Host),
		Timestamp:        intPtr(v.Timestamp),
		ProjectID:        strPtr(v.ProjectID),
		Level:            strPtr(v.Level),
		Message:          strPtr(normalizeMessage(v.Message)),
		ProjectName:      strPtr(v.ProjectName),
		BuildID:          strPtr(v.BuildID),
		Type:             strPtr(v.Type),
		Entrypoint:       strPtr(v.Entrypoint),
		RequestID:        strPtr(v.RequestID),
		StatusCode:       optInt32(v.StatusCode),
		Path:             strPtr(v.Path),
		ExecutionRegion:  strPtr(v.ExecutionRegion),
		Environment:      strPtr(v.Environment),
		TraceID:          strPtr(traceID),
		SpanID:           strPtr(spanID),
		ProxyTimestamp:   getProxyInt64(v.Proxy, "timestamp"),
		ProxyMethod:      getProxyString(v.Proxy, "method"),
		ProxyHost:        getProxyString(v.Proxy, "host"),
		ProxyPath:        getProxyString(v.Proxy, "path"),
		ProxyUserAgent:   getProxyUserAgent(v.Proxy),
		ProxyReferer:     getProxyString(v.Proxy, "referer"),
		ProxyRegion:      getProxyString(v.Proxy, "region"),
		ProxyStatusCode:  getProxyInt32(v.Proxy, "statusCode"),
		ProxyClientIP:    getProxyString(v.Proxy, "clientIp"),
		ProxyScheme:      getProxyString(v.Proxy, "scheme"),
		ProxyVercelCache: getProxyString(v.Proxy, "vercelCache"),
	}
}

type LogBuffer struct {
	mu       sync.Mutex
	entries  []LogEntry
	s3       *s3.Client
	bucket   string
}

func NewLogBuffer(s3Client *s3.Client, bucket string) *LogBuffer {
	return &LogBuffer{
		s3:     s3Client,
		bucket: bucket,
	}
}

func (b *LogBuffer) Append(entries []LogEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries = append(b.entries, entries...)
}

func (b *LogBuffer) Flush() {
	b.mu.Lock()
	entries := b.entries
	b.entries = nil
	b.mu.Unlock()

	if len(entries) == 0 {
		return
	}

	buf := new(bytes.Buffer)
	writer := parquet.NewGenericWriter[LogEntry](buf,
		parquet.Compression(&snappy.Codec{}),
	)
	writer.Write(entries)
	if err := writer.Close(); err != nil {
		log.Printf("Parquet write error: %v", err)
		return
	}

	if b.s3 != nil && b.bucket != "" {
		now := time.Now().UTC()
		key := fmt.Sprintf("logs/date=%s/%02d-%02d_%x.parquet",
			now.Format("2006-01-02"),
			now.Hour(),
			now.Minute(),
			now.UnixMilli())
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err := b.s3.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String(b.bucket),
			Key:    aws.String(key),
			Body:   bytes.NewReader(buf.Bytes()),
		})
		if err != nil {
			log.Printf("S3 upload error: %v", err)
			return
		}
		log.Printf("Flushed %d entries to s3://%s/%s", len(entries), b.bucket, key)
	} else {
		now := time.Now().UTC()
		filename := fmt.Sprintf("storage/logs/date=%s/%02d-%02d_%x.parquet",
			now.Format("2006-01-02"),
			now.Hour(),
			now.Minute(),
			now.UnixMilli())
		os.MkdirAll(fmt.Sprintf("storage/logs/date=%s", now.Format("2006-01-02")), 0755)
		os.WriteFile(filename, buf.Bytes(), 0644)
		log.Printf("Flushed %d entries to %s", len(entries), filename)
	}
}

func verifySignature(secret []byte, body []byte, header string) bool {
	if header == "" || len(secret) == 0 {
		return false
	}
	mac := hmac.New(sha1.New, secret)
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(header), []byte(expected))
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "4000"
	}
	secret := []byte(os.Getenv("VERCEL_WEBHOOK_SECRET"))
	if len(secret) == 0 {
		log.Fatal("VERCEL_WEBHOOK_SECRET must be set")
	}

	flushInterval := 15 * time.Second
	if s := os.Getenv("LOG_FLUSH_INTERVAL"); s != "" {
		if d, err := time.ParseDuration(s + "s"); err == nil {
			flushInterval = d
		}
	}

	var s3Client *s3.Client
	bucket := os.Getenv("S3_BUCKET")
	if bucket != "" {
		cfg, err := config.LoadDefaultConfig(context.Background(),
			config.WithRegion(os.Getenv("S3_REGION")),
		)
		if err != nil {
			log.Printf("AWS config error: %v, falling back to local disk", err)
		} else {
			if key := os.Getenv("AWS_ACCESS_KEY_ID"); key != "" {
				creds := credentials.NewStaticCredentialsProvider(
					key,
					os.Getenv("AWS_SECRET_ACCESS_KEY"),
					"",
				)
				cfg.Credentials = creds
			}
			s3Client = s3.NewFromConfig(cfg)
		}
	}

	buffer := NewLogBuffer(s3Client, bucket)
	go func() {
		ticker := time.NewTicker(flushInterval)
		defer ticker.Stop()
		for range ticker.C {
			buffer.Flush()
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK\n"))
	})

	mux.HandleFunc("/vercel", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if verifyToken := r.Header.Get("x-vercel-verify"); verifyToken != "" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(verifyToken))
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		sig := r.Header.Get("x-vercel-signature")
		if !verifySignature(secret, body, sig) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		var logs []vercelLog
		if err := json.Unmarshal(body, &logs); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		entries := make([]LogEntry, len(logs))
		for i, l := range logs {
			entries[i] = toLogEntry(l)
		}
		buffer.Append(entries)
		log.Printf("Buffered %d log entries", len(entries))

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK\n"))
	})

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down, flushing remaining logs...")
		buffer.Flush()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()

	log.Printf("Listening on :%s", port)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
