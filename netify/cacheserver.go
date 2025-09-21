package netify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"regexp"
	"strconv"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

const ipEndpoint = "https://feeds.netify.ai/api/v2/ips"
const hostnameEndpoint = "https://feeds.netify.ai/api/v2/hostnames"

type CacheServer struct {
	ApiKey          string
	CacheServerPort int
	CacheFilesDir   string

	ipCacheFilesDir      string
	hostnameCacheFileDir string

	isServerOn    bool
	httpClient    *http.Client
	httpServer    *http.Server
	httpServerUrl string

	ipCacheStats       *cacheStats
	hostnameCacheStats *cacheStats
}

func (c *CacheServer) Init() error {
	c.httpClient = &http.Client{
		Timeout: 30 * time.Second,
	}

	c.ipCacheFilesDir = path.Join(c.CacheFilesDir, "ips")
	c.hostnameCacheFileDir = path.Join(c.CacheFilesDir, "hostnames")

	c.ipCacheStats = &cacheStats{}
	c.hostnameCacheStats = &cacheStats{}

	mux := http.NewServeMux()
	mux.HandleFunc("/ips/{ip}", c.getIpData)
	mux.HandleFunc("/hostnames/{hostname}", c.getHostnameData)

	c.httpServer = &http.Server{
		Addr:    ":" + strconv.Itoa(c.CacheServerPort),
		Handler: mux,
	}
	c.httpServerUrl = "http://localhost" + c.httpServer.Addr

	go func() {
		if err := c.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalln(err)
		}
	}()

	for range 10 {
		if conn, err := net.DialTimeout("tcp", c.httpServer.Addr, 500*time.Millisecond); err == nil {
			conn.Close()
			log.Warning("server started")
			c.isServerOn = true
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}

	return fmt.Errorf("error starting cache server")
}

// Shutdown Should be called in defer
func (c *CacheServer) Shutdown() error {
	c.isServerOn = false
	return c.httpServer.Shutdown(context.Background())
}

func (c *CacheServer) getIpData(w http.ResponseWriter, r *http.Request) {
	muxHandle(c, w, r, "ip", func(s string) bool {
		return net.ParseIP(s) != nil
	}, c.ipCacheFilesDir, ipEndpoint, c.ipCacheStats)
}

var domainRegex = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

func (c *CacheServer) getHostnameData(w http.ResponseWriter, r *http.Request) {
	muxHandle(c, w, r, "hostname", func(s string) bool {
		return domainRegex.MatchString(s)
	}, c.hostnameCacheFileDir, hostnameEndpoint, c.hostnameCacheStats)
}

func muxHandle(c *CacheServer, w http.ResponseWriter, r *http.Request,
	pathValueName string, validPathValue func(string) bool,
	cacheDir string, endpoint string, cacheStat *cacheStats) {

	var (
		body       []byte
		statusCode = http.StatusOK
	)

	pathValue := r.PathValue(pathValueName)
	if !validPathValue(pathValue) {
		statusCode = http.StatusBadRequest
		body = []byte("{\"Status\": \"invalid " + pathValueName + " " + pathValue + "\"}")
	} else {
		fileName := pathValue + ".json"
		file := path.Join(cacheDir, fileName)
		liveURL := endpoint + "/" + pathValue + "?x-api-key=" + c.ApiKey
		statusCode, body = serveCachedOrLive(c.httpClient, file, liveURL, cacheStat)

		if err := cacheResponse(cacheDir, fileName, body); err != nil {
			statusCode = http.StatusInternalServerError
			body = []byte("{\"Status\": \"error saving cache file " + file + "\"}")
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(body)
}

func (c *CacheServer) QueryIPData(ipStr string) (*IPData, error) {
	return query[IPData](c, "/ips/", ipStr)
}

func (c *CacheServer) QueryHostnameData(hostname string) (*HostnameData, error) {
	return query[HostnameData](c, "/hostnames/", hostname)
}

func query[T any](c *CacheServer, endpoint string, parameter string) (*T, error) {
	if !c.isServerOn {
		return nil, fmt.Errorf("server cache is not running")
	}

	req, err := c.httpClient.Get(c.httpServerUrl + endpoint + parameter)
	if err != nil {
		return nil, err
	}
	defer req.Body.Close()
	body, _ := io.ReadAll(req.Body)
	if req.StatusCode > 299 {
		return nil, fmt.Errorf(string(body))
	}

	var data T
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	return &data, nil

}

// IPCacheStats Returns number of cached and requested resources
func (c *CacheServer) IPCacheStats() (int64, int64) {
	return c.ipCacheStats.cached.Load(), c.ipCacheStats.requested.Load()
}

// HostnameCacheStats Returns number of cached and requested resources
func (c *CacheServer) HostnameCacheStats() (int64, int64) {
	return c.hostnameCacheStats.cached.Load(), c.hostnameCacheStats.requested.Load()
}

type cacheStats struct {
	cached    atomic.Int64
	requested atomic.Int64
}

const retryDelay = 5 * time.Second
const maxRetries = 3
const minRateLimitAvailable = 3

//goland:noinspection D
func serveCachedOrLive(httpClient *http.Client, cacheFile string, liveURL string, cacheStats *cacheStats) (int, []byte) {
	if stat, err := os.Stat(cacheFile); err == nil && stat.Size() > 0 {
		body, _ := os.ReadFile(cacheFile)
		cacheStats.cached.Add(1)
		return http.StatusOK, body
	} else {
		for i := 0; i < maxRetries; i++ {
			res, err := httpClient.Get(liveURL)
			if err != nil {
				return http.StatusInternalServerError, []byte(fmt.Sprintf("{\"Status\": \"Error fetching live URL: %v\"}", err))
			}

			body, readErr := io.ReadAll(res.Body)
			res.Body.Close()
			if readErr != nil {
				return http.StatusInternalServerError, []byte(fmt.Sprintf("{\"Status\": \"Error reading response body: %v\"}", readErr))
			}

			switch res.StatusCode {
			case http.StatusOK:
				cacheStats.requested.Add(1)
				return res.StatusCode, body
			case http.StatusTooManyRequests:
				time.Sleep(retryDelay)
			default:
				if remaining := res.Header.Get("X-RateLimit-Remaining"); remaining != "" {
					remainingInt, err := strconv.Atoi(remaining)
					if err == nil && remainingInt < minRateLimitAvailable {
						time.Sleep(5 * time.Second)
					}
				}
				return res.StatusCode, []byte(fmt.Sprintf("{\"Status\": \"Error: %s\"}", res.Status))
			}
		}
		return http.StatusInternalServerError, []byte("{\"Status\": \"Server error\"}")
	}
}

func cacheResponse(dir string, fileName string, body []byte) error {
	filePath := path.Join(dir, fileName)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return err
	}
	if stat, err := os.Stat(filePath); err != nil || stat.Size() == 0 {
		return os.WriteFile(filePath, body, 0644)
	}

	return nil
}
