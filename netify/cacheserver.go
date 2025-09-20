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
			log.Warning("Server started")
			c.isServerOn = true
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("error starting cache server")
}

// Shutdown Should be called in defer
func (c *CacheServer) Shutdown() error {
	c.isServerOn = false
	return c.httpServer.Shutdown(context.Background())
}

func (c *CacheServer) getIpData(w http.ResponseWriter, r *http.Request) {
	var (
		body       []byte
		statusCode = http.StatusOK
	)

	ipStr := r.PathValue("ip")
	if ip := net.ParseIP(ipStr); ip == nil {
		statusCode = http.StatusBadRequest
		body = []byte("{\"Status\": \"invalid ip address " + ipStr + "\"}")

	} else {
		fileName := ipStr + ".json"
		file := path.Join(c.ipCacheFilesDir, fileName)
		liveURL := ipEndpoint + "/" + ipStr + "?x-api-key=" + c.ApiKey
		statusCode, body = serveCachedOrLive(c.httpClient, file, liveURL, c.ipCacheStats)

		if err := cacheResponse(c.ipCacheFilesDir, fileName, body); err != nil {
			statusCode = http.StatusInternalServerError
			body = []byte("{\"Status\": \"error saving cache file " + file + "\"}")
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(body)
}

func (c *CacheServer) getHostnameData(w http.ResponseWriter, _ *http.Request) {

}

func (c *CacheServer) QueryIPData(ipStr string) (*IPData, error) {
	if !c.isServerOn {
		return nil, fmt.Errorf("server cache is not running")
	}

	req, err := c.httpClient.Get(c.httpServerUrl + "/ips/" + ipStr)
	if err != nil {
		return nil, err
	}
	defer req.Body.Close()
	body, _ := io.ReadAll(req.Body)
	if req.StatusCode > 299 {
		return nil, fmt.Errorf(string(body))
	}

	var ipData IPData
	if err := json.Unmarshal(body, &ipData); err != nil {
		return nil, err
	}

	return &ipData, nil
}

func (c *CacheServer) QueryHostnameData(hostname string) *HostnameData {
	panic("To implement")
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

func serveCachedOrLive(httpClient *http.Client, cacheFile string, liveURL string, cacheStats *cacheStats) (int, []byte) {
	if stat, err := os.Stat(cacheFile); err == nil && stat.Size() > 0 {
		body, _ := os.ReadFile(cacheFile)
		cacheStats.cached.Add(1)
		return http.StatusOK, body
	} else {
		res, _ := httpClient.Get(liveURL)
		if res != nil {
			defer res.Body.Close()
			body, _ := io.ReadAll(res.Body)
			cacheStats.requested.Add(1)
			return res.StatusCode, body
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
