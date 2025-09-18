package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type QuestDBClient struct {
	http *http.Client
	url  string
}

// NewQuestDBClient creates a new QuestDB client with connection pooling
func NewQuestDBClient(URL string) (*QuestDBClient, error) {
	httpClient := &http.Client{}

	if res, err := http.Get(URL + "/exec?query=" + url.QueryEscape("SELECT NOW();")); err != nil || res.StatusCode > 299 {
		return nil, fmt.Errorf("unable to ping database. status code: %d, err :%v", res.StatusCode, err)
	}

	return &QuestDBClient{http: httpClient, url: URL}, nil
}

func CreatePacketTable(c *QuestDBClient, tableName string) error {
	const query = `
		CREATE TABLE IF NOT EXISTS %s (
			ts TIMESTAMP,
			ip_src IPV4,
			port_src INT,
			ip_dst IPV4,
			port_dst INT,
			frame_len SHORT,
			ip_proto SYMBOL,
			tls_sni SYMBOL,
			tls_alpn SYMBOL,
			stream_index INT
		) TIMESTAMP(ts) PARTITION BY DAY WAL
		DEDUP UPSERT KEYS(ts);`

	queryComplete := fmt.Sprintf(query, tableName)

	resp, err := c.http.Get(c.url + "/exec?query=" + url.QueryEscape(queryComplete))
	if resp.StatusCode > 299 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("error creating table, status: %s, body: %s", resp.Status, string(body))
	}
	return err
}

type QuestDBImpResp struct {
	Status       string `json:"status"`
	Location     string `json:"location"`
	RowsRejected int    `json:"rowsRejected"`
	RowsImported int    `json:"rowsImported"`
	Header       bool   `json:"header"`
	Columns      []struct {
		Name   string `json:"name"`
		Type   string `json:"type"`
		Size   int    `json:"size"`
		Errors int    `json:"errors"`
	} `json:"columns"`
}

func SendPacketsToQuestDB(pkts []*Packet, client *QuestDBClient, tableName string) (int, error) {
	const headers = "ts,ip_src,port_src,ip_dst,port_dst,frame_len,ip_proto,tls_sni,tls_alpn,stream_index\n"
	lines := headers
	for _, pkt := range pkts {
		lines += packetToCSV(pkt) + "\n"
	}

	buf := new(bytes.Buffer)
	writer := multipart.NewWriter(buf)
	part, err := writer.CreateFormFile("data", tableName)
	if err != nil {
		return -1, err
	}
	_, err = io.Copy(part, strings.NewReader(lines))
	if err != nil {
		return -1, err
	}
	writer.Close()

	req, err := http.NewRequest(http.MethodPost, client.url+"/imp?create=false&fmt=json&timestamp=ts", buf)
	if err != nil {
		return -1, err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := client.http.Do(req)
	if err != nil {
		return -1, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return -1, fmt.Errorf("QuestDB returned status %d: %s", resp.StatusCode, string(body))
	}

	var impResp QuestDBImpResp
	if err := json.Unmarshal(body, &impResp); err != nil {
		return -1, fmt.Errorf("Failed to parse QuestDB response: %v\nResponse body: %s", err, string(body))
	}

	if impResp.RowsRejected > 0 {
		return impResp.RowsImported, fmt.Errorf("some rows were rejected, count: %d, err %s", impResp.RowsRejected, impResp.Status)
	}

	if impResp.Status != "OK" {
		return -1, fmt.Errorf(impResp.Status)
	}

	return impResp.RowsImported, nil
}

func packetToCSV(pkt *Packet) string {
	return fmt.Sprintf("\"%s\",%s,%d,%s,%d,%d,%s,\"%s\",\"%s\",%d",
		pkt.Time.Format(time.RFC3339Nano), // ts
		pkt.IpSrc,                         // ip_src
		pkt.PortSrc,                       // port_src
		pkt.IpDst,                         // ip_dst
		pkt.PortDst,                       // port_dst
		pkt.FrameLen,                      // frame_len
		pkt.IpProto.String(),              // ip_proto
		pkt.Sni,                           // tls_sni
		pkt.Alpn,                          // tls_alpn
		pkt.StreamIndex,                   // stream_index
	)
}
