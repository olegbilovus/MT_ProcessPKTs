package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type QuestDBClient struct {
	http *http.Client
	url  string
}

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
		) TIMESTAMP(ts) PARTITION BY DAY WAL;`

	queryComplete := fmt.Sprintf(query, tableName)

	resp, err := c.http.Get(c.url + "/exec?query=" + url.QueryEscape(queryComplete))
	if resp.StatusCode > 299 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("error creating table, status: %s, body: %s", resp.Status, string(body))
	}
	return err
}
