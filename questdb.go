package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
)

func InitQuestDB(URL string, tableName string) error {
	if res, err := http.Get(URL + "/exec?query=" + url.QueryEscape("SELECT NOW();")); err != nil || res.StatusCode > 299 {
		return fmt.Errorf("unable to ping database. status code: %d, err :%v", res.StatusCode, err)
	}

	if err := DeletePacketTable(URL, tableName); err != nil {
		return err
	}

	if err := CreatePacketTable(URL, tableName); err != nil {
		return err
	}

	return nil
}

func CreatePacketTable(URL string, tableName string) error {
	const query = `
		CREATE TABLE IF NOT EXISTS %s (
			ts TIMESTAMP,
			ip_src IPV4,
			ip_src_type SYMBOL,
			port_src INT,
			ip_dst IPV4,
			ip_dst_type SYMBOL,
			port_dst INT,
			frame_len SHORT,
			ip_proto SYMBOL,
			tls_sni SYMBOL,
			tls_alpn SYMBOL,
			stream_index INT
		), INDEX(tls_sni) TIMESTAMP(ts) PARTITION BY DAY WAL;`

	queryComplete := fmt.Sprintf(query, tableName)

	resp, err := http.Get(URL + "/exec?query=" + url.QueryEscape(queryComplete))
	if resp.StatusCode > 299 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("error creating table, status: %s, body: %s", resp.Status, string(body))
	}
	return err
}

func DeletePacketTable(URL string, tableName string) error {
	const query = `DROP TABLE IF EXISTS %s;`

	queryComplete := fmt.Sprintf(query, tableName)

	resp, err := http.Get(URL + "/exec?query=" + url.QueryEscape(queryComplete))
	if resp.StatusCode > 299 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("error dropping table, status: %s, body: %s", resp.Status, string(body))
	}
	return err

}
