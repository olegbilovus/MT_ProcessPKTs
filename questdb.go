package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
)

func InitQuestDB(URL string, experimentName string) error {
	if res, err := http.Get(URL + "/exec?query=" + url.QueryEscape("SELECT NOW();")); err != nil || res.StatusCode > 299 {
		return fmt.Errorf("unable to ping database. status code: %d, err :%v", res.StatusCode, err)
	}

	if err := InsertIntoExperimentsTable(URL, experimentName); err != nil {
		return err
	}
	if err := DeletePacketTable(URL, experimentName); err != nil {
		return err
	}
	if err := CreatePacketTable(URL, experimentName); err != nil {
		return err
	}

	return nil
}

func CreatePacketTable(URL string, experimentName string) error {
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

	queryComplete := fmt.Sprintf(query, GetTableName(experimentName))

	resp, err := http.Get(URL + "/exec?query=" + url.QueryEscape(queryComplete))
	if resp.StatusCode > 299 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("error creating table, status: %s, body: %s", resp.Status, string(body))
	}
	return err
}

func InsertIntoExperimentsTable(URL string, experimentName string) error {
	const queryCreateTable = `
		CREATE TABLE IF NOT EXISTS experiments (
			  ts TIMESTAMP,
			  name VARCHAR,
			  active BOOLEAN
			) TIMESTAMP(ts) PARTITION BY DAY WAL DEDUP UPSERT KEYS(ts, name);`

	resp, err := http.Get(URL + "/exec?query=" + url.QueryEscape(queryCreateTable))
	if resp.StatusCode > 299 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("error creating experiments table, status: %s, body: %s", resp.Status, string(body))
	}

	const queryInsertTable = `INSERT INTO experiments VALUES(0, '%s', true);`
	queryComplete := fmt.Sprintf(queryInsertTable, experimentName)
	resp, err = http.Get(URL + "/exec?query=" + url.QueryEscape(queryComplete))
	if resp.StatusCode > 299 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("error inserting experiment into table, status: %s, body: %s", resp.Status, string(body))
	}

	return err
}

func DeletePacketTable(URL string, experimentName string) error {
	const query = `DROP TABLE IF EXISTS %s;`

	queryComplete := fmt.Sprintf(query, GetTableName(experimentName))

	resp, err := http.Get(URL + "/exec?query=" + url.QueryEscape(queryComplete))
	if resp.StatusCode > 299 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("error dropping table, status: %s, body: %s", resp.Status, string(body))
	}

	return err
}

func GetTableName(experimentName string) string {
	return "packets_" + experimentName
}
