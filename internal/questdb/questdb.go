package questdb

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
			stream_index INT,
			ip_src_netify_app_tag SYMBOL,
			ip_src_netify_app_category_tag SYMBOL,
			ip_src_netify_geo_continent SYMBOL,
			ip_src_netify_geo_country SYMBOL,
			ip_src_netify_geo_city SYMBOL,
			ip_src_netify_geo_lon DOUBLE,
			ip_src_netify_geo_lat DOUBLE,
			ip_dst_netify_app_tag SYMBOL,
			ip_dst_netify_app_category_tag SYMBOL,
			ip_dst_netify_geo_continent SYMBOL,
			ip_dst_netify_geo_country SYMBOL,
			ip_dst_netify_geo_city SYMBOL,
			ip_dst_netify_geo_lon DOUBLE,
			ip_dst_netify_geo_lat DOUBLE,
			tls_sni_netify_app_tag SYMBOL,
			tls_sni_netify_app_category_tag SYMBOL,
			tls_sni_netify_domain_tag SYMBOL
		                        
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
