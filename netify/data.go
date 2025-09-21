package netify

type ApplicationProperty struct {
	Id          int            `json:"id"`
	Tag         string         `json:"tag"`
	Label       string         `json:"label"`
	FullLabel   string         `json:"full_label"`
	Description string         `json:"description"`
	HomePage    HomePageObject `json:"home_page"`
	Category    CategoryObject `json:"category"`
	Active      bool           `json:"active"`
	IconFields
}

type ASNProperty struct {
	Id     int    `json:"id"`
	Tag    string `json:"tag"`
	Label  string `json:"label"`
	Entity struct {
		Id          int            `json:"id"`
		Tag         string         `json:"tag"`
		Label       string         `json:"label"`
		Description string         `json:"description"`
		HomePage    HomePageObject `json:"home_page"`
		Category    CategoryObject `json:"category"`
		IconFields
	} `json:"entity"`
}

type GeolocationProperty struct {
	Continent struct {
		Code  string `json:"code"`
		Label string `json:"label"`
	} `json:"continent"`
	Country struct {
		Code  string `json:"code"`
		Label string `json:"label"`
	} `json:"country"`
	Region struct {
		GeonameId int    `json:"geoname_id"`
		Label     string `json:"label"`
	} `json:"region"`
	City struct {
		GeonameId int    `json:"geoname_id"`
		Label     string `json:"label"`
	} `json:"city"`
	Coordinates struct {
		Scale     string `json:"scale"`
		Latitude  string `json:"latitude"`
		Longitude string `json:"longitude"`
	}
}

type NetworkProperty struct {
	Id          int            `json:"id"`
	Tag         string         `json:"tag"`
	Label       string         `json:"label"`
	Description string         `json:"description"`
	HomePage    HomePageObject `json:"home_page"`
	Category    CategoryObject `json:"category"`
	IconFields
}

type PopProperty struct {
	Id          int    `json:"id"`
	Tag         string `json:"tag"`
	Label       string `json:"label"`
	InternalTag string `json:"internal_tag"`
	IsAnycast   bool   `json:"is_anycast"`
}

type ReverseDNSProperty struct {
	Hostname    string              `json:"hostname"`
	Application ApplicationProperty `json:"application"`
}

type TLSCertificateProperty struct {
	CommonName  string              `json:"common_name"`
	Application ApplicationProperty `json:"application"`
}

type HomePageObject struct {
	Url  string `json:"url"`
	Text string `json:"text"`
}

type CategoryObject struct {
	Id    int    `json:"id"`
	Tag   string `json:"tag"`
	Label string `json:"label"`
}

type IconFields struct {
	Favicon       string `json:"favicon"`
	Icon          string `json:"icon"`
	Logo          string `json:"logo"`
	FaviconSource string `json:"favicon_source"`
	IconSource    string `json:"icon_source"`
	LogoSource    string `json:"logo_source"`
}

// PlatformProperty Platform property is the same as Application property
type PlatformProperty ApplicationProperty

// IPData Only the desired data is considered, there could be more data like the VPN, TOR etc...
// https://www.netify.ai/documentation/data-feeds/v2/objects/ip
type IPData struct {
	StatusCode    int    `json:"status_code"`
	StatusMessage string `json:"status_message"`
	Data          struct {
		Address         string                  `json:"address"`
		Version         string                  `json:"version"`
		SharedScore     int                     `json:"shared_score"`
		IsBogon         bool                    `json:"is_bogon"`
		IsAnycast       bool                    `json:"is_anycast"`
		AppCIDR         string                  `json:"app_cidr"`
		RDNS            ReverseDNSProperty      `json:"rdns"`
		TlsCertificate  *TLSCertificateProperty `json:"tls_certificate"`
		Platform        *PlatformProperty       `json:"platform"`
		Network         *NetworkProperty        `json:"network"`
		Pop             *PopProperty            `json:"pop"`
		AsnRoute        string                  `json:"asn_route"`
		Asn             *ASNProperty            `json:"asn"`
		Geolocation     *GeolocationProperty    `json:"geolocation"`
		ApplicationList []ApplicationProperty   `json:"application_list"`
		Hostnames       []string                `json:"hostnames"`
	} `json:"data"`
}

type HostnameData struct {
	StatusCode    int    `json:"status_code"`
	StatusMessage string `json:"status_message"`
	Data          struct {
		Hostname string `json:"hostname"`
		Domain   *struct {
			Id       int            `json:"id"`
			Label    string         `json:"label"`
			Category CategoryObject `json:"category"`
		} `json:"domain"`

		Application ApplicationProperty `json:"application"`
		Platform    *PlatformProperty   `json:"platform"`
		Network     *NetworkProperty    `json:"network"`
		ASN         *ASNProperty        `json:"asn"`
		IPs         []string            `json:"ips"`
	}
}
