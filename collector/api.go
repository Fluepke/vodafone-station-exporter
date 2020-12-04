package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/prometheus/common/log"
	"golang.org/x/crypto/pbkdf2"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type VodafoneStation struct {
	URL      string
	Password string
	client   *http.Client
}

type LoginResponseSalts struct {
	Error     string `json:"error"`
	Salt      string `json:"salt"`
	SaltWebUI string `json:"saltwebui"`
}

type LoginResponse struct {
	Error   string             `json:"error"`
	Message string             `json:"message"`
	Data    *LoginResponseData `json:"data"`
}

type LoginResponseData struct {
	Interface       string `json:"intf"`
	User            string `json:"user"`
	Uid             string `json:"uid"`
	DefaultPassword string `json:"Dpd"`
	RemoteAddress   string `json:"remoteAddr"`
	UserAgent       string `json:"userAgent"`
	HttpReferer     string `json:"httpReferer"`
}

type LogoutResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

type DocsisStatusResponse struct {
	Error   string            `json:"error"`
	Message string            `json:"message"`
	Data    *DocsisStatusData `json:"data"`
}

type DocsisStatusData struct {
	OfdmDownstreamData []*OfdmDownstreamData      `json:"ofdm_downstream"`
	Downstream         []*DocsisDownstreamChannel `json:"downstream"`
	Upstream           []*DocsisUpstreamChannel   `json:"upstream"`
}

type OfdmDownstreamData struct {
	Id                   string `json:"__id"`
	ChannelIdOfdm        string `json:"channelid_ofdm"`
	StartFrequency       string `json:"start_frequency"`
	EndFrequency         string `json:"end_frequency"`
	CentralFrequencyOfdm string `json:"CentralFrequency_ofdm"`
	Bandwidth            string `json:"bandwidth"`
	PowerOfdm            string `json:"power_ofdm"`
	SnrOfdm              string `json:"SNR_ofdm"`
	FftOfdm              string `json:"FFT_ofdm"`
	LockedOfdm           string `json:"locked_ofdm"`
	ChannelType          string `json:"ChannelType"`
}

type DocsisDownstreamChannel struct {
	Id               string `json:"__id"`
	ChannelId        string `json:"channelid"`
	CentralFrequency string `json:"CentralFrequency"`
	Power            string `json:"power"`
	Snr              string `json:"SNR"`
	Fft              string `json:"FFT"`
	Locked           string `json:"locked"`
	ChannelType      string `json:"ChannelType"`
}

type DocsisUpstreamChannel struct {
	Id               string `json:"__id"`
	ChannelIdUp      string `json:"channelidup"`
	CentralFrequency string `json:"CentralFrequency"`
	Power            string `json:"power"`
	ChannelType      string `json:"ChannelType"`
	Fft              string `json:"FFT"`
	RangingStatus    string `json:"RangingStatus"`
}

type StationStatusReponse struct {
	Error   string             `json:"error"`
	Message string             `json:"message"`
	Data    *StationStatusData `json:"data"`
}

type StationStatusData struct {
	DateAndTime     string   `json:"dateandtime"`
	FirewallStatus  string   `json:"firewallstatus"`
	LanIpv4         string   `json:"lanipv4"`
	LanMode         string   `json:"LanMode"`
	LanGateway      string   `json:"langateway"`
	LanDHCPstatus   string   `json:"lanDHCPstatus"`
	LanMAC          string   `json:"lanMAC"`
	LanPortStatus4  string   `json:"lanportstatus_4"`
	LanPortSpeed4   string   `json:"lanportspeed_4"`
	LanPortStatus1  string   `json:"lanportstatus_1"`
	LanPortSpeed1   string   `json:"lanportspeed_1"`
	LanPortStatus2  string   `json:"lanportstatus_2"`
	LanPortSpeed2   string   `json:"lanportspeed_2"`
	LanPortStatus3  string   `json:"lanportstatus_3"`
	LanPortSpeed3   string   `json:"lanportspeed_3"`
	WifiStatus      string   `json:"wifistatus"`
	Channel         string   `json:"channel"`
	Bandwidth       string   `json:"bandwidth"`
	MaxSpeed        string   `json:"maxspeed"`
	Ssid            string   `json:"ssid"`
	MacAddress      string   `json:"macaddress"`
	Security        string   `json:"security"`
	WifiStatus5     string   `json:"wifistatus_5"`
	Channel5        string   `json:"channel_5"`
	Bandwidth5      string   `json:"bandwidth_5"`
	MaxSpeed5       string   `json:"maxspeed_5"`
	Ssid5           string   `json:"ssid_5"`
	MacAddress5     string   `json:"macaddress_5"`
	Security5       string   `json:"security_5"`
	DnsEntries      string   `json:"DnsEntries"`
	AFTR            string   `json:"AFTR"`
	Serialnumber    string   `json:"serialnumber"`
	FirmwareVersion string   `json:"firmwareversion"`
	HardwareType    string   `json:"hardwaretype"`
	Uptime          string   `json:"uptime"`
	InternetIpv4    string   `json:"internetipv4"`
	DnsTbl          []string `json:"Dns_Tbl"`
	DelegatedPrefix string   `json:"DelegatedPrefix"`
	DNSTblRT        []string `json:"DNSTblRT"`
	IPAddressRT     []string `json:"IPAddressRT"`
	IpPrefixClass   string   `json:"IpPrefixClass"`
}

type CallLog struct {
	Lines map[string]*PhoneNumberCallLog
	Line0 *PhoneNumberCallLog `json:"0"`
	Line1 *PhoneNumberCallLog `json:"1"`
	Token string              `json:"token"`
}

type PhoneNumberCallLog struct {
	Error   string       `json:"error"`
	Message string       `json:"message"`
	Data    *CallLogData `json:"data"`
}

type CallLogData struct {
	Entries []*CallLogEntry `json:"CallTbl"`
}

type CallLogEntry struct {
	Id             string `json:"__id"`
	EndTime        string `json:"endTime"`
	StartTime      string `json:"startTime"`
	ExternalNumber string `json:"externalNumber"`
	Direction      string `json:"Direction"`
	Type           string `json:"type"`
}

func NewVodafoneStation(stationUrl, password string) *VodafoneStation {
	cookieJar, err := cookiejar.New(nil)
	parsedUrl, err := url.Parse(stationUrl)
	cookieJar.SetCookies(parsedUrl, []*http.Cookie{
		&http.Cookie{
			Name:  "Cwd",
			Value: "No",
		},
	})
	if err != nil {
		panic(err)
	}
	return &VodafoneStation{
		URL:      stationUrl,
		Password: password,
		client: &http.Client{
			Jar:     cookieJar,
			Timeout: time.Second * 20, // getting DOCSIS status can be slow!
		},
	}
}

func (v *VodafoneStation) Login() (*LoginResponse, error) {
	_, err := v.doRequest("GET", v.URL, "")
	if err != nil {
		return nil, err
	}
	loginResponseSalts, err := v.getLoginSalts()
	if err != nil {
		return nil, err
	}
	derivedPassword := GetLoginPassword(v.Password, loginResponseSalts.Salt, loginResponseSalts.SaltWebUI)
	responseBody, err := v.doRequest("POST", v.URL+"/api/v1/session/login", "username=admin&password="+derivedPassword)
	if err != nil {
		return nil, err
	}
	loginResponse := &LoginResponse{}
	err = json.Unmarshal(responseBody, loginResponse)
	if loginResponse.Error != "ok" {
		return nil, fmt.Errorf("Got non error=ok message from vodafone station")
	}
	return loginResponse, nil
}

func (v *VodafoneStation) Logout() (*LogoutResponse, error) {
	responseBody, err := v.doRequest("POST", v.URL+"/api/v1/session/logout", "")
	if err != nil {
		return nil, err
	}
	logoutResponse := &LogoutResponse{}
	err = json.Unmarshal(responseBody, logoutResponse)
	if err != nil {
		return nil, err
	}
	if logoutResponse.Error != "ok" {
		return nil, fmt.Errorf("Got non error=ok message from vodafone station")
	}
	return logoutResponse, nil
}

func (v *VodafoneStation) GetDocsisStatus() (*DocsisStatusResponse, error) {
	responseBody, err := v.doRequest("GET", v.URL+"/api/v1/sta_docsis_status?_="+strconv.FormatInt(makeTimestamp(), 10), "")
	if err != nil {
		return nil, err
	}
	docsisStatusResponse := &DocsisStatusResponse{}
	return docsisStatusResponse, json.Unmarshal(responseBody, docsisStatusResponse)
}

func (v *VodafoneStation) GetStationStatus() (*StationStatusReponse, error) {
	responseBody, err := v.doRequest("GET", v.URL+"/api/v1/sta_status?_="+strconv.FormatInt(makeTimestamp(), 10), "")
	if err != nil {
		return nil, err
	}
	stationStatusReponse := &StationStatusReponse{}
	return stationStatusReponse, json.Unmarshal(responseBody, stationStatusReponse)
}

func (v *VodafoneStation) GetCallLog() (*CallLog, error) {
	responseBody, err := v.doRequest("GET", v.URL+"/api/v1/phone_calllog/1,2/CallTbl?_="+strconv.FormatInt(makeTimestamp(), 10), "")
	if err != nil {
		return nil, err
	}
	callLog := &CallLog{}
	err = json.Unmarshal(responseBody, callLog)
	if err != nil {
		return nil, err
	}
	callLog.Lines = map[string]*PhoneNumberCallLog{"0": callLog.Line0, "1": callLog.Line1}
	return callLog, nil
}

func makeTimestamp() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}

func (v *VodafoneStation) getLoginSalts() (*LoginResponseSalts, error) {
	responseBody, err := v.doRequest("POST", v.URL+"/api/v1/session/login", "username=admin&password=seeksalthash")
	if err != nil {
		return nil, err
	}
	loginResponseSalts := &LoginResponseSalts{}
	err = json.Unmarshal(responseBody, loginResponseSalts)
	if err != nil {
		return nil, err
	}
	if loginResponseSalts.Error != "ok" {
		return nil, fmt.Errorf("Got non error=ok message from vodafone station")
	}
	return loginResponseSalts, nil
}

func (v *VodafoneStation) doRequest(method, url, body string) ([]byte, error) {
	logger := log.With("method", method).With("url", url)
	logger.Debug("Performing request")
	requestBody := strings.NewReader(body)
	request, err := http.NewRequest(method, url, requestBody)
	if err != nil {
		logger.With("error", err.Error).Error("Creating request failed")
		return nil, err
	}
	if method == "POST" {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	}
	request.Header.Set("Referer", "http://192.168.100.1")
	request.Header.Set("X-Requested-With", "XMLHttpRequest")
	response, err := v.client.Do(request)
	if err != nil {
		logger.With("error", err.Error).Error("Performing request failed")
		return nil, err
	}
	if response.Body != nil {
		defer response.Body.Close()
	}
	return ioutil.ReadAll(response.Body)
}

// GetLoginPassword derives the password using the given salts
func GetLoginPassword(password, salt, saltWebUI string) string {
	return DoPbkdf2NotCoded(DoPbkdf2NotCoded(password, salt), saltWebUI)
}

// Equivalent to the JS doPbkdf2NotCoded (see README.md)
func DoPbkdf2NotCoded(key, salt string) string {
	temp := pbkdf2.Key([]byte(key), []byte(salt), 0x3e8, 0x80, sha256.New)
	return hex.EncodeToString(temp[:16])
}
