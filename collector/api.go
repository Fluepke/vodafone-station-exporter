package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"
)

type VodafoneStation struct {
	URL      string
	Password string
	client   *http.Client
}

type LoginResponse struct {
	Error     string `json:"error"`
	Salt      string `json:"salt"`
	SaltWebUI string `json:"saltwebui"`
}

func NewVodafoneStation(url, password string) *VodafoneStation {
	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}
	return &VodafoneStation{
		URL:      url,
		Password: password,
		client: &http.Client{
			Jar:     cookieJar,
			Timeout: time.Second * 2,
		},
	}
}

func (v *VodafoneStation) getLoginSalts() (*LoginResponse, error) {
	requestBody := strings.NewReader("username=admin&password=seeksalthash")
	response, err := v.client.Post(v.URL+"/api/v1/session/login", "application/x-www-form-urlencoded", requestBody)
	if err != nil {
		return nil, err
	}
	if response.Body != nil {
		defer response.Body.Close()
	}
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	loginResponse := &LoginResponse{}
	err = json.Unmarshal(responseBody, loginResponse)
	if err != nil {
		return nil, err
	}
	if loginResponse.Error != "ok" {
		return nil, fmt.Errorf("Got non error=ok message from vodafone station")
	}
	return loginResponse, nil
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
