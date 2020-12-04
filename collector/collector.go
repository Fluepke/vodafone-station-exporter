package collector

import (
	"github.com/prometheus/client_golang/prometheus"
	"regexp"
	"strconv"
)

type Collector struct {
	Station *VodafoneStation
}

var (
	loginSuccessDesc    *prometheus.Desc
	loginMessageDesc    *prometheus.Desc
	userDesc            *prometheus.Desc
	uidDesc             *prometheus.Desc
	defaultPasswordDesc *prometheus.Desc

	centralFrequencyDesc *prometheus.Desc
	powerDesc            *prometheus.Desc
	snrDesc              *prometheus.Desc
	lockedDesc           *prometheus.Desc

	logoutSuccessDesc *prometheus.Desc
	logoutMessageDesc *prometheus.Desc
)

const prefix = "vodafone_station_"

func init() {
	loginSuccessDesc = prometheus.NewDesc(prefix+"login_success_bool", "1 if the login was successfull", nil, nil)
	loginMessageDesc = prometheus.NewDesc(prefix+"login_message_info", "Login message returned by the web interface", []string{"message"}, nil)
	userDesc = prometheus.NewDesc(prefix+"user_info", "User name as returned by the web interface", []string{"username"}, nil)
	uidDesc = prometheus.NewDesc(prefix+"uid_info", "User id as returned by the web interface", []string{"uid"}, nil)
	defaultPasswordDesc = prometheus.NewDesc(prefix+"default_password_bool", "1 if the default password is in use", nil, nil)

	channelLabels := []string{"id", "channel_id", "fft", "channel_type"}
	centralFrequencyDesc = prometheus.NewDesc(prefix+"central_frequency_hertz", "Central frequency in hertz", channelLabels, nil)
	powerDesc = prometheus.NewDesc(prefix+"power_dBmV", "Power in dBmV", channelLabels, nil)
	snrDesc = prometheus.NewDesc(prefix+"snr_dB", "SNR in dB", channelLabels, nil)
	lockedDesc = prometheus.NewDesc(prefix+"locked_bool", "Locking status", channelLabels, nil)

	logoutSuccessDesc = prometheus.NewDesc(prefix+"logout_success_bool", "1 if the logout was successfull", nil, nil)
	logoutMessageDesc = prometheus.NewDesc(prefix+"logout_message_info", "Logout message returned by the web interface", []string{"message"}, nil)
}

// Describe implements prometheus.Collector interface's Describe function
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- loginSuccessDesc
	ch <- loginMessageDesc
	ch <- userDesc
	ch <- uidDesc
	ch <- defaultPasswordDesc
	ch <- centralFrequencyDesc
	ch <- powerDesc
	ch <- snrDesc
	ch <- snrDesc
	ch <- logoutSuccessDesc
	ch <- logoutMessageDesc
}

// Collect implements prometheus.Collector interface's Collect function
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	loginresponse, err := c.Station.Login()
	if loginresponse != nil {
		ch <- prometheus.MustNewConstMetric(loginMessageDesc, prometheus.GaugeValue, 1, loginresponse.Message)
	}
	if err != nil {
		ch <- prometheus.MustNewConstMetric(loginSuccessDesc, prometheus.GaugeValue, 0)
		ch <- prometheus.MustNewConstMetric(logoutSuccessDesc, prometheus.GaugeValue, 0)
		return
	}
	ch <- prometheus.MustNewConstMetric(loginSuccessDesc, prometheus.GaugeValue, 1)
	ch <- prometheus.MustNewConstMetric(userDesc, prometheus.GaugeValue, 1, loginresponse.Data.User)
	ch <- prometheus.MustNewConstMetric(uidDesc, prometheus.GaugeValue, 1, loginresponse.Data.Uid)
	ch <- prometheus.MustNewConstMetric(defaultPasswordDesc, prometheus.GaugeValue, bool2float64(loginresponse.Data.DefaultPassword == "Yes"))

	docsisStatusResponse, err := c.Station.GetDocsisStatus()
	if err == nil && docsisStatusResponse.Data != nil {
		for _, downstreamChannel := range docsisStatusResponse.Data.Downstream {
			labels := []string{downstreamChannel.Id, downstreamChannel.ChannelId, downstreamChannel.Fft, downstreamChannel.ChannelType}
			ch <- prometheus.MustNewConstMetric(centralFrequencyDesc, prometheus.GaugeValue, parse2float(downstreamChannel.CentralFrequency), labels...)
			ch <- prometheus.MustNewConstMetric(powerDesc, prometheus.GaugeValue, parse2float(downstreamChannel.Power), labels...)
			ch <- prometheus.MustNewConstMetric(snrDesc, prometheus.GaugeValue, parse2float(downstreamChannel.Snr), labels...)
			ch <- prometheus.MustNewConstMetric(lockedDesc, prometheus.GaugeValue, bool2float64(downstreamChannel.Locked == "Locked"), labels...)
		}
	}

	logoutresponse, err := c.Station.Logout()
	if logoutresponse != nil {
		ch <- prometheus.MustNewConstMetric(logoutMessageDesc, prometheus.GaugeValue, 1, logoutresponse.Message)
	}
	if err != nil {
		ch <- prometheus.MustNewConstMetric(logoutSuccessDesc, prometheus.GaugeValue, 0)
	}
	ch <- prometheus.MustNewConstMetric(logoutSuccessDesc, prometheus.GaugeValue, 1)
}

func parse2float(str string) float64 {
	reg := regexp.MustCompile(`[^\.0-9]+`)
	processedString := reg.ReplaceAllString(str, "")
	value, err := strconv.ParseFloat(processedString, 64)
	if err != nil {
		return 0
	}
	return value
}

func bool2float64(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
