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

	centralFrequencyDownstreamDesc *prometheus.Desc
	powerDownstreamDesc            *prometheus.Desc
	snrDownstreamDesc              *prometheus.Desc
	lockedDownstreamDesc           *prometheus.Desc

	startFrequencyOfdmDownstreamDesc   *prometheus.Desc
	endFrequencyOfdmDownstreamDesc     *prometheus.Desc
	centralFrequencyOfdmDownstreamDesc *prometheus.Desc
	bandwidthOfdmDownstreamDesc        *prometheus.Desc
	powerOfdmDownstreamDesc            *prometheus.Desc
	snrOfdmDownstreamDesc              *prometheus.Desc
	lockedOfdmDownstreamDesc           *prometheus.Desc

	centralFrequencyUpstreamDesc *prometheus.Desc
	powerUpstreamDesc            *prometheus.Desc
	rangingStatusUpstreamDesc    *prometheus.Desc

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

	downstreamChannelLabels := []string{"id", "channel_id", "fft", "channel_type"}
	centralFrequencyDownstreamDesc = prometheus.NewDesc(prefix+"downstream_central_frequency_hertz", "Central frequency in hertz", downstreamChannelLabels, nil)
	powerDownstreamDesc = prometheus.NewDesc(prefix+"downstream_power_dBmV", "Power in dBmV", downstreamChannelLabels, nil)
	snrDownstreamDesc = prometheus.NewDesc(prefix+"downstream_snr_dB", "SNR in dB", downstreamChannelLabels, nil)
	lockedDownstreamDesc = prometheus.NewDesc(prefix+"downstream_locked_bool", "Locking status", downstreamChannelLabels, nil)

	ofdmDownstreamChannelLabels := []string{"id", "channel_id_ofdm", "fft", "channel_type"}
	startFrequencyOfdmDownstreamDesc = prometheus.NewDesc(prefix+"ofdm_downstream_start_frequency_hertz", "Start frequency", ofdmDownstreamChannelLabels, nil)
	endFrequencyOfdmDownstreamDesc = prometheus.NewDesc(prefix+"ofdm_downstream_end_frequency_hertz", "End frequency", ofdmDownstreamChannelLabels, nil)
	centralFrequencyOfdmDownstreamDesc = prometheus.NewDesc(prefix+"ofdm_downstream_central_frequency_hertz", "Central frequency", ofdmDownstreamChannelLabels, nil)
	bandwidthOfdmDownstreamDesc = prometheus.NewDesc(prefix+"ofdm_downstream_bandwidth_hertz", "Bandwidth", ofdmDownstreamChannelLabels, nil)
	powerOfdmDownstreamDesc = prometheus.NewDesc(prefix+"ofdm_downstream_power_dBmV", "Power", ofdmDownstreamChannelLabels, nil)
	snrOfdmDownstreamDesc = prometheus.NewDesc(prefix+"ofdm_downstream_snr_dB", "SNR", ofdmDownstreamChannelLabels, nil)
	lockedOfdmDownstreamDesc = prometheus.NewDesc(prefix+"ofdm_downstream_locked_bool", "Locking status", ofdmDownstreamChannelLabels, nil)

	upstreamLabels := []string{"id", "channel_id_up", "fft", "channel_type"}
	centralFrequencyUpstreamDesc = prometheus.NewDesc(prefix+"upstream_central_frequency_hertz", "Central frequency", upstreamLabels, nil)
	powerUpstreamDesc = prometheus.NewDesc(prefix+"upstream_power_dBmV", "Power", upstreamLabels, nil)
	rangingStatusUpstreamDesc = prometheus.NewDesc(prefix+"upstream_ranging_status_info", "Ranging status", append(upstreamLabels, "status"), nil)

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

	ch <- centralFrequencyDownstreamDesc
	ch <- powerDownstreamDesc
	ch <- snrDownstreamDesc
	ch <- snrDownstreamDesc

	ch <- startFrequencyOfdmDownstreamDesc
	ch <- endFrequencyOfdmDownstreamDesc
	ch <- centralFrequencyOfdmDownstreamDesc
	ch <- bandwidthOfdmDownstreamDesc
	ch <- powerOfdmDownstreamDesc
	ch <- snrOfdmDownstreamDesc
	ch <- lockedOfdmDownstreamDesc

	ch <- centralFrequencyUpstreamDesc
	ch <- powerUpstreamDesc
	ch <- rangingStatusUpstreamDesc

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
			ch <- prometheus.MustNewConstMetric(centralFrequencyDownstreamDesc, prometheus.GaugeValue, parse2float(downstreamChannel.CentralFrequency)*10e9, labels...)
			ch <- prometheus.MustNewConstMetric(powerDownstreamDesc, prometheus.GaugeValue, parse2float(downstreamChannel.Power), labels...)
			ch <- prometheus.MustNewConstMetric(snrDownstreamDesc, prometheus.GaugeValue, parse2float(downstreamChannel.Snr), labels...)
			ch <- prometheus.MustNewConstMetric(lockedDownstreamDesc, prometheus.GaugeValue, bool2float64(downstreamChannel.Locked == "Locked"), labels...)
		}
		for _, ofdmDownstreamChannel := range docsisStatusResponse.Data.OfdmDownstreamData {
			labels := []string{ofdmDownstreamChannel.Id, ofdmDownstreamChannel.ChannelIdOfdm, ofdmDownstreamChannel.FftOfdm, ofdmDownstreamChannel.ChannelType}
			ch <- prometheus.MustNewConstMetric(startFrequencyOfdmDownstreamDesc, prometheus.GaugeValue, parse2float(ofdmDownstreamChannel.StartFrequency)*10e9, labels...)
			ch <- prometheus.MustNewConstMetric(endFrequencyOfdmDownstreamDesc, prometheus.GaugeValue, parse2float(ofdmDownstreamChannel.EndFrequency)*10e9, labels...)
			ch <- prometheus.MustNewConstMetric(centralFrequencyOfdmDownstreamDesc, prometheus.GaugeValue, parse2float(ofdmDownstreamChannel.CentralFrequencyOfdm)*10e9, labels...)
			ch <- prometheus.MustNewConstMetric(bandwidthOfdmDownstreamDesc, prometheus.GaugeValue, parse2float(ofdmDownstreamChannel.Bandwidth)*10e9, labels...)
			ch <- prometheus.MustNewConstMetric(powerOfdmDownstreamDesc, prometheus.GaugeValue, parse2float(ofdmDownstreamChannel.PowerOfdm), labels...)
			ch <- prometheus.MustNewConstMetric(snrOfdmDownstreamDesc, prometheus.GaugeValue, parse2float(ofdmDownstreamChannel.SnrOfdm), labels...)
			ch <- prometheus.MustNewConstMetric(lockedOfdmDownstreamDesc, prometheus.GaugeValue, bool2float64(ofdmDownstreamChannel.LockedOfdm == "Locked"), labels...)
		}
		for _, upstreamChannel := range docsisStatusResponse.Data.Upstream {
			labels := []string{upstreamChannel.Id, upstreamChannel.ChannelIdUp, upstreamChannel.Fft, upstreamChannel.ChannelType}
			ch <- prometheus.MustNewConstMetric(centralFrequencyUpstreamDesc, prometheus.GaugeValue, parse2float(upstreamChannel.CentralFrequency)*10e9, labels...)
			ch <- prometheus.MustNewConstMetric(powerUpstreamDesc, prometheus.GaugeValue, parse2float(upstreamChannel.Power), labels...)
			ch <- prometheus.MustNewConstMetric(rangingStatusUpstreamDesc, prometheus.GaugeValue, 1, append(labels, upstreamChannel.RangingStatus)...)
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
