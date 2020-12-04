package collector

import (
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
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

	firewallStatusDesc  *prometheus.Desc
	lanIPv4Desc         *prometheus.Desc
	lanModeDesc         *prometheus.Desc
	lanGatewayDesc      *prometheus.Desc
	lanDhcpEnabledDesc  *prometheus.Desc
	lanMacDesc          *prometheus.Desc
	lanPortStatusDesc   *prometheus.Desc
	lanPortSpeedDesc    *prometheus.Desc
	wlanEnabledDesc     *prometheus.Desc
	wlanChannelDesc     *prometheus.Desc
	wlanBandwidthDesc   *prometheus.Desc
	wlanMaxSpeedDesc    *prometheus.Desc
	wlanSsidDesc        *prometheus.Desc
	wlanMacAddressDesc  *prometheus.Desc
	wlanSecurityDesc    *prometheus.Desc
	dnsEntriesCountDesc *prometheus.Desc
	aftrDesc            *prometheus.Desc
	seralnumberDesc     *prometheus.Desc
	firmwareVersionDesc *prometheus.Desc
	hardwareTypeDesc    *prometheus.Desc
	uptimeDesc          *prometheus.Desc
	internetIPv4Desc    *prometheus.Desc
	delegatedPrefixDesc *prometheus.Desc
	ipAddressRTDesc     *prometheus.Desc
	ipPrefixClassDesc   *prometheus.Desc

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

	firewallStatusDesc = prometheus.NewDesc(prefix+"firewall_status_info", "Firewall status", []string{"firewall_status"}, nil)
	lanIPv4Desc = prometheus.NewDesc(prefix+"lan_ip4_info", "LAN IPv4 info", []string{"lan_ip4"}, nil)
	lanModeDesc = prometheus.NewDesc(prefix+"lan_mode_info", "LAN mode info", []string{"mode"}, nil)
	lanGatewayDesc = prometheus.NewDesc(prefix+"lan_gateway_info", "LAN gateway info", []string{"lan_gateway"}, nil)
	lanDhcpEnabledDesc = prometheus.NewDesc(prefix+"lan_dhcp_enabled_bool", "LAN DHCP enabled info", nil, nil)
	lanMacDesc = prometheus.NewDesc(prefix+"lan_mac_address_info", "LAN MAC address", []string{"mac_address"}, nil)
	lanPortStatusDesc = prometheus.NewDesc(prefix+"lan_port_up_bool", "LAN port status", []string{"port"}, nil)
	lanPortSpeedDesc = prometheus.NewDesc(prefix+"lan_port_speed_bits_per_second", "LAN port speed in bits/second", []string{"port"}, nil)
	wlanEnabledDesc = prometheus.NewDesc(prefix+"wlan_enabled_bool", "WLAN enabled info", []string{"frequency"}, nil)
	wlanChannelDesc = prometheus.NewDesc(prefix+"wlan_channel", "WLAN channel", []string{"frequency"}, nil)
	wlanBandwidthDesc = prometheus.NewDesc(prefix+"wlan_bandwidth_hertz", "WLAN bandwidth in Hertz", []string{"frequency"}, nil)
	wlanMaxSpeedDesc = prometheus.NewDesc(prefix+"wlan_max_speed_bits_per_second", "Max WLAN speed in bits/seconds", []string{"frequency"}, nil)
	wlanSsidDesc = prometheus.NewDesc(prefix+"wlan_ssid_info", "SSID information", []string{"frequency", "ssid"}, nil)
	wlanMacAddressDesc = prometheus.NewDesc(prefix+"wlan_mac_address_info", "WLAN MAC address", []string{"frequency", "mac_address"}, nil)
	wlanSecurityDesc = prometheus.NewDesc(prefix+"wlan_security_info", "WLAN security", []string{"frequency", "security_info"}, nil)
	dnsEntriesCountDesc = prometheus.NewDesc(prefix+"dns_entries_count", "DNS Entries count", nil, nil)
	aftrDesc = prometheus.NewDesc(prefix+"aftr_info", "AFTR gateway information", []string{"aftr"}, nil)
	seralnumberDesc = prometheus.NewDesc(prefix+"serialnumber_info", "Serial number information", []string{"serial_number"}, nil)
	firmwareVersionDesc = prometheus.NewDesc(prefix+"firmwareversion_info", "Firmware vresion information", []string{"firmware_version"}, nil)
	hardwareTypeDesc = prometheus.NewDesc(prefix+"hardware_type_info", "Hardware type information", []string{"hardware_type"}, nil)
	uptimeDesc = prometheus.NewDesc(prefix+"uptime_seconds", "Uptime in seconds", nil, nil)
	internetIPv4Desc = prometheus.NewDesc(prefix+"internet_ip4_info", "Internet IPv4", []string{"ip4"}, nil)
	delegatedPrefixDesc = prometheus.NewDesc(prefix+"delegated_prefix_info", "Delegated prefix information", []string{"prefix"}, nil)
	ipAddressRTDesc = prometheus.NewDesc(prefix+"ip_address_rt_info", "IP address RT", []string{"ip"}, nil)
	ipPrefixClassDesc = prometheus.NewDesc(prefix+"ip_prefix_class_info", "IP prefix class info", []string{"prefix_class"}, nil)

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

	ch <- firewallStatusDesc
	ch <- lanIPv4Desc
	ch <- lanModeDesc
	ch <- lanGatewayDesc
	ch <- lanDhcpEnabledDesc
	ch <- lanMacDesc
	ch <- lanPortStatusDesc
	ch <- lanPortSpeedDesc
	ch <- wlanEnabledDesc
	ch <- wlanChannelDesc
	ch <- wlanBandwidthDesc
	ch <- wlanMaxSpeedDesc
	ch <- wlanSsidDesc
	ch <- wlanMacAddressDesc
	ch <- wlanSecurityDesc
	ch <- dnsEntriesCountDesc
	ch <- aftrDesc
	ch <- seralnumberDesc
	ch <- firmwareVersionDesc
	ch <- hardwareTypeDesc
	ch <- uptimeDesc
	ch <- internetIPv4Desc
	ch <- delegatedPrefixDesc
	ch <- ipAddressRTDesc
	ch <- ipPrefixClassDesc

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
	if err != nil {
		fmt.Println(err.Error())
	}
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

	stationStatusResponse, err := c.Station.GetStationStatus()
	if err != nil {
		log.With("error", err.Error()).Error("Failed to get station status")
	} else if stationStatusResponse.Data != nil {
		ch <- prometheus.MustNewConstMetric(firewallStatusDesc, prometheus.GaugeValue, 1, stationStatusResponse.Data.FirewallStatus)
		ch <- prometheus.MustNewConstMetric(lanIPv4Desc, prometheus.GaugeValue, 1, stationStatusResponse.Data.LanIpv4)
		ch <- prometheus.MustNewConstMetric(lanModeDesc, prometheus.GaugeValue, 1, stationStatusResponse.Data.LanMode)
		ch <- prometheus.MustNewConstMetric(lanGatewayDesc, prometheus.GaugeValue, 1, stationStatusResponse.Data.LanGateway)
		ch <- prometheus.MustNewConstMetric(lanDhcpEnabledDesc, prometheus.GaugeValue, bool2float64(stationStatusResponse.Data.LanDHCPstatus == "true"))
		ch <- prometheus.MustNewConstMetric(lanMacDesc, prometheus.GaugeValue, 1, stationStatusResponse.Data.LanMAC)
		ch <- prometheus.MustNewConstMetric(lanPortStatusDesc, prometheus.GaugeValue, bool2float64(stationStatusResponse.Data.LanPortStatus1 == "Up"), "1")
		ch <- prometheus.MustNewConstMetric(lanPortSpeedDesc, prometheus.GaugeValue, parse2float(stationStatusResponse.Data.LanPortSpeed1), "1")
		ch <- prometheus.MustNewConstMetric(lanPortStatusDesc, prometheus.GaugeValue, bool2float64(stationStatusResponse.Data.LanPortStatus2 == "Up"), "2")
		ch <- prometheus.MustNewConstMetric(lanPortSpeedDesc, prometheus.GaugeValue, parse2float(stationStatusResponse.Data.LanPortSpeed2), "2")
		ch <- prometheus.MustNewConstMetric(lanPortStatusDesc, prometheus.GaugeValue, bool2float64(stationStatusResponse.Data.LanPortStatus3 == "Up"), "3")
		ch <- prometheus.MustNewConstMetric(lanPortSpeedDesc, prometheus.GaugeValue, parse2float(stationStatusResponse.Data.LanPortSpeed3), "3")
		ch <- prometheus.MustNewConstMetric(lanPortStatusDesc, prometheus.GaugeValue, bool2float64(stationStatusResponse.Data.LanPortStatus4 == "Up"), "4")
		ch <- prometheus.MustNewConstMetric(lanPortSpeedDesc, prometheus.GaugeValue, parse2float(stationStatusResponse.Data.LanPortSpeed4), "4")
		ch <- prometheus.MustNewConstMetric(wlanEnabledDesc, prometheus.GaugeValue, bool2float64(stationStatusResponse.Data.WifiStatus == "true"), "2.4 GHz")
		ch <- prometheus.MustNewConstMetric(wlanChannelDesc, prometheus.GaugeValue, parse2float(stationStatusResponse.Data.Channel), "2.4 GHz")
		ch <- prometheus.MustNewConstMetric(wlanBandwidthDesc, prometheus.GaugeValue, parse2float(stationStatusResponse.Data.Bandwidth)*10e9, "2.4 GHz")
		ch <- prometheus.MustNewConstMetric(wlanMaxSpeedDesc, prometheus.GaugeValue, parse2float(stationStatusResponse.Data.MaxSpeed)*10e8, "2.4 GHz")
		ch <- prometheus.MustNewConstMetric(wlanSsidDesc, prometheus.GaugeValue, 1, "2.4 GHz", stationStatusResponse.Data.Ssid)
		ch <- prometheus.MustNewConstMetric(wlanMacAddressDesc, prometheus.GaugeValue, 1, "2.4 GHz", stationStatusResponse.Data.MacAddress)
		ch <- prometheus.MustNewConstMetric(wlanSecurityDesc, prometheus.GaugeValue, 1, "2.4 GHz", stationStatusResponse.Data.Security)
		ch <- prometheus.MustNewConstMetric(wlanEnabledDesc, prometheus.GaugeValue, bool2float64(stationStatusResponse.Data.WifiStatus5 == "true"), "5 GHz")
		ch <- prometheus.MustNewConstMetric(wlanChannelDesc, prometheus.GaugeValue, parse2float(stationStatusResponse.Data.Channel5), "5 GHz")
		ch <- prometheus.MustNewConstMetric(wlanBandwidthDesc, prometheus.GaugeValue, parse2float(stationStatusResponse.Data.Bandwidth5)*10e9, "5 GHz")
		ch <- prometheus.MustNewConstMetric(wlanMaxSpeedDesc, prometheus.GaugeValue, parse2float(stationStatusResponse.Data.MaxSpeed5)*10e8, "5 GHz")
		ch <- prometheus.MustNewConstMetric(wlanSsidDesc, prometheus.GaugeValue, 1, "5 GHz", stationStatusResponse.Data.Ssid5)
		ch <- prometheus.MustNewConstMetric(wlanMacAddressDesc, prometheus.GaugeValue, 1, "5 GHz", stationStatusResponse.Data.MacAddress5)
		ch <- prometheus.MustNewConstMetric(wlanSecurityDesc, prometheus.GaugeValue, 1, "5 GHz", stationStatusResponse.Data.Security5)
		ch <- prometheus.MustNewConstMetric(dnsEntriesCountDesc, prometheus.GaugeValue, parse2float(stationStatusResponse.Data.DnsEntries))
		ch <- prometheus.MustNewConstMetric(aftrDesc, prometheus.GaugeValue, 1, stationStatusResponse.Data.AFTR)
		ch <- prometheus.MustNewConstMetric(seralnumberDesc, prometheus.GaugeValue, 1, stationStatusResponse.Data.Serialnumber)
		ch <- prometheus.MustNewConstMetric(firmwareVersionDesc, prometheus.GaugeValue, 1, stationStatusResponse.Data.FirmwareVersion)
		ch <- prometheus.MustNewConstMetric(hardwareTypeDesc, prometheus.GaugeValue, 1, stationStatusResponse.Data.HardwareType)
		ch <- prometheus.MustNewConstMetric(uptimeDesc, prometheus.GaugeValue, parse2float(stationStatusResponse.Data.Uptime))
		ch <- prometheus.MustNewConstMetric(internetIPv4Desc, prometheus.GaugeValue, 1, stationStatusResponse.Data.InternetIpv4)
		ch <- prometheus.MustNewConstMetric(delegatedPrefixDesc, prometheus.GaugeValue, 1, stationStatusResponse.Data.DelegatedPrefix)
		for _, ipAddressRT := range stationStatusResponse.Data.IPAddressRT {
			ch <- prometheus.MustNewConstMetric(ipAddressRTDesc, prometheus.GaugeValue, 1, ipAddressRT)
		}
		ch <- prometheus.MustNewConstMetric(ipPrefixClassDesc, prometheus.GaugeValue, 1, stationStatusResponse.Data.IpPrefixClass)
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
