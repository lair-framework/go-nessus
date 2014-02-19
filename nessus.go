/* Parses Nessus XML data into a similary formed struct */

package gonessus

import (
	"encoding/xml"
)

type NessusData struct {
	Report Report `xml:"Report"`
}

type Report struct {
	Name       string       `xml:"name,attr"`
	ReportHost []ReportHost `xml:"ReportHost"`
}

type ReportHost struct {
	Name           string         `xml:"name,attr"`
	HostProperties HostProperties `xml:"HostProperties"`
	ReportItem     []ReportItem   `xml:"ReportItem"`
}

type HostProperties struct {
	Tags []Tag `xml:"tag"`
}

type Tag struct {
	Name string `xml:"name,attr"`
	Data string `xml:",chardata"`
}

type ReportItem struct {
	Port                       string   `xml:"port,attr"`
	SvcName                    string   `xml:"svc_name,attr"`
	Protocol                   string   `xml:"protocol,attr"`
	Severity                   string   `xml:"severity,attr"`
	PluginId                   string   `xml:"pluginID,attr"`
	PluginName                 string   `xml:"pluginName,attr"`
	PluginFamily               string   `xml:"pluginFamily,attr"`
	PluginType                 string   `xml:"plugin_type,name"`
	PluginVersion              string   `xml:"plugin_version"`
	Fname                      string   `xml:"fname,name"`
	RiskFactor                 string   `xml:"risk_factor,name"`
	Synopsis                   string   `xml:"synopsis,name"`
	Descripion                 string   `xml:"description,name"`
	Solution                   string   `xml:"solution,name"`
	PluginOutput               string   `xml:"plugin_output,name"`
	SeeAlso                    string   `xml:"see_also,name"`
	CVE                        []string `xml:"cve,name"`
	BID                        []string `xml:"bid,name"`
	XREF                       []string `xml:"xref,name"`
	PluginModificationDate     string   `xml:"plugin_modification_date,name"`
	PluginPublicationDate      string   `xml:"plugin_publication_date,name"`
	VulnPublicationDate        string   `xml:"vuln_publification_date,name"`
	ExploitabilityEase         string   `xml:"exploitability_ease,name"`
	ExploitAvailable           string   `xml:"exploit_available,name"`
	ExploitFrameworkCanvas     string   `xml:"exploit_framework_canvas,name"`
	ExploitFrameworkMetasploit string   `xml:"exploit_framework_metasploit,name"`
	ExploitFrameworkCore       string   `xml:"exploit_framework_core,name"`
	MetasploitName             string   `xml:"metasploit_name,name"`
	CanvasPackage              string   `xml:"canvas_package,name"`
	CVSSVector                 string   `xml:"cvss_vector,name"`
	CVSSBaseScore              string   `xml:"cvss_base_score,name"`
	CVSSTemporalScore          string   `xml:"cvss_temporal_score,name"`
	ComplianceResult           string   `xml:"cm:compliance-result,name"`
	ComplianceActualValue      string   `xml:"cm:compliance-actual-value,name"`
	ComplianceCheckId          string   `xml:"cm:compliance-check-id,name"`
	ComplianceAuditFile        string   `xml:"cm:compliance-audit-file,name"`
	ComplianceCheckValue       string   `xml:"cm:compliance-check-name,name"`
}

// Parse takes a byte array of nessus xml data and unmarshals it into an
// NessusData struct. All elements are returned as strings, it is up to the caller
// to check and cast them to the proper type.
func Parse(content []byte) (*NessusData, error) {
	r := &NessusData{}
	err := xml.Unmarshal(content, r)
	if err != nil {
		return r, err
	}
	return r, nil
}
