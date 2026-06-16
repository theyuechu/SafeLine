package model

import "time"

// ThreatIntelSource 威胁情报来源
type ThreatIntelSource string

const (
	IntelSourceFireHOL   ThreatIntelSource = "firehol"
	IntelSourceAbuseIPDB ThreatIntelSource = "abuseipdb"
	IntelSourceManual    ThreatIntelSource = "manual"
)

// ThreatIntel 威胁情报 IP 表
// 跟 PolicyRule 分开，自动同步，自动过期
type ThreatIntel struct {
	ID        uint              `json:"id"          gorm:"primarykey"`
	IP        string            `json:"ip"          gorm:"index;size:45"`       // 单个 IP 或 CIDR
	Source    ThreatIntelSource `json:"source"      gorm:"index;size:32"`       // 情报来源
	ExpireAt  time.Time         `json:"expire_at"   gorm:"index"`               // 过期时间
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// ThreatIntelStats 统计信息
type ThreatIntelStats struct {
	Total   int64
	Expired int64
	Active  int64
	BySource map[ThreatIntelSource]int64
}
