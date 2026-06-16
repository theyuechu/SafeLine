package cron

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"gorm.io/gorm/clause"

	"chaitin.cn/patronus/safeline-2/management/webserver/model"
	"chaitin.cn/patronus/safeline-2/management/webserver/pkg/config"
	"chaitin.cn/patronus/safeline-2/management/webserver/pkg/database"
	"chaitin.cn/patronus/safeline-2/management/webserver/pkg/fvm"
)

// 威胁情报源
var threatIntelSources = []struct {
	Name   string
	URL    string
	Source model.ThreatIntelSource
	TTL    time.Duration
}{
	{
		Name:   "FireHOL Level 1",
		URL:    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
		Source: model.IntelSourceFireHOL,
		TTL:    24 * time.Hour,
	},
	{
		Name:   "FireHOL Level 2",
		URL:    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
		Source: model.IntelSourceFireHOL,
		TTL:    24 * time.Hour,
	},
	{
		Name:   "FireHOL Web Attacks",
		URL:    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_webserver.netset",
		Source: model.IntelSourceFireHOL,
		TTL:    24 * time.Hour,
	},
}

const specThreatIntel = "0 0 3 * * ?" // 每天凌晨 3 点

// syncThreatIntel 同步所有威胁情报源并重新编译
func syncThreatIntel() {
	logger.Info("Starting threat intelligence sync...")
	db := database.GetDB()
	total := 0

	for _, src := range threatIntelSources {
		n, err := syncSource(src.URL, src.Source, src.TTL)
		if err != nil {
			logger.Errorf("sync %s failed: %v", src.Name, err)
			continue
		}
		logger.Infof("synced %s: %d entries", src.Name, n)
		total += n
	}

	// 清理过期
	r := db.Where("expire_at <= NOW()").Delete(&model.ThreatIntel{})
	if r.Error == nil && r.RowsAffected > 0 {
		logger.Infof("cleaned %d expired threat intel entries", r.RowsAffected)
	}

	logger.Infof("threat intel sync done, total new/updated: %d", total)

	// 重新编译 FSL 并推送到 detector
	if err := recompileThreatIntel(); err != nil {
		logger.Errorf("recompile after threat intel sync failed: %v", err)
	}
}

// syncSource 拉取单个情报源，用 upsert 写入 DB
func syncSource(url string, source model.ThreatIntelSource, ttl time.Duration) (int, error) {
	resp, err := http.Get(url)
	if err != nil {
		return 0, fmt.Errorf("fetch %s failed: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("read body failed: %w", err)
	}

	expireAt := time.Now().Add(ttl)
	lines := strings.Split(string(body), "\n")
	db := database.GetDB()
	added := 0

	for _, line := range lines {
		ip := strings.TrimSpace(line)
		if ip == "" || strings.HasPrefix(ip, "#") || strings.HasPrefix(ip, ";") {
			continue
		}
		// 跳过 IPv6
		if strings.Contains(ip, ":") {
			continue
		}

		err := db.Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "ip"}},
			DoUpdates: clause.AssignmentColumns([]string{"source", "expire_at", "updated_at"}),
		}).Create(&model.ThreatIntel{
			IP:        ip,
			Source:    source,
			ExpireAt:  expireAt,
			UpdatedAt: time.Now(),
		}).Error
		if err != nil {
			return added, fmt.Errorf("insert %s failed: %w", ip, err)
		}
		added++
	}

	return added, nil
}

// recompileThreatIntel 重新编译 FSL（全量编译）并推送
func recompileThreatIntel() error {
	db := database.GetDB()
	fullFSL, err := fvm.GenerateFullFSL(db)
	if err != nil {
		return fmt.Errorf("generate FSL failed: %w", err)
	}
	addr := config.GlobalConfig.Detector.Addr
	if addr == "" {
		logger.Warn("detector addr not configured, skip push")
		return nil
	}
	if err := fvm.CompileAndPush(fullFSL, addr); err != nil {
		return fmt.Errorf("compile and push failed: %w", err)
	}
	return nil
}

// InitThreatIntel 启动时立即同步一次
func InitThreatIntel() {
	logger.Info("initializing threat intelligence (first sync)...")
	go func() {
		syncThreatIntel()
		logger.Info("threat intelligence initialized")
	}()
}
