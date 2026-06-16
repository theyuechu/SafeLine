package api

import (
	"github.com/gin-gonic/gin"

	"chaitin.cn/patronus/safeline-2/management/webserver/api/response"
	"chaitin.cn/patronus/safeline-2/management/webserver/model"
	"chaitin.cn/patronus/safeline-2/management/webserver/pkg/database"
)

// GetThreatIntelStatus 威胁情报状态
func GetThreatIntelStatus(c *gin.Context) {
	db := database.GetDB()

	var total, expired, active, firehol, manual int64
	db.Model(&model.ThreatIntel{}).Count(&total)
	db.Model(&model.ThreatIntel{}).Where("expire_at <= NOW()").Count(&expired)
	db.Model(&model.ThreatIntel{}).Where("expire_at > NOW()").Count(&active)
	db.Model(&model.ThreatIntel{}).Where("source = ?", model.IntelSourceFireHOL).Count(&firehol)
	db.Model(&model.ThreatIntel{}).Where("source = ?", model.IntelSourceManual).Count(&manual)

	response.Success(c, gin.H{
		"total":   total,
		"expired": expired,
		"active":  active,
		"sources": gin.H{
			"firehol": firehol,
			"manual":  manual,
		},
	})
}
