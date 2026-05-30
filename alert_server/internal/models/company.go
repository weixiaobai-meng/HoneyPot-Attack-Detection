package models

import (
	"errors"
	"log"

	"gorm.io/gorm"
)

// 数据库表-company_infos
type CompanyInfo struct {
	gorm.Model
	Id          uint   `gorm:"primarykey"`  // 公司/单位id
	ApiKey      string `gorm:"uniqueIndex"` // apikey
	Description string `gorm:"uniqueIndex"` // 描述
	Role        string ``
}

// 获取key对应的api，可用于校验
func FindCompanyIdByKey(db *gorm.DB, apiKey string) (uint, error) {
	var companyInfo CompanyInfo
	result := db.Where("api_key = ?", apiKey).First(&companyInfo) // 从companyInfo表中查询
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			log.Printf("no record found for apiKey: %s", apiKey)
			return 0, nil // 没有找到记录
		}
		// 错误记录日志
		log.Printf("failed to find company info: %s", result.Error.Error())
		return 0, result.Error
	}
	// print(companyInfo.Id)
	return companyInfo.Id, nil
}

func FindCompanyInfoByKey(db *gorm.DB, apiKey string) (*CompanyInfo, error) {
	var companyInfo CompanyInfo
	result := db.Where("api_key = ?", apiKey).First(&companyInfo) // 从companyInfo表中查询
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			log.Printf("no record found for apiKey: %s", apiKey)
			return nil, result.Error // 没有找到记录
		}
		// 错误记录日志
		log.Printf("failed to find company info: %s", result.Error.Error())
		return nil, result.Error
	}
	return &companyInfo, nil
}

// 查询获取company info
func FindAllCompany(db *gorm.DB) ([]CompanyInfo, error) {
	var companyInfos []CompanyInfo
	query := db.Model(&CompanyInfo{})
	result := query.Find(&companyInfos)
	return companyInfos, result.Error
}

// 查询获取company info
func FindCompanyById(db *gorm.DB, id int) (CompanyInfo, error) {
	var companyInfo CompanyInfo
	query := db.Model(&CompanyInfo{})
	result := query.Where("id = ?", id).First(&companyInfo)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) { //未找到
		return CompanyInfo{}, result.Error
	}
	return companyInfo, result.Error
}

// 查询获取company info
func FindCompanyByDesc(db *gorm.DB, description string) (CompanyInfo, error) {
	var companyInfo CompanyInfo
	query := db.Model(&CompanyInfo{})
	result := query.Where("description = ?", description).First(&companyInfo)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) { //未找到
		return CompanyInfo{}, nil
	}
	return companyInfo, result.Error
}

// 插入公司信息
func CreateCompany(db *gorm.DB, companyInfo *CompanyInfo) (uint, error) {
	result := db.Create(&companyInfo)
	if result.Error != nil {
		return 0, result.Error
	}
	return companyInfo.Id, nil
}

// 删除companyInfo
func DeleteCompany(db *gorm.DB, id int) error {
	var companyInfo CompanyInfo
	result := db.Where("Id = ?", id).First(&companyInfo)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return result.Error // 没有找到记录
		}
		return result.Error
	}
	return nil
}

// 修改 company 信息
func UpdateCompany(db *gorm.DB, id int, companyToUpdate CompanyInfo) error {
	// 查找
	result := db.Where("Id = ?", id).Updates(companyToUpdate)
	if result.RowsAffected == 0 {
		return errors.New("记录不存在或没有数据被更新")
	}
	return result.Error
}

// 验证 API Key 并返回用户的角色信息
func ValidateAPIKey(db *gorm.DB, apiKey string) (string, error) {
	var company CompanyInfo
	result := db.Where("api_key = ?", apiKey).First(&company)

	if result.Error != nil {
		return "", errors.New("invalid API Key")
	}

	// 返回用户的角色
	return company.Role, nil
}

// ===================请求参数结构体==============
// 查询请求结构体
type CompanyFindRequest struct {
	Id int `uri:"id" binding:"required"`
}
type CompanyCreateRequest struct {
	ApiKey      string `json:"api_key"`
	Description string `json:"description" binding:"required"`
}

type CompanyUpdateRequest struct {
	Id          int    `uri:"id" binding:"required"`
	ApiKey      string `json:"api_key"`
	Description string `json:"description"`
}
