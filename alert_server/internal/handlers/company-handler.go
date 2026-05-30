package handlers

import (
	"net/http"
	"server/internal/models"
	"server/pkg"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// 查询所有company
func FindCompanyAllHandler(c *gin.Context) {
	companyInfos, err := models.FindAllCompany(pkg.Db)
	if err != nil {
		logrus.Errorf("查询失败, %v", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    1,
			"message": err.Error(),
		})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"code":    0,
		"message": "success",
		"data":    companyInfos,
	})
}

// 通过ID查询companyInfo
func FindCompanyByIdHandler(c *gin.Context) {
	var company models.CompanyFindRequest
	err := c.ShouldBindUri(&company)
	if err != nil {
		logrus.Errorf("参数错误, %v", err.Error())
		c.JSON(http.StatusOK, gin.H{
			"code":    1,
			"message": "参数错误",
			"data":    "",
		})
		return
	}
	id := company.Id
	res, err := models.FindCompanyById(pkg.Db, id)
	if err != nil {
		logrus.Errorf("查询出错,%v", err.Error())
		c.JSON(http.StatusOK, gin.H{
			"code":    1,
			"message": err.Error(),
		})
		return
	}
	// fmt.Println(res)
	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": "success",
		"data":    res,
	})
}

// 新增company
func CreateCompanyHandler(c *gin.Context) {
	var company models.CompanyCreateRequest
	err := c.ShouldBindJSON(&company)
	if err != nil {
		logrus.Error("参数错误", err)
		c.JSON(http.StatusOK, gin.H{
			"code":    1,
			"message": err.Error(),
		})
		return
	}

	description := company.Description // 获取传入的公司描述/名

	// 查询是否已经存在
	res, err := models.FindCompanyByDesc(pkg.Db, description)
	if err != nil {
		logrus.Errorf("新增company失败, %v", err)
		c.JSON(http.StatusOK, gin.H{
			"code":    1,
			"message": err.Error(),
		})
		return
	}
	if res.Id != 0 {
		// 已存在
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    1,
			"message": "Company already exists",
		})
		return
	}

	var apiKey string
	if company.ApiKey != "" {
		// 传入了api_key
		apiKey = company.ApiKey
	} else {
		// 随机生成api_key
		apiKey, err = pkg.GenerateApiKey(16)
		if err != nil {
			logrus.Errorf("新增company失败, %v", err)
			c.JSON(http.StatusOK, gin.H{
				"code":    1,
				"message": err.Error(),
			})
			return
		}
	}

	companyInfo := models.CompanyInfo{
		ApiKey:      apiKey,
		Description: description,
	}

	id, err := models.CreateCompany(pkg.Db, &companyInfo) // 添加

	if err != nil {
		logrus.Error("新增company失败", err)
		c.JSON(http.StatusOK, gin.H{
			"code":    1,
			"message": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": "success",
		"data":    id,
	})
}

// 删除 company
func DeleteCompanyHandler(c *gin.Context) {
	var req models.CompanyFindRequest
	err := c.ShouldBindUri(&req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    1,
			"message": err.Error(),
		})
		return
	}
	if err := models.DeleteCompany(pkg.Db, req.Id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    1,
			"message": err.Error(),
		})
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{
		"code":    0,
		"message": "success",
	})
}

// 修改 company 数据
func UpdateCompanyHandler(c *gin.Context) {
	var req models.CompanyUpdateRequest
	// 先绑定 URI 参数
	if err := c.ShouldBindUri(&req); err != nil {
		logrus.Errorf("参数错误,%v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    1,
			"message": err.Error(),
		})
		return
	}
	// 再绑定 JSON body
	if err := c.ShouldBindJSON(&req); err != nil {
		logrus.Errorf("参数错误,%v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    1,
			"message": err.Error(),
		})
		return
	}

	var companyToUpdate models.CompanyInfo
	companyToUpdate.Description = req.Description
	companyToUpdate.ApiKey = req.ApiKey
	err := models.UpdateCompany(pkg.Db, req.Id, companyToUpdate)
	if err != nil {
		logrus.Errorf("修改company出错,%v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    1,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": "success",
	})
}
