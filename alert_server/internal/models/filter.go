package models

type CreateWhiteRequest struct {
	Ip string `json:"ip" binding:"required"`
}
