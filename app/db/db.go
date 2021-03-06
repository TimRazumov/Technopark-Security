package db

import (
	"github.com/TimRazumov/Technopark-Security/app/models"
	"github.com/jinzhu/gorm"
)

type RequestStore struct {
	DB *gorm.DB
}

func (store *RequestStore) Set(req models.Request) error {
	if err := store.DB.Create(&req).Error; err != nil {
		return err
	}
	return nil
}

func (store *RequestStore) Get(limit uint) ([]models.Request, error) {
	var requests []models.Request
	if err := store.DB.Limit(limit).Order("id desc").Find(&requests).Error; err != nil {
		return nil, err
	}
	return requests, nil
}

func (store *RequestStore) GetByID(id int) (models.Request, error) {
	var request models.Request
	if err := store.DB.Where("id = ?", id).First(&request).Error; err != nil {
		return models.Request{}, err
	}
	return request, nil
}
