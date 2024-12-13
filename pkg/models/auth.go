package models

import "gorm.io/gorm"

type User struct {
	gorm.Model
	//ID        uint   `gorm:"primary key" json:"id"`
	FirstName string `validate:"required"`
	LastName  string `validate:"required"`
	Email     string `gorm:"unique" validate:"required"`
	Password  string `validate:"required"`
	Phone     string `json:"phone" validate:"required,numeric,len=10"`
	Status    string `gorm:"type:varchar(10); check(status IN ('Active', 'Blocked', 'Deleted')) ;default:'Active'" json:"status" validate:"required"`
}
