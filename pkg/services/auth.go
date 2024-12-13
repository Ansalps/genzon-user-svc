package services

import (
	"context"
	"net/http"

	"github.com/Ansalps/genzon-user-svc/pkg/db"
	"github.com/Ansalps/genzon-user-svc/pkg/models"
	"github.com/Ansalps/genzon-user-svc/pkg/pb"
	"github.com/Ansalps/genzon-user-svc/pkg/utils"
)

type Server struct {
	H   db.Handler
	Jwt utils.JwtWrapper
	pb.UnimplementedAuthServiceServer
}

func (s *Server) SignUp(ctx context.Context, req *pb.SignUpRequest) (*pb.SignUpResponse, error) {
	var user models.User
	if result := s.H.DB.Where(&models.User{Email: req.Email}).First(&user); result.Error == nil {
		return &pb.SignUpResponse{
			Status: http.StatusConflict,
			Error:  "E-mail already exists",
		}, nil
	}

	user.FirstName = req.Firstname
	user.LastName = req.Lastname
	user.Email = req.Email
	user.Password = utils.HashPassword(req.Password)
	user.Phone = req.Phone
	s.H.DB.Create(&user)
	return &pb.SignUpResponse{
		Status: http.StatusCreated,
	}, nil
}
func (s *Server) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	var user models.User
	if result := s.H.DB.Where(&models.User{Email: req.Email}).First(&user); result.Error != nil {
		return &pb.LoginResponse{
			Status: http.StatusNotFound,
			Error:  "User not found",
		}, nil
	}
	match := utils.CheckPasswordHash(req.Password, user.Password)
	if !match {
		return &pb.LoginResponse{
			Status: http.StatusNotFound,
			Error:  "User not found",
		}, nil
	}
	token, _ := s.Jwt.GenerateToken(user, "user")
	return &pb.LoginResponse{
		Status: http.StatusOK,
		Token:  token,
	}, nil
}

func (s *Server) Validate(ctx context.Context, req *pb.ValidateRequest) (*pb.ValidateResponse, error) {
	claims, err := s.Jwt.ValidateToken(req.Token)
	if err != nil {
		return &pb.ValidateResponse{
			Status: http.StatusBadRequest,
			Error:  err.Error(),
		}, nil
	}
	var user models.User
	if result := s.H.DB.Where(&models.User{Email: claims.Email}).First(&user); result.Error != nil {
		return &pb.ValidateResponse{
			Status: http.StatusNotFound,
			Error:  "User not found",
		}, nil
	}
	return &pb.ValidateResponse{
		Status: http.StatusOK,
		UserId: int64(user.ID),
	}, nil
}
