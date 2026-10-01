package handler

import (
	"go-auth-api/internal/auth"
	"go-auth-api/internal/store"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	store *store.UserStore
}

func NewAuthHandler(s *store.UserStore) *AuthHandler {
	return &AuthHandler{store: s}
}

type loginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}

	user, ok := h.store.FindByUsername(req.Username)
	if !ok {
		c.JSON(401, gin.H{"error": "invalid credentials"})
		return
	}

	if !auth.CheckPassword(user.Password, req.Password) {
		c.JSON(401, gin.H{"error": "invalid credentials"})
		return
	}

	tokenString, err := auth.GenerateToken(user.ID)
	if err != nil {
		c.JSON(500, gin.H{"error": "server error"})
		return
	}

	c.JSON(200, gin.H{"token": tokenString})
}
