package handler

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/smallbiznis/valora-auth/internal/http/middleware"
	"github.com/smallbiznis/valora-auth/internal/service"
)

func (h *AuthHandler) PasswordLogin(c *gin.Context) {
	orgCtx, ok := middleware.GetOrgContext(c)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "invalid_tenant", "error_description": "Org not resolved."})
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		ClientID string `json:"client_id"`
		Scope    string `json:"scope"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Invalid payload."})
		return
	}
	if strings.TrimSpace(req.Email) == "" || strings.TrimSpace(req.Password) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Email and password are required."})
		return
	}

	clientID := strings.TrimSpace(req.ClientID)
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unauthorized_client", "error_description": "Unknown client_id for org."})
		return
	}

	scope := strings.TrimSpace(req.Scope)

	resp, err := h.Auth.LoginWithPassword(c.Request.Context(), orgCtx.Org.ID, req.Email, req.Password, clientID, scope)
	if err != nil {
		respondOAuthError(c, err)
		return
	}

	maxAge := 3600
	setCookie(c, "sb_access_token", resp.AccessToken, maxAge, "/", ".smallbiznisapp.io", false, true)
	setCookie(c, "sb_refresh_token", resp.RefreshToken, maxAge, "/", ".smallbiznisapp.io", false, true)

	c.JSON(http.StatusOK, resp)
}

func (h *AuthHandler) PasswordRegister(c *gin.Context) {
	orgCtx, ok := middleware.GetOrgContext(c)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "invalid_tenant", "error_description": "Org not resolved."})
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
		ClientID string `json:"client_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Invalid payload."})
		return
	}
	if strings.TrimSpace(req.Email) == "" || strings.TrimSpace(req.Password) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Email and password are required."})
		return
	}

	clientID := strings.TrimSpace(req.ClientID)
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unauthorized_client", "error_description": "Unknown client_id for org."})
		return
	}

	resp, err := h.Auth.RegisterWithPassword(c.Request.Context(), orgCtx.Org.ID, req.Email, req.Password, req.Name, clientID)
	if err != nil {
		respondOAuthError(c, err)
		return
	}

	maxAge := 3600
	setCookie(c, "sb_access_token", resp.AccessToken, maxAge, "/", ".smallbiznisapp.io", false, true)
	setCookie(c, "sb_refresh_token", resp.RefreshToken, maxAge, "/", ".smallbiznisapp.io", false, true)


	c.JSON(http.StatusOK, resp)
}

func (h *AuthHandler) PasswordForgot(c *gin.Context) {
	orgCtx, ok := middleware.GetOrgContext(c)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "invalid_tenant", "error_description": "Org not resolved."})
		return
	}

	var req struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Invalid payload."})
		return
	}
	if strings.TrimSpace(req.Email) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Email is required."})
		return
	}

	if err := h.Auth.ForgotPassword(c.Request.Context(), orgCtx.Org.ID, req.Email); err != nil {
		respondOAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "If the account exists, password reset instructions have been sent."})
}

func (h *AuthHandler) OTPRequest(c *gin.Context) {
	orgCtx, ok := middleware.GetOrgContext(c)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "invalid_tenant", "error_description": "Org not resolved."})
		return
	}

	var req struct {
		Phone   string `json:"phone"`
		Channel string `json:"channel"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Invalid payload."})
		return
	}
	if strings.TrimSpace(req.Phone) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Phone is required."})
		return
	}

	if err := h.Auth.RequestOTP(c.Request.Context(), orgCtx.Org.ID, req.Phone, req.Channel); err != nil {
		respondOAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OTP request accepted."})
}

func (h *AuthHandler) OTPVerify(c *gin.Context) {
	orgCtx, ok := middleware.GetOrgContext(c)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "invalid_tenant", "error_description": "Org not resolved."})
		return
	}

	var req struct {
		Phone    string `json:"phone"`
		Code     string `json:"code"`
		ClientID string `json:"client_id"`
		Scope    string `json:"scope"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Invalid payload."})
		return
	}
	if strings.TrimSpace(req.Phone) == "" || strings.TrimSpace(req.Code) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Phone and code are required."})
		return
	}

	clientID := strings.TrimSpace(req.ClientID)
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unauthorized_client", "error_description": "Unknown client_id for org."})
		return
	}
	scope := strings.TrimSpace(req.Scope)

	resp, err := h.Auth.VerifyOTP(c.Request.Context(), orgCtx.Org.ID, req.Phone, req.Code, clientID, scope)
	if err != nil {
		respondOAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (h *AuthHandler) Me(c *gin.Context) {
	orgCtx, ok := middleware.GetOrgContext(c)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "invalid_tenant", "error_description": "Org not resolved."})
		return
	}

	std, ok := middleware.GetStdClaims(c)
	if !ok || std == nil || strings.TrimSpace(std.Subject) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "Missing subject claim."})
		return
	}
	userID, err := strconv.ParseInt(std.Subject, 10, 64)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "Invalid subject claim."})
		return
	}

	user, err := h.Auth.GetUserInfo(c.Request.Context(), orgCtx.Org.ID, userID)
	if err != nil {
		respondOAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, user)
}

func respondOAuthError(c *gin.Context, err error) {
	if oauthErr, ok := err.(*service.OAuthError); ok {
		c.JSON(oauthErr.Status, gin.H{"error": oauthErr.Code, "error_description": oauthErr.Description})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
}

func setCookie(c *gin.Context, name, value string, maxAge int, path, domain string, secure, httpOnly bool) {
	c.SetCookie(
		name,   // name
		value,         // value
		maxAge,                // maxAge (1 jam)
		path,                 // path
		domain, // domain → penting!!
		secure,                // secure → harus true kalau HTTPS
		httpOnly,                // httpOnly → jangan bisa diakses JS
	)
}
