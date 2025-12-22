package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

// [
// "hamid" => ["register" => 1334],
// "akbar" => ["register" => 3333],
// ]

type OTP struct {
	Code      string    // خود کد
	ExpiresAt time.Time // تا کی معتبره
	Used      bool      // استفاده شده یا نه
}

var OtpStore = make(map[string]map[string]*OTP)

func main() {
	//  Setup Gin
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	//  Trusted Proxies
	if err := r.SetTrustedProxies([]string{"127.0.0.1"}); err != nil {
		log.Fatal("failed to set trusted proxies:", err)
	}

	// ====== 3) DB Connection ======
	dsn := "root:secret@tcp(127.0.0.1:3306)/myapp"
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("failed to open db:", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatal("failed to ping db:", err)
	}
	// ====== 4) Ping ========================================================
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "pong"})
	})

	//  Register
	r.POST("/register", func(c *gin.Context) {
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Otp      string `json:"otp"`
		}

		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if body.Username == "" || body.Password == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "username and password are required"})
			return
		}

		if body.Otp == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "otp is required"})
			return
		}

		otpDetail, ok := OtpStore[body.Username]["register"]

		if ok {
			if otpDetail.Code != body.Otp {
				c.JSON(http.StatusBadRequest, gin.H{"error": "otp code is incorrect"})
				return
			}
			if otpDetail.ExpiresAt.Before(time.Now()) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "otp expires date is in the future"})
				return
			}
			if otpDetail.Used {
				c.JSON(http.StatusBadRequest, gin.H{"error": "otp already used"})
				return
			}
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "otp code is not found"})
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
			return
		}

		if _, execErr := db.Exec(
			"INSERT INTO users (username, password_hash) VALUES (?, ?)",
			body.Username, string(hashedPassword),
		); execErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": execErr.Error()})
			return
		}

		otpDetail.Used = true

		c.JSON(http.StatusOK, gin.H{"message": "User registered successfully"})
	})

	// Login
	r.POST("/login", func(c *gin.Context) {
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Otp      string `json:"otp"`
		}

		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		otpDetail, ok := OtpStore[body.Username]["login"]

		if ok {
			if otpDetail.Code != body.Otp {
				c.JSON(http.StatusBadRequest, gin.H{"error": "otp code is incorrect"})
				return
			}
			if otpDetail.ExpiresAt.Before(time.Now()) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "otp expires date is in the future"})
				return
			}
			if otpDetail.Used {
				c.JSON(http.StatusBadRequest, gin.H{"error": "otp already used"})
				return
			}
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "otp code is not found"})
			return
		}

		otpDetail.Used = true

		var userID int64
		var passwordHash string
		err := db.QueryRow(
			"SELECT id, password_hash FROM users WHERE username = ?",
			body.Username,
		).Scan(&userID, &passwordHash)

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(body.Password)); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
			return
		}

		token, err := newSessionToken()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
			return
		}

		expiresAt := time.Now().Add(7 * 24 * time.Hour) // 7 days
		_, execErr := db.Exec(
			"INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)",
			userID, token, expiresAt,
		)
		if execErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": execErr.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message":    "login success",
			"token":      token,
			"expires_in": 7 * 24 * 3600,
		})
	})

	//  OTP Send
	r.POST("/otp", func(c *gin.Context) {
		var body struct {
			Username string `json:"username"`
			Section  string `json:"section"` // register | forget_password | login
		}

		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if body.Username == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "username is required"})
			return
		}
		if body.Section != "register" && body.Section != "forget_password" && body.Section != "login" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "purpose must be register | forget_password | login"})
			return
		}

		code, err := generateOTP6()

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		if OtpStore[body.Username] == nil {
			OtpStore[body.Username] = make(map[string]*OTP)
		}

		OtpStore[body.Username][body.Section] = &OTP{
			Code:      code,
			ExpiresAt: time.Now().Add(2 * time.Minute),
			Used:      false,
		}

		c.JSON(http.StatusOK, gin.H{
			"message":    "otp sent",
			"otp":        code, // for learning
			"expires_in": 120,
		})
	})

	//  Me (با Bearer token مشخص می‌کنه کی هستی)
	r.GET("/me", func(c *gin.Context) {
		token := getBearerToken(c)
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			return
		}

		var userID int64
		var username string
		err := db.QueryRow(
			`SELECT u.id, u.username
			 FROM sessions s
			 JOIN users u ON u.id = s.user_id
			 WHERE s.token = ? AND s.revoked_at IS NULL AND s.expires_at > NOW()
			 LIMIT 1`,
			token,
		).Scan(&userID, &username)

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"id": userID, "username": username})
	})

	//  Logout (token رو revoke می‌کنه)
	r.POST("/logout", func(c *gin.Context) {
		token := getBearerToken(c)
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			return
		}

		res, err := db.Exec(
			"UPDATE sessions SET revoked_at = NOW() WHERE token = ? AND revoked_at IS NULL",
			token,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		affected, _ := res.RowsAffected()
		if affected == 0 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "logged out"})
	})

	//  Run Server
	log.Println("server listening on :6060")
	if err := r.Run(":6060"); err != nil {
		log.Fatal("failed to run server:", err)
	}
}

// Helper: generate OTP 6 digits
func generateOTP6() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	n := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if n < 0 {
		n = -n
	}
	code := n % 1000000
	return fmt.Sprintf("%06d", code), nil
}

// Helper: hash OTP
func hashOTP(otp string) string {
	sum := sha256.Sum256([]byte(otp))
	return hex.EncodeToString(sum[:])
}

// Helper: create session token
func newSessionToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Helper: get Bearer token
func getBearerToken(c *gin.Context) string {
	h := c.GetHeader("Authorization")
	parts := strings.SplitN(h, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return strings.TrimSpace(parts[1])
	}
	return ""
}
