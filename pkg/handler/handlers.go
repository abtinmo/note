package handlers

import (
	"fmt"
	"log"
	"time"

	jwtauth "github.com/abtinmo/note/pkg/auth"
	database "github.com/abtinmo/note/pkg/db"
	models "github.com/abtinmo/note/pkg/model"

	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/segmentio/ksuid"
	"golang.org/x/crypto/bcrypt"
)

func getUserIdFromContext(c *gin.Context) string {
	claim := c.MustGet("claims")
	return claim.(jwt.MapClaims)["user_id"].(string)
}

var tableName = "NoteTaking"

func CreateNote(c *gin.Context) {
	uuid := ksuid.New()
	user_notes := fmt.Sprintf("NOTE#%v", getUserIdFromContext(c))
	now_time := time.Now().UTC()
	note := models.NoteCreate{
		Id:         uuid.String(),
		Pk:         user_notes,
		CreateDate: now_time.String(),
		UpdateDate: now_time.String(),
	}
	if err := c.ShouldBindJSON(&note); err != nil {
		c.JSON(400, gin.H{"message": err.Error()})
		return
	}
	err := database.CreateNote(&note)
	if err.Message != "" {
		c.JSON(err.Code, gin.H{"message": err.Message})
		return
	}
	c.JSON(201, nil)
}

func UpdateNote(c *gin.Context) {
	note := models.NoteUpdate{
		UpdateDate: time.Now().UTC().String(),
		Sk:         c.Param("note_id"),
		Pk:         fmt.Sprintf("NOTE#%v", getUserIdFromContext(c)),
	}
	if err := c.ShouldBindJSON(&note); err != nil {
		c.JSON(400, gin.H{"message": err.Error()})
		return
	}
	err1 := database.UpdateNote(&note)
	if err1.Message != "" {
		c.JSON(err1.Code, gin.H{"message": err1.Message})
		return
	}
	c.JSON(200, nil)
}

func DeleteNote(c *gin.Context) {
	user_pk := fmt.Sprintf("NOTE#%v", getUserIdFromContext(c))
	note_id := c.Param("note_id")
	err1 := database.DeleteNote(user_pk, note_id)
	if err1.Message != "" {
		c.JSON(err1.Code, gin.H{"message": err1.Message})
		return
	}
	c.JSON(204, nil)
}

func GetNotes(c *gin.Context) {
	user_id := getUserIdFromContext(c)
	user_pk := fmt.Sprintf("NOTE#%v", user_id)
	response, err := database.GetNotes(user_pk)
	if err.Message != "" {
		c.JSON(err.Code, gin.H{"message": err.Message})
		return
	}
	c.JSON(200, response)
}

func RegisterUser(c *gin.Context) {
	// get username and password and register the user, return access token in response
	var userRegisterRequest models.UserAuthRequest
	if err := c.ShouldBindJSON(&userRegisterRequest); err != nil {
		c.JSON(400, gin.H{"message": err.Error()})
		return
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(userRegisterRequest.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Can not generate hashed password: %s", err)
		c.JSON(500, gin.H{"message": "Internal server error."})
		return
	}
	user := models.User{
		Pk:       fmt.Sprintf("USERNAME#%v", userRegisterRequest.Username),
		Sk:       ksuid.New().String(),
		Password: string(hashedPassword),
	}
	var resp, err1 = database.GetUser(user.Pk)
	if err != nil {
		log.Fatalf("Error at geting user data from db: %s", err1)
		c.JSON(500, gin.H{"message": "Internal server error."})
		return
	}
	if *resp.Count > 0 {
		c.JSON(409, gin.H{"message": "User already exists."})
		return
	}
	err2 := database.CreateUser(&user)
	if err2.Message != "" {
		c.JSON(err2.Code, gin.H{"message": err2.Message})
		return
	}
	access_token, err := jwtauth.GenerateToken(user.Sk)
	if err != nil {
		log.Fatalf("Can not create jwt token: %s", err)
		c.JSON(500, gin.H{"message": "Internal server error."})
		return
	}
	data := models.UserAccessToken{AccessToken: access_token}
	c.JSON(201, data)
}

func LoginUser(c *gin.Context) {
	var userLoginRequest models.UserAuthRequest
	if err := c.ShouldBindJSON(&userLoginRequest); err != nil {
		c.JSON(400, gin.H{"message": err.Error()})
		return
	}
	userName := fmt.Sprintf("USERNAME#%v", userLoginRequest.Username)
	var resp1, err = database.GetUser(userName)
	if err != nil {
		log.Fatalf("Error at geting user data from db: %s", err)
		c.JSON(500, gin.H{"message": "Internal server error."})
		return
	}
	if *resp1.Count <= 0 {
		c.JSON(404, gin.H{"message": "User not found."})
		return
	}
	var db_users []models.User
	err1 := dynamodbattribute.UnmarshalListOfMaps(resp1.Items, &db_users)
	if err1 != nil {
		log.Fatalf("Error at unmarshaling user record: %s", err1)
		c.JSON(500, gin.H{"message": "Internal server error."})
		return
	}
	user := db_users[0]
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(user.Password))
	if err != nil {
		c.JSON(400, gin.H{"message": "Password is worng."})
		return
	}
	access_token, err := jwtauth.GenerateToken(user.Sk)
	if err != nil {
		c.JSON(500, gin.H{"message": "Internal server error."})
		return
	}
	data := models.UserAccessToken{AccessToken: access_token}
	c.JSON(200, data)
}
