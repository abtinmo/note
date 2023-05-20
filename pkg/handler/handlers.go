package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	jwtauth "github.com/abtinmo/note/pkg/auth"
	database "github.com/abtinmo/note/pkg/db"
	models "github.com/abtinmo/note/pkg/model"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/segmentio/ksuid"
	"golang.org/x/crypto/bcrypt"
)

func getDynamoSession() *dynamodb.DynamoDB {
	creds := credentials.NewEnvCredentials()
	sess, _ := session.NewSession(&aws.Config{
		Region:      aws.String(os.Getenv("AWS_REGION")),
		Credentials: creds,
	})
	return dynamodb.New(sess)
}

func getUserIdFromContext(c *gin.Context) string {
	claim := c.MustGet("claims")
	return claim.(jwt.MapClaims)["user_id"].(string)
}

var tableName = "NoteTaking"

func CreateNote(c *gin.Context) {
	uuid := ksuid.New()
	user_id := getUserIdFromContext(c)
	user_notes := fmt.Sprintf("NOTE#%v", user_id)
	now_time := time.Now().UTC()
	note := models.NoteCreate{
		Id:         uuid.String(),
		Pk:         user_notes,
		CreateDate: now_time.String(),
		UpdateDate: now_time.String(),
	}
	c.ShouldBindJSON(&note)
	err := database.CreateNote(&note)
	if err.Message != "" {
		c.JSON(err.Code, gin.H{"message": err.Message})
		return
	}
	c.JSON(201, nil)
}

func UpdateNote(c *gin.Context) {
	user_id := getUserIdFromContext(c)
	now_time := time.Now().UTC()
	note := models.NoteUpdate{
		UpdateDate: now_time.String(),
		Id:         c.Param("note_id"),
		UserId:     fmt.Sprintf("NOTE#%v", user_id),
	}
	decoder := json.NewDecoder(c.Request.Body)
	err := decoder.Decode(&note)
	if err != nil {
		c.JSON(500, gin.H{"message": err.Error()})
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
	// validate.Struct(user)
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
	decoder := json.NewDecoder(c.Request.Body)
	decoder.Decode(&userRegisterRequest)
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
	decoder := json.NewDecoder(c.Request.Body)
	decoder.Decode(&userLoginRequest)
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
