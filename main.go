package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"github.com/segmentio/ksuid"
	"golang.org/x/crypto/bcrypt"
)

var validate validator.Validate

func getKey() []byte {
	var str = "hello boss!"
	key := []byte(str)
	return key
}

type ErrorMsg struct {
	Message string `json:"message"`
}

func getDynamoSession() *dynamodb.DynamoDB {
	creds := credentials.NewEnvCredentials()
	sess, _ := session.NewSession(&aws.Config{
		Region:      aws.String("eu-central-1"),
		Credentials: creds,
	})
	return dynamodb.New(sess)
}

func getUserIdFromContext(c *gin.Context) string {
	claim := c.MustGet("claims")
	return claim.(jwt.MapClaims)["user_id"].(string)
}

type Note struct {
	Id         string `json:"sk" validate:"required"`
	Title      string `json:"title" validate:"required"`
	Body       string `json:"body" validate:"required"`
	Tag        string `json:"tag" validate:"required"`
	CreateDate string `json:"create_date"`
	UpdateDate string `json:"update_date"`
}

type NoteCreate struct {
	Id         string `json:"sk" validate:"required"`
	Pk         string `json:"pk" validate:"required"`
	Title      string `json:"title" validate:"required"`
	Body       string `json:"body" validate:"required"`
	Tag        string `json:"tag,omitempty" validate:"required"`
	CreateDate string `json:"create_date,omitempty"`
	UpdateDate string `json:"update_date,omitempty"`
}

type NoteUpdate struct {
	Title      string `json:"title" validate:"required"`
	Body       string `json:"body" validate:"required"`
	Tag        string `json:"tag,omitempty" validate:"required"`
	UpdateDate string
}

type UserRegisterRequest struct {
	Password string `json:"password" validate:"required"`
	Username string `json:"username" validate:"required"`
}

type RegisterResponse struct {
	AccessToken string `json:"acces_token" validate:"required"`
}

type NoteResponse struct {
	Count   int    `json:"count"`
	Results []Note `json:"results"`
}

func dayToNanoSec(day int) int {
	return day * 8.64e+13
}

var tableName = "NoteTaking"

func generateToken(user_id string) (string, error) {
	now_time := time.Now().UTC()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp":     now_time.Add(time.Duration(dayToNanoSec(180))).Unix(),
		"iss":     now_time.Add(10000).Unix(),
		"user_id": user_id,
	})
	return token.SignedString(getKey())
}

func validateTokenMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth_token := c.Request.Header.Get("authorization")
		if auth_token == "" {
			c.JSON(400, gin.H{"message": "An authorization header is required."})
			c.Abort()
		}
		bearerToken := strings.Split(auth_token, " ")
		if len(bearerToken) != 2 {
			c.JSON(400, gin.H{"message": "Invalid authorization token."})
			c.Abort()
		}
		token, error := jwt.Parse(bearerToken[1], func(token *jwt.Token) (interface{}, error) {
			if _, err := token.Method.(*jwt.SigningMethodHMAC); !err {
				log.Fatalf("Error while parrsing token %v", err)
				return nil, fmt.Errorf("There was an error.")
			}
			return getKey(), nil
		})
		if error != nil {
			c.JSON(400, gin.H{"message": error.Error()})
			c.Abort()
		}
		if !token.Valid {
			c.JSON(400, gin.H{"message": "Invalid authorization token."})
			c.Abort()
		}
		c.Set("claims", token.Claims)
		c.Next()
	}

}

func create(c *gin.Context) {
	uuid := ksuid.New()
	user_id := getUserIdFromContext(c)
	user_notes := fmt.Sprintf("NOTE#%v", user_id)
	now_time := time.Now().UTC()
	note := NoteCreate{
		Id:         uuid.String(),
		Pk:         user_notes,
		CreateDate: now_time.String(),
		UpdateDate: now_time.String(),
	}
	decoder := json.NewDecoder(c.Request.Body)
	err := decoder.Decode(&note)
	if err != nil {
		c.JSON(400, gin.H{"message": err.Error()})
		c.Abort()
	}
	svc := getDynamoSession()

	av, err := dynamodbattribute.MarshalMap(note)
	if err != nil {
		log.Fatalf("Got error marshalling new note: %s", err)
		c.JSON(500, gin.H{"message": "Internal server error."})
		c.Abort()
	}
	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String(tableName),
	}

	_, err = svc.PutItem(input)
	if err != nil {
		log.Fatalf("Got error calling PutItem: %s", err)
		c.JSON(500, gin.H{"message": "Internal server error."})
		c.Abort()
	}
	c.JSON(201, nil)
}

func update(c *gin.Context) {
	user_id := getUserIdFromContext(c)
	user_notes := fmt.Sprintf("NOTE#%v", user_id)
	note_id := c.Param("note_id")
	now_time := time.Now().UTC()
	note := NoteUpdate{
		UpdateDate: now_time.String(),
	}
	decoder := json.NewDecoder(c.Request.Body)
	err := decoder.Decode(&note)
	if err != nil {
		println(err)
	}
	// save data in db
	input := &dynamodb.UpdateItemInput{
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":title": {
				S: aws.String(note.Title),
			},
			":body": {
				S: aws.String(note.Body),
			},
			":tag": {
				S: aws.String(note.Tag),
			},
			":update_date": {
				S: aws.String(note.UpdateDate),
			},
		},
		TableName: aws.String(tableName),
		Key: map[string]*dynamodb.AttributeValue{
			"pk": {
				S: aws.String(user_notes),
			},
			"sk": {
				S: aws.String(note_id),
			},
		},
		ReturnValues:     aws.String("UPDATED_NEW"),
		UpdateExpression: aws.String("set title = :title, body = :body, tag = :tag, update_date = :update_date"),
	}
	svc := getDynamoSession()

	_, err1 := svc.UpdateItem(input)
	if err1 != nil {
		log.Fatalf("Error by updating note: %s", err1)
		c.JSON(500, gin.H{"message": "Internal server error."})
	}
}

func delete(c *gin.Context) {
	user_id := getUserIdFromContext(c)
	user_notes := fmt.Sprintf("NOTE#%v", user_id)
	note_id := c.Param("note_id")

	input := &dynamodb.DeleteItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			"pk": {
				S: aws.String(user_notes),
			},
			"sk": {
				S: aws.String(note_id),
			},
		},
		TableName: aws.String(tableName),
	}
	svc := getDynamoSession()
	_, err := svc.DeleteItem(input)
	if err != nil {
		log.Fatalf("Error by deleting user from db: %s", err)
		c.JSON(500, gin.H{"message": "Internal server error."})
		c.Abort()
	}
	c.JSON(204, nil)
}

func getNotes(c *gin.Context) {
	user_id := getUserIdFromContext(c)
	// validate.Struct(user)
	user_notes := fmt.Sprintf("NOTE#%v", user_id)
	svc := getDynamoSession()
	var queryInput = &dynamodb.QueryInput{
		TableName: aws.String(tableName),
		KeyConditions: map[string]*dynamodb.Condition{
			"pk": {
				ComparisonOperator: aws.String("EQ"),
				AttributeValueList: []*dynamodb.AttributeValue{
					{
						S: aws.String(user_notes),
					},
				},
			},
		},
	}
	var resp1, err1 = svc.Query(queryInput)
	if err1 != nil {
		log.Fatalf("Error at geting user data from db: %s", err1)
		c.JSON(500, gin.H{"message": "Internal server error."})
		c.Abort()
	}

	var notes []Note
	err := dynamodbattribute.UnmarshalListOfMaps(resp1.Items, &notes)
	if err != nil {
		log.Fatalf("Error at unmarshaling user record: %s", err1)
		c.JSON(500, gin.H{"message": "Internal server error."})
		c.Abort()
	}
	data := NoteResponse{Count: int(*resp1.Count), Results: notes}
	c.JSON(200, data)
}

func registerUser(c *gin.Context) {
	// get username and password and register the user, return access token in response
	var user UserRegisterRequest
	decoder := json.NewDecoder(c.Request.Body)
	decoder.Decode(&user)
	//validate.Struct(user)
	password := []byte(user.Password)

	// Hashing the password with the default cost of 10
	hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Can not generate hashed password: %s", err)
		c.JSON(500, gin.H{"message": "Internal server error."})
		c.Abort()
	}
	username := fmt.Sprintf("USERNAME#%v", user.Username)
	uuid := ksuid.New()
	type UserRecord struct {
		Pk       string `json:"pk" validate:"required"`
		Sk       string `json:"sk" validate:"required"`
		Password string `json:"password" validate:"required"`
	}

	userRecord := UserRecord{
		Pk:       username,
		Sk:       uuid.String(),
		Password: string(hashedPassword),
	}
	var queryInput = &dynamodb.QueryInput{
		TableName: aws.String(tableName),
		KeyConditions: map[string]*dynamodb.Condition{
			"pk": {
				ComparisonOperator: aws.String("EQ"),
				AttributeValueList: []*dynamodb.AttributeValue{
					{
						S: aws.String(userRecord.Pk),
					},
				},
			},
		},
	}
	svc := getDynamoSession()
	var resp1, err1 = svc.Query(queryInput)
	if err1 != nil {
		log.Fatalf("Error at geting user data from db: %s", err)
		c.JSON(500, gin.H{"message": "Internal server error."})
		c.Abort()
	}
	if *resp1.Count > 0 {
		c.JSON(409, gin.H{"message": "User already exists."})
		c.Abort()
	}
	fmt.Println(err1)
	av, err := dynamodbattribute.MarshalMap(&userRecord)
	if err != nil {
		log.Fatalf("Error at unmarshaling user record: %s", err1)
		c.JSON(500, gin.H{"message": "Internal server error."})
		c.Abort()
	}
	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String(tableName),
	}

	_, err = svc.PutItem(input)
	if err != nil {
		log.Fatalf("Got error calling PutItem: %s", err)
		c.JSON(500, gin.H{"message": "Internal server error."})
	}
	access_token, err := generateToken(uuid.String())
	if err != nil {
		log.Fatalf("Can not create jwt token: %s", err)
		c.JSON(500, gin.H{"message": "Internal server error."})
		c.Abort()
	}
	data := RegisterResponse{AccessToken: access_token}
	c.JSON(201, data)
}

func loginUser(c *gin.Context) {
	var user UserRegisterRequest
	decoder := json.NewDecoder(c.Request.Body)
	decoder.Decode(&user)
	username := fmt.Sprintf("USERNAME#%v", user.Username)
	svc := getDynamoSession()

	var queryInput = &dynamodb.QueryInput{
		TableName: aws.String(tableName),
		KeyConditions: map[string]*dynamodb.Condition{
			"pk": {
				ComparisonOperator: aws.String("EQ"),
				AttributeValueList: []*dynamodb.AttributeValue{
					{
						S: aws.String(username),
					},
				},
			},
		},
	}
	var resp1, err = svc.Query(queryInput)
	if err != nil {
		log.Fatalf("Error at geting user data from db: %s", err)
		c.JSON(500, gin.H{"message": "Internal server error."})
		c.Abort()
	}
	if *resp1.Count <= 0 {
		c.JSON(404, gin.H{"message": "User not found."})
		c.Abort()
	}
	type UserAuthRecord struct {
		Sk       string `json:"sk" validate:"required"`
		Password string `json:"password" validate:"required"`
	}
	var db_users []UserAuthRecord
	err1 := dynamodbattribute.UnmarshalListOfMaps(resp1.Items, &db_users)
	if err1 != nil {
		log.Fatalf("Error at unmarshaling user record: %s", err1)
		c.JSON(500, gin.H{"message": "Internal server error."})
		c.Abort()
	}
	db_user := db_users[0]
	err = bcrypt.CompareHashAndPassword([]byte(db_user.Password), []byte(user.Password))
	if err != nil {
		c.JSON(400, gin.H{"message": "Password is worng."})
		c.Abort()
	}
	access_token, err := generateToken(db_user.Sk)
	if err != nil {
		c.JSON(500, gin.H{"message": "Internal server error."})
		c.Abort()
	}
	data := RegisterResponse{AccessToken: access_token}
	c.JSON(200, data)

}

func main() {
	r := gin.Default()
	auth_required_endpints := r.Group("/")
	auth_required_endpints.Use(validateTokenMiddleware())
	auth_required_endpints.GET("/note/", getNotes)
	auth_required_endpints.POST("/note/", create)
	auth_required_endpints.PUT("/note/:note_id/", update)
	auth_required_endpints.DELETE("/note/:note_id/", delete)
	r.POST("/register/", registerUser)
	r.POST("/login/", loginUser)
	r.Run()
}
