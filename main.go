package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
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

func validateTokenMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		authorizationHeader := req.Header.Get("authorization")
		if authorizationHeader != "" {
			bearerToken := strings.Split(authorizationHeader, " ")
			if len(bearerToken) == 2 {
				token, error := jwt.Parse(bearerToken[1], func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("There was an error")
					}
					return getKey(), nil
				})
				if error != nil {
					w.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(w).Encode(ErrorMsg{Message: error.Error()})
					return
				}
				if token.Valid {
					ctx := req.Context()
					req := req.WithContext(context.WithValue(ctx, "claims", token.Claims))
					next(w, req)
				} else {
					w.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(w).Encode(ErrorMsg{Message: "Invalid authorization token"})
				}
			} else {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(ErrorMsg{Message: "Invalid authorization token"})
			}
		} else {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorMsg{Message: "An authorization header is required"})
		}
	})
}

func create(w http.ResponseWriter, r *http.Request) {
	uuid := ksuid.New()
	user_id := r.Context().Value("claims").(jwt.MapClaims)["user_id"].(string)
	user_notes := fmt.Sprintf("NOTE#%v", user_id)
	now_time := time.Now().UTC()
	note := NoteCreate{
		Id:         uuid.String(),
		Pk:         user_notes,
		CreateDate: now_time.String(),
		UpdateDate: now_time.String(),
	}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&note)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorMsg{Message: err.Error()})
		return
	}
	svc := getDynamoSession()

	av, err := dynamodbattribute.MarshalMap(note)
	if err != nil {
		log.Fatalf("Got error marshalling new note: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String(tableName),
	}

	_, err = svc.PutItem(input)
	if err != nil {
		log.Fatalf("Got error calling PutItem: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
}

func update(w http.ResponseWriter, r *http.Request) {
	user_id := r.Context().Value("claims").(jwt.MapClaims)["user_id"].(string)
	user_notes := fmt.Sprintf("NOTE#%v", user_id)
	note_id := r.URL.Query().Get("note_id")
	now_time := time.Now().UTC()
	note := NoteUpdate{
		UpdateDate: now_time.String(),
	}
	decoder := json.NewDecoder(r.Body)
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
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func delete(w http.ResponseWriter, r *http.Request) {
	user_id := r.Context().Value("claims").(jwt.MapClaims)["user_id"].(string)
	user_notes := fmt.Sprintf("NOTE#%v", user_id)
	note_id := r.URL.Query().Get("note_id")

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
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
	w.Header().Set("Content-Type", "application/json")
}

func get(w http.ResponseWriter, r *http.Request) {
	user_id := r.Context().Value("claims").(jwt.MapClaims)["user_id"].(string)
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
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var notes []Note
	err := dynamodbattribute.UnmarshalListOfMaps(resp1.Items, &notes)
	if err != nil {
		log.Fatalf("Error at unmarshaling user record: %s", err1)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	data := NoteResponse{Count: int(*resp1.Count), Results: notes}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(data)
	w.Header().Set("Content-Type", "application/json")
}

func registerUser(w http.ResponseWriter, r *http.Request) {
	// get username and password and register the user, return access token in response
	var user UserRegisterRequest
	decoder := json.NewDecoder(r.Body)
	decoder.Decode(&user)
	//validate.Struct(user)
	password := []byte(user.Password)

	// Hashing the password with the default cost of 10
	hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Can not generate hashed password: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
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
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if *resp1.Count > 0 {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(ErrorMsg{Message: "User already exists."})
		return
	}
	fmt.Println(err1)
	av, err := dynamodbattribute.MarshalMap(&userRecord)
	if err != nil {
		log.Fatalf("Error at unmarshaling user record: %s", err1)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String(tableName),
	}

	_, err = svc.PutItem(input)
	if err != nil {
		fmt.Printf("Got error calling PutItem: %s", err)
	}
	access_token, err := generateToken(uuid.String())
	if err != nil {
		log.Fatalf("Can not create jwt token: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	data := RegisterResponse{AccessToken: access_token}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(data)
}

func loginUser(w http.ResponseWriter, r *http.Request) {
	var user UserRegisterRequest
	decoder := json.NewDecoder(r.Body)
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
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if *resp1.Count <= 0 {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorMsg{Message: "User not found."})
		return
	}
	type UserAuthRecord struct {
		Sk       string `json:"sk" validate:"required"`
		Password string `json:"password" validate:"required"`
	}
	var db_users []UserAuthRecord
	err1 := dynamodbattribute.UnmarshalListOfMaps(resp1.Items, &db_users)
	if err1 != nil {
		log.Fatalf("Error at unmarshaling user record: %s", err1)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	db_user := db_users[0]
	err = bcrypt.CompareHashAndPassword([]byte(db_user.Password), []byte(user.Password))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorMsg{Message: "Wrong Password."})
		return
	}
	access_token, err := generateToken(db_user.Sk)
	if err != nil {
		log.Fatalf("Can not create jwt token: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	data := RegisterResponse{AccessToken: access_token}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func main() {
	http.HandleFunc("/register", registerUser)
	http.HandleFunc("/login", loginUser)
	http.HandleFunc("/get", validateTokenMiddleware(get))
	http.HandleFunc("/create", validateTokenMiddleware(create))
	http.HandleFunc("/update", validateTokenMiddleware(update))
	http.HandleFunc("/delete", validateTokenMiddleware(delete))

	err := http.ListenAndServe(":3333", nil)
	if err != nil {
		os.Exit(1)
	}
}
