package database

import (
	"log"
	"os"

	models "github.com/abtinmo/note/pkg/model"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

var tableName = "NoteTaking"

func getDynamoSession() *dynamodb.DynamoDB {
	creds := credentials.NewEnvCredentials()
	sess, _ := session.NewSession(&aws.Config{
		Region:      aws.String(os.Getenv("AWS_REGION")),
		Credentials: creds,
	})
	return dynamodb.New(sess)
}

func CreateNote(note *models.NoteCreate) models.ErrorModel {
	av, err := dynamodbattribute.MarshalMap(note)
	if err != nil {
		log.Fatalf("Got error marshalling new note: %s", err)
		return models.ErrorModel{Message: "Internal server error.", Code: 500}
	}
	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String(tableName),
	}
	svc := getDynamoSession()
	_, err = svc.PutItem(input)
	if err != nil {
		log.Fatalf("Got error calling PutItem: %s", err)
		return models.ErrorModel{Message: "Internal server error.", Code: 500}
	}
	return models.ErrorModel{}
}

func UpdateNote(note *models.NoteUpdate) models.ErrorModel {
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
				S: aws.String(note.Pk),
			},
			"sk": {
				S: aws.String(note.Sk),
			},
		},
		ReturnValues:     aws.String("UPDATED_NEW"),
		UpdateExpression: aws.String("set title = :title, body = :body, tag = :tag, update_date = :update_date"),
	}
	svc := getDynamoSession()
	_, err1 := svc.UpdateItem(input)
	if err1 != nil {
		log.Fatalf("Error by updating note: %s", err1)
		return models.ErrorModel{Message: "Internal server error.", Code: 500}
	}
	return models.ErrorModel{}
}

func DeleteNote(userId string, NoteId string) models.ErrorModel {
	input := &dynamodb.DeleteItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			"pk": {
				S: aws.String(userId),
			},
			"sk": {
				S: aws.String(NoteId),
			},
		},
		TableName: aws.String(tableName),
	}
	svc := getDynamoSession()
	_, err := svc.DeleteItem(input)
	if err != nil {
		log.Fatalf("Error by deleting user from db: %s", err)
		return models.ErrorModel{Message: "Internal server error.", Code: 500}
	}
	return models.ErrorModel{}
}

func GetNotes(userId string) (models.NoteResponse, models.ErrorModel) {
	svc := getDynamoSession()
	var queryInput = &dynamodb.QueryInput{
		TableName: aws.String(tableName),
		KeyConditions: map[string]*dynamodb.Condition{
			"pk": {
				ComparisonOperator: aws.String("EQ"),
				AttributeValueList: []*dynamodb.AttributeValue{
					{
						S: aws.String(userId),
					},
				},
			},
		},
	}
	var resp1, err1 = svc.Query(queryInput)
	noteResponse := models.NoteResponse{}
	if err1 != nil {
		log.Fatalf("Error at geting user data from db: %s", err1)
		return noteResponse, models.ErrorModel{Message: "Internal server error.", Code: 500}
	}

	var notes []models.Note
	err := dynamodbattribute.UnmarshalListOfMaps(resp1.Items, &notes)
	if err != nil {
		log.Fatalf("Error at unmarshaling user record: %s", err1)
		return noteResponse, models.ErrorModel{Message: "Internal server error.", Code: 500}
	}
	return models.NoteResponse{Count: int(*resp1.Count), Results: notes}, models.ErrorModel{}
}

func GetUser(userName string) (*dynamodb.QueryOutput, error) {
	var queryInput = &dynamodb.QueryInput{
		TableName: aws.String(tableName),
		KeyConditions: map[string]*dynamodb.Condition{
			"pk": {
				ComparisonOperator: aws.String("EQ"),
				AttributeValueList: []*dynamodb.AttributeValue{
					{
						S: aws.String(userName),
					},
				},
			},
		},
	}
	svc := getDynamoSession()
	return svc.Query(queryInput)
}

func CreateUser(user *models.User) models.ErrorModel {
	av, err := dynamodbattribute.MarshalMap(user)
	if err != nil {
		log.Fatalf("Error at unmarshaling user record: %s", err)
		return models.ErrorModel{Message: "Internal server error.", Code: 500}
	}
	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String(tableName),
	}
	svc := getDynamoSession()
	_, err = svc.PutItem(input)
	if err != nil {
		log.Fatalf("Got error calling PutItem: %s", err)
		return models.ErrorModel{Message: "Internal server error.", Code: 500}
	}
	return models.ErrorModel{}
}
