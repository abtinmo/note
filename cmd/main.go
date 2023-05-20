package main

import (
	jwtauth "github.com/abtinmo/note/pkg/auth"
	handlers "github.com/abtinmo/note/pkg/handler"

	"context"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"

	ginadapter "github.com/awslabs/aws-lambda-go-api-proxy/gin"
	"github.com/gin-gonic/gin"
)

var ginLambda *ginadapter.GinLambdaV2

func init() {
	r := gin.Default()
	auth_required_endpints := r.Group("/")
	auth_required_endpints.Use(jwtauth.ValidateTokenMiddleware())
	auth_required_endpints.GET("/note/", handlers.GetNotes)
	auth_required_endpints.POST("/note/", handlers.CreateNote)
	auth_required_endpints.PUT("/note/:note_id/", handlers.UpdateNote)
	auth_required_endpints.DELETE("/note/:note_id/", handlers.DeleteNote)
	r.POST("/register/", handlers.RegisterUser)
	r.POST("/login/", handlers.LoginUser)
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	ginLambda = ginadapter.NewV2(r)
}

func Handler(ctx context.Context, req events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	return ginLambda.ProxyWithContext(ctx, req)
}

func main() {
	lambda.Start(Handler)
}
