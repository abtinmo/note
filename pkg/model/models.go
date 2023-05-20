package models

type ErrorModel struct {
	Message string `json:"message"`
	Code    int
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
	Id         string `json:"sk"`
	Pk         string `json:"pk"`
	Title      string `json:"title" binding:"required"`
	Body       string `json:"body" binding:"required"`
	Tag        string `json:"tag,omitempty" binding:"required"`
	CreateDate string `json:"create_date,omitempty"`
	UpdateDate string `json:"update_date,omitempty"`
}

type NoteUpdate struct {
	Id         string
	UserId     string
	Title      string `json:"title" validate:"required"`
	Body       string `json:"body" validate:"required"`
	Tag        string `json:"tag,omitempty" validate:"required"`
	UpdateDate string
}

type NoteResponse struct {
	Count   int    `json:"count"`
	Results []Note `json:"results"`
}

type User struct {
	Pk       string `json:"pk" validate:"required"`
	Sk       string `json:"sk" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type UserAuthRequest struct {
	Password string `json:"password" validate:"required,email"`
	Username string `json:"username" validate:"required"`
}

type UserAccessToken struct {
	AccessToken string `json:"acces_token" validate:"required"`
}
