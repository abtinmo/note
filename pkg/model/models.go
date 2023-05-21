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
	Pk         string `json:"pk" binding:"required,startswith=NOTE#"`
	Title      string `json:"title" binding:"required"`
	Body       string `json:"body" binding:"required"`
	Tag        string `json:"tag,omitempty" binding:"required"`
	CreateDate string `json:"create_date"`
	UpdateDate string `json:"update_date"`
}

type NoteUpdate struct {
	Sk         string `json:"id"`
	Pk         string `json:"pk" binding:"required,startswith=NOTE#"`
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
	Pk       string `json:"pk" binding:"required,startswith=USERNAME#"`
	Sk       string `json:"sk" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type UserAuthRequest struct {
	Password string `json:"password" binding:"required,min=8,max=255"`
	Username string `json:"username" binding:"required,email"`
}

type UserAccessToken struct {
	AccessToken string `json:"acces_token"`
}
