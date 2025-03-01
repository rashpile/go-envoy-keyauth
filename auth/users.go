package auth

type User struct {
	Username string
	Key			string
}

type UsersSource interface {
	GetUser(username string) (*User, error)
}

//implement this interface to read users from file
//file format: username:key
