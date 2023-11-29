package pasetobackendadmin

import (
	"fmt"
	"testing"

	"github.com/aiteung/atdb"
	"github.com/whatsauth/watoken"
	"go.mongodb.org/mongo-driver/bson"
)

func TestCreateNewAdminRole(t *testing.T) {
	var admindata Admin
	admindata.Username = "admin"
	admindata.Password = "adminpass"
	admindata.Role = "admin"
	mconn := SetConnection("MONGOSTRING", "dbpakarbi")
	CreateNewAdminRole(mconn, "admin", admindata)
}

// func TestDeleteUser(t *testing.T) {
// 	mconn := SetConnection("MONGOSTRING", "pasabar13")
// 	var userdata User
// 	userdata.Username = "lolz"
// 	DeleteUser(mconn, "user", userdata)
// }

func CreateNewAdminToken(t *testing.T) {
	var admindata Admin
	admindata.Username = "admin"
	admindata.Password = "adminpass"
	admindata.Role = "admin"

	// Create a MongoDB connection
	mconn := SetConnection("MONGOSTRING", "dbpakarbi")

	// Call the function to create a user and generate a token
	err := CreateAdminAndAddToken("your_private_key_env", mconn, "admin", admindata)

	if err != nil {
		t.Errorf("Error creating admin and token: %v", err)
	}
}

func TestGFCPostHandlerAdmin(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "dbpakarbi")
	var admindata Admin
	admindata.Username = "admin"
	admindata.Password = "adminpass"
	admindata.Role = "admin"
	CreateNewAdminRole(mconn, "admin", admindata)
}

func TestGeneratePasswordHash(t *testing.T) {
	password := "testpass"
	hash, _ := HashPassword(password) // ignore error for the sake of simplicity

	fmt.Println("Password:", password)
	fmt.Println("Hash:    ", hash)
	match := CheckPasswordHash(password, hash)
	fmt.Println("Match:   ", match)
}
func TestGeneratePrivateKeyPaseto(t *testing.T) {
	privateKey, publicKey := watoken.GenerateKey()
	fmt.Println(privateKey)
	fmt.Println(publicKey)
	hasil, err := watoken.Encode("testpakarbi", privateKey)
	fmt.Println(hasil, err)
}

func TestHashFunction(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "dbpakarbi")
	var admindata Admin
	admindata.Username = "admin"
	admindata.Password = "testpass"

	filter := bson.M{"username": admindata.Username}
	res := atdb.GetOneDoc[Admin](mconn, "admin", filter)
	fmt.Println("Mongo User Result: ", res)
	hash, _ := HashPassword(admindata.Password)
	fmt.Println("Hash Password : ", hash)
	match := CheckPasswordHash(admindata.Password, res.Password)
	fmt.Println("Match:   ", match)

}

func TestIsPasswordValid(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "dbpakarbi")
	var admindata Admin
	admindata.Username = "admin"
	admindata.Password = "testpass"

	anu := IsPasswordValid(mconn, "admin", admindata)
	fmt.Println(anu)
}

func TestAdminFix(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "dbpakarbi")
	var admindata Admin
	admindata.Username = "admin"
	admindata.Password = "adminpass"
	admindata.Role = "admin"
	CreateAdmin(mconn, "admin", admindata)
}
