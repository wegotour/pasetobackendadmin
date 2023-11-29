package pasetobackendadmin

import (
	"context"
	"fmt"
	"os"

	"github.com/aiteung/atdb"
	"github.com/whatsauth/watoken"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func GetConnectionMongo(MongoString, dbname string) *mongo.Database {
	MongoInfo := atdb.DBInfo{
		DBString: os.Getenv(MongoString),
		DBName:   dbname,
	}
	conn := atdb.MongoConnect(MongoInfo)
	return conn
}

func SetConnection(MONGOCONNSTRINGENV, dbname string) *mongo.Database {
	var DBmongoinfo = atdb.DBInfo{
		DBString: os.Getenv(MONGOCONNSTRINGENV),
		DBName:   dbname,
	}
	return atdb.MongoConnect(DBmongoinfo)
}

func CreateAdmin(mongoconn *mongo.Database, collection string, admindata Admin) interface{} {
	// Hash the password before storing it
	hashedPassword, err := HashPassword(admindata.Password)
	if err != nil {
		return err
	}
	privateKey, publicKey := watoken.GenerateKey()
	adminid := admindata.Username
	tokenstring, err := watoken.Encode(adminid, privateKey)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(tokenstring)
	// decode token to get adminid
	adminidstring := watoken.DecodeGetId(publicKey, tokenstring)
	if adminidstring == "" {
		fmt.Println("expire token")
	}
	fmt.Println(adminidstring)
	admindata.Private = privateKey
	admindata.Public = publicKey
	admindata.Password = hashedPassword

	// Insert the user data into the database
	return atdb.InsertOneDoc(mongoconn, collection, admindata)
}

func GetNameAndPassowrd(mongoconn *mongo.Database, collection string) []Admin {
	admin := atdb.GetAllDoc[[]Admin](mongoconn, collection)
	return admin
}

func CreateNewAdminRole(mongoconn *mongo.Database, collection string, admindata Admin) interface{} {
	// Hash the password before storing it
	hashedPassword, err := HashPassword(admindata.Password)
	if err != nil {
		return err
	}
	admindata.Password = hashedPassword

	// Insert the user data into the database
	return atdb.InsertOneDoc(mongoconn, collection, admindata)
}

func CreateAdminAndAddedToeken(PASETOPRIVATEKEYENV string, mongoconn *mongo.Database, collection string, admindata Admin) interface{} {
	// Hash the password before storing it
	hashedPassword, err := HashPassword(admindata.Password)
	if err != nil {
		return err
	}
	admindata.Password = hashedPassword

	// Insert the user data into the database
	atdb.InsertOneDoc(mongoconn, collection, admindata)

	// Create a token for the user
	tokenstring, err := watoken.Encode(admindata.Username, os.Getenv(PASETOPRIVATEKEYENV))
	if err != nil {
		return err
	}
	admindata.Token = tokenstring

	// Update the user data in the database
	return atdb.ReplaceOneDoc(mongoconn, collection, bson.M{"username": admindata.Username}, admindata)
}

func DeleteAdmin(mongoconn *mongo.Database, collection string, admindata Admin) interface{} {
	filter := bson.M{"username": admindata.Username}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}

func ReplaceOneDoc(mongoconn *mongo.Database, collection string, filter bson.M, admindata Admin) interface{} {
	return atdb.ReplaceOneDoc(mongoconn, collection, filter, admindata)
}

func FindAdmin(mongoconn *mongo.Database, collection string, admindata Admin) Admin {
	filter := bson.M{"username": admindata.Username}
	return atdb.GetOneDoc[Admin](mongoconn, collection, filter)
}

func IsPasswordValid(mongoconn *mongo.Database, collection string, admindata Admin) bool {
	filter := bson.M{"username": admindata.Username}
	res := atdb.GetOneDoc[Admin](mongoconn, collection, filter)
	return CheckPasswordHash(admindata.Password, res.Password)
}

func CreateAdminAndAddToken(privateKeyEnv string, mongoconn *mongo.Database, collection string, admindata Admin) error {
	// Hash the password before storing it
	hashedPassword, err := HashPassword(admindata.Password)
	if err != nil {
		return err
	}
	admindata.Password = hashedPassword

	// Create a token for the user
	tokenstring, err := watoken.Encode(admindata.Username, os.Getenv(privateKeyEnv))
	if err != nil {
		return err
	}

	admindata.Token = tokenstring

	// Insert the user data into the MongoDB collection
	if err := atdb.InsertOneDoc(mongoconn, collection, admindata.Username); err != nil {
		return nil // Mengembalikan kesalahan yang dikembalikan oleh atdb.InsertOneDoc
	}

	// Return nil to indicate success
	return nil
}

func InsertAdmindata(MongoConn *mongo.Database, username, role, password string) (InsertedID interface{}) {
	req := new(Admin)
	req.Username = username
	req.Password = password
	req.Role = role
	return InsertOneDoc(MongoConn, "admin", req)
}

func InsertOneDoc(db *mongo.Database, collection string, doc interface{}) (insertedID interface{}) {
	insertResult, err := db.Collection(collection).InsertOne(context.TODO(), doc)
	if err != nil {
		fmt.Printf("InsertOneDoc: %v\n", err)
	}
	return insertResult.InsertedID
}

func InsertAdmin(db *mongo.Database, collection string, admindata Admin) string {
	hash, _ := HashPassword(admindata.Password)
	admindata.Password = hash
	atdb.InsertOneDoc(db, collection, admindata)
	return "Username : " + admindata.Username + "\nPassword : " + admindata.Password
}
