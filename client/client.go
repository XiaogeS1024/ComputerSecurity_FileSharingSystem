package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	"strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID)

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

func concat(head []byte, foot []byte) []byte {
	head = append(head, foot...)
	return head
}

//整型转换成字节
func IntToBytes(n int) (arr []byte) {

	var str string = strconv.Itoa(n)

	foot := []byte{0}

	arr = []byte(str)

	var length int = len(arr)

	for i := 0; i < 8; i++ {
		if length <= i {
			arr = append(arr, foot...)
		}
	}
	return arr
}

//字节转换成整型
func BytesToInt(b []byte) int {

	var arr []byte
	for i := 0; i < 8; i++ {
		if b[i] == 0 {
			break
		}
		arr = append(arr, b[i:i+1]...)

	}

	byteToInt, _ := strconv.Atoi(string(arr))

	return byteToInt
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username            []byte
	Password_plain_text []byte
	Password            []byte //这个是pbkdf的
	PKlockbox           userlib.PublicKeyType
	SKlockbox           userlib.PrivateKeyType

	Pbkdf    []byte
	Signkey  userlib.DSSignKey
	FileList map[string]File
	//AccessFileList map[string]File //这里的file是不是应该是mailbox？ //delete
	//mailbox
	//下面这个：第一个string是filename，而第二个是接收者的name：LockBox
	//mail的信息在lockbox里面
	//CreatorMailBox map[string]map[string]LockBox //该用户是创建者时候去使用 //delete
	AccessMailBox map[string]LockBox ///将文件名和它对应的mailbox对应上了。
	Children      map[string][]string
	// ClientList   []string
	// IdentityCode string

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when thi s struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}
type FileInfo struct {
	ChangeNum uint
	TotalSize uint
}
type File struct {
	FileUUID uuid.UUID
	InfoUUID uuid.UUID
	Owner    []byte
	EncKey   []byte
	MacKey   []byte
	//下面不仅要有用户名，还要有对应的lockbox的uuid，前者为了函数的调用，后者为了进行操作。
	//Children map[string]string
	//下面就是创建者直接相连的用户

}
type MACPair struct {
	Content []byte
	MAC     []byte
}

// type Share_info struct {
// 	location uuid.UUID
// 	file_key []byte
// }

type LockBox struct {
	MailboxUUID uuid.UUID
	Hkey        []byte //产生mailbox的Hmac的Hkey，用来保障mailbox的完整性
	SymKey      []byte //产生mailbox用来对称加密的key，用来保障mailbox的加密性
}

type EnLockBox struct {
	Enlockbox []byte
	Sig       []byte
}

//如果需要添加内容，就往mailbox里面添加就可以
type MailBox struct {
	FileUUID     uuid.UUID
	FileInfoUUID uuid.UUID
	Owner        []byte
	Hkey         []byte //产生file的Hmac的Hkey，用来保障mailbox的完整性
	SymKey       []byte //产生file用来对称加密的key，用来保障mailbox的加密性
}
type EnMailBox struct {
	Enmailbox []byte
	Sig       []byte
}

func (userdata *User) UpdataUserInfo() error {
	marshalledUser, err := json.Marshal(&userdata)
	if err != nil {
		panic(err)
	}

	//Use password generated by PBKDF as the EncKey
	encedUser := userlib.SymEnc(userdata.Password[:userlib.AESKeySizeBytes], userlib.RandomBytes(userlib.AESBlockSizeBytes), marshalledUser)

	//HMAC the encrypted data. Use password generated by PBKDF as the HMACKey
	HMACKey := userdata.Password[:userlib.AESKeySizeBytes]
	pairHMAC, err := userlib.HMACEval(HMACKey, encedUser)
	if err != nil {
		panic(err)
	}
	HMACPair := MACPair{encedUser, pairHMAC}

	//Set the location(key) in the DS
	HMACedUsername, err := userlib.HMACEval(HMACKey, []byte(userdata.Username))
	if err != nil {
		panic(err)
	}
	location, err := uuid.FromBytes(HMACedUsername[:16])
	if err != nil {
		panic(err)
	}

	//Marshal the HMAC pair and set it as the value in the DS
	value, err := json.Marshal(HMACPair)
	if err != nil {
		panic(err)
	}

	userlib.DatastoreSet(location, value)
	return nil
}

//Store created FileInfo in DataStore
func (userdata *User) StoreFileInfo(filename string, fileInfo *FileInfo) {

	// permission check
	var isOwner bool
	var file File
	var err error
	file, isOwner = userdata.FileList[filename]
	if !isOwner {
		mailbox := userdata.AccessMailBox[filename]
		file, err = LockboxToFile(mailbox)
		if err != nil {
			panic("LockboxToFile err")
		}
	}

	// Marshal fileInfo
	marshalledInfo, err := json.Marshal(fileInfo)
	if err != nil {
		panic(err)
	}

	// Do we need to encrypt the marshalled fileInfo to guarantee confidentiality?
	//No need, for fileInfo doesn't include infomation about file's content or filename.

	// Set the HMAC pair
	pairHMAC, err := userlib.HMACEval(file.MacKey, marshalledInfo)
	if err != nil {
		panic(err)
	}
	HMACPair := MACPair{marshalledInfo, pairHMAC}

	//Set the location(key) in the DS, using UUID
	location := file.InfoUUID
	if err != nil {
		panic(err)
	}

	//Marshal the HMAC pair and set it as the value in the DS
	value, err := json.Marshal(HMACPair)
	if err != nil {
		panic("json marshal err")
	}
	userlib.DatastoreSet(location, value)
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

	if username == "" {
		return &userdata, errors.New("username can't be null")
	}
	username_loc := userlib.Hash([]byte(username))[:16]
	username_loc1, err := uuid.FromBytes(username_loc)

	_, ok := userlib.DatastoreGet(username_loc1)
	if ok {
		return &userdata, errors.New("username has exsit")
	}

	userdata.Username = []byte(username)
	userdata.Password_plain_text = []byte(password)
	userdata.Password = userlib.Argon2Key([]byte(userdata.Password_plain_text), []byte(username), uint32(userlib.AESKeySizeBytes))
	userdata.Pbkdf = userlib.Argon2Key(userdata.Password_plain_text, userdata.Username, 16)

	//Generate the RSA Key Pair
	var pk1 userlib.PKEEncKey
	var sk1 userlib.PKEDecKey
	pk1, sk1, _ = userlib.PKEKeyGen()
	userdata.PKlockbox = pk1
	userdata.SKlockbox = sk1

	//Generate the RSA Key Pair for DS
	// var pk2 userlib.DSVerifyKey
	// var sk2 userlib.DSSignKey
	// sk2, pk2, _ = userlib.DSKeyGen()
	// userdata.PK2 = pk2
	// userdata.SK2 = sk2

	userdata.FileList = make(map[string]File)
	userdata.AccessMailBox = make(map[string]LockBox)
	userdata.Children = make(map[string][]string)
	//userdata.AccessFileList = make(map[string]File)
	//PKlockbox
	userlib.KeystoreSet(username+"PKlockbox", userdata.PKlockbox)
	// userlib.KeystoreSet(username+"0", userdata.PK2)

	//Marshal then Encrypt then HMAC the created user
	err = userdata.UpdataUserInfo()
	if err != nil {
		return &userdata, errors.New("broken")
	}
	userlib.DatastoreSet(username_loc1, []byte(username))
	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	name := []byte(username)

	//Use username and password to generate the stored password, then generate the EncKey and HMACKey
	pw := userlib.Argon2Key([]byte(password), []byte(username), uint32(userlib.AESKeySizeBytes))
	encKey := pw[:userlib.AESKeySizeBytes]
	hmacKey := pw[:userlib.AESKeySizeBytes]

	//Get the location where the user is stored in DataStore
	hmacedName, err := userlib.HMACEval(hmacKey, []byte(name))
	if err != nil {
		return userdataptr, errors.New("broken")
	}
	location, err := uuid.FromBytes(hmacedName[:16])
	if err != nil {
		return userdataptr, errors.New("broken")
	}

	//Get the value using function DatastoreGet()
	value, ok := userlib.DatastoreGet(location)
	if !ok {
		return userdataptr, errors.New("broken")
	}
	var hmacPair MACPair

	//Unmarshal the value to get the HMACPair
	if json.Unmarshal(value, &hmacPair) != nil {
		return userdataptr, errors.New("broken")
	}

	//Validate the HMAC Pair
	correctHMAC, err := userlib.HMACEval(hmacKey, hmacPair.Content)
	if err != nil {
		return userdataptr, errors.New("broken")
	}
	if !(userlib.HMACEqual(hmacPair.MAC, correctHMAC)) {
		return userdataptr, errors.New("broken")
	}

	//Decrypt to get the marshalled data
	marshalledContent := userlib.SymDec(encKey, hmacPair.Content)

	//Unmarshal to get the userdata
	var userdata User
	err = json.Unmarshal(marshalledContent, &userdata)
	if err != nil {
		panic(err)
	}
	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	var file File
	fileNum, err := json.Marshal(0)
	userdata, err = GetUser(string(userdata.Username), string(userdata.Password_plain_text))
	if err != nil {
		return errors.New("broken")
	}

	//Associate the created file with the owner(user)
	for k, _ := range userdata.AccessMailBox {
		if k == filename {
			//如果已经被撤销权限了，那么accessmailbox里面也清空
			mailbox := userdata.AccessMailBox[filename]
			file, err := LockboxToFile(mailbox)
			if err != nil {
				delete(userdata.AccessMailBox, k)
			} else { //代表还能访问前文件
				EncedContent := userlib.SymEnc(file.EncKey, userlib.RandomBytes(userlib.AESBlockSizeBytes), content)
				var arr []byte
				arr = make([]byte, len(EncedContent))
				copy(arr, EncedContent)
				arr = concat(arr, fileNum)

				fileDataHMACPart, err := userlib.HMACEval(file.MacKey, arr)
				if err != nil {
					panic(err)
				}

				fileData := concat(concat(fileDataHMACPart, IntToBytes(len(EncedContent))), EncedContent)
				userlib.DatastoreSet(file.FileUUID, fileData)
				var fileinfo FileInfo
				fileinfo.ChangeNum = 1
				userdata.StoreFileInfo(filename, &fileinfo)

				return err

			}
		}
	}

	//Generate random EncKey and HMACKey for the file
	//file.UUID, err = uuid.FromBytes( userlib.Hash( concat(fileNum, concat(userlib.Hash(userlib.Hash([]byte(userdata.Username))), userdata.Username))   )              [:16])

	for j, _ := range userdata.FileList {
		if j == filename {
			file = userdata.FileList[filename]
			EncedContent := userlib.SymEnc(file.EncKey, userlib.RandomBytes(userlib.AESBlockSizeBytes), content)
			var arr []byte
			arr = make([]byte, len(EncedContent))
			copy(arr, EncedContent)
			arr = concat(arr, fileNum)

			fileDataHMACPart, err := userlib.HMACEval(file.MacKey, arr)
			if err != nil {
				panic(err)
			}

			fileData := concat(concat(fileDataHMACPart, IntToBytes(len(EncedContent))), EncedContent)
			userlib.DatastoreSet(file.FileUUID, fileData)
			var fileinfo FileInfo
			fileinfo.ChangeNum = 1
			userdata.StoreFileInfo(filename, &fileinfo)

			return err

		}

	}

	file.InfoUUID = uuid.New()
	file.Owner = userdata.Username
	file.EncKey = userlib.RandomBytes(16)
	file.MacKey = userlib.RandomBytes(16)

	if err != nil {
		return err
	}
	location := uuid.New()
	file.FileUUID = location
	if err != nil {
		return err
	}

	userdata.FileList[filename] = file

	//Encrypt the content
	EncedContent := userlib.SymEnc(file.EncKey, userlib.RandomBytes(userlib.AESBlockSizeBytes), content)

	//Create FileInfo to record the file's relevant information including how many times it has been changed and the changed length each time
	//The default value are 1 and len(content) respectively
	var fileInfo FileInfo
	fileInfo.TotalSize = uint(len(EncedContent))
	fileInfo.ChangeNum = 1
	//fileInfo.ChangeSize = []uint{uint(len(EncedContent))}

	//Call StoreFileInfo() to store fileInfo in DataStore
	userdata.StoreFileInfo(filename, &fileInfo)

	//Store file content

	var arr []byte
	arr = make([]byte, len(EncedContent))
	copy(arr, EncedContent)
	arr = concat(arr, fileNum)

	fileDataHMACPart, err := userlib.HMACEval(file.MacKey, arr)
	if err != nil {
		panic(err)
	}

	fileData := concat(concat(fileDataHMACPart, IntToBytes(len(EncedContent))), EncedContent)

	userlib.DatastoreSet(location, fileData)
	err = userdata.UpdataUserInfo()
	if err != nil {
		return errors.New("broken")
	}

	return err
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	var err error
	userdata, err = GetUser(string(userdata.Username), string(userdata.Password_plain_text))

	if err != nil {
		return errors.New("broken")
	}
	// permission check
	var isOwner bool
	var file File
	file, isOwner = userdata.FileList[filename]

	if !isOwner {
		mailbox := userdata.AccessMailBox[filename]
		file, err = LockboxToFile(mailbox)
		if err != nil {
			return errors.New("broken")
		}
	}

	EncedContent := userlib.SymEnc(file.EncKey, userlib.RandomBytes(userlib.AESBlockSizeBytes), content)

	file_length := uint(len(EncedContent))

	// Load fileInfo
	var fileInfo FileInfo
	//Get the location where the fileInfo is stored in DataStore
	location := file.InfoUUID

	//Get the value using function DatastoreGet()
	//before := userlib.DatastoreGetBandwidth()
	value, ok := userlib.DatastoreGet(location)
	//after := userlib.DatastoreGetBandwidth()

	//fmt.Println("after - before:", after-before)
	// fmt.Println("value", value)
	if !ok {
		return errors.New("broken")
	}
	var HMACPair MACPair

	//Unmarshal the value to get the HMACPair
	err = json.Unmarshal(value, &HMACPair)
	if err != nil {
		return errors.New("broken")
	}

	//Validate the HMAC Pair
	correctHMAC, err := userlib.HMACEval(file.MacKey, HMACPair.Content)
	if err != nil {
		panic(err)
	}
	if !(userlib.HMACEqual(HMACPair.MAC, correctHMAC)) {
		return errors.New("broken")
	}

	//Unmarshal to get the fileInfo
	err = json.Unmarshal(HMACPair.Content, &fileInfo)
	if err != nil {
		return errors.New("broken")
	}

	// Get fileNum from fileInfo and determine the next fileNum
	fileNum, err := json.Marshal(fileInfo.ChangeNum)
	if err != nil {
		panic(err)
	}

	var arr []byte
	arr = make([]byte, file_length)
	copy(arr, EncedContent)
	arr = concat(arr, fileNum)

	fileDataHMACPart, err := userlib.HMACEval(file.MacKey, arr)
	if err != nil {
		panic(err)
	}

	// Update FileInfo fields and store
	fileInfo.TotalSize += file_length
	fileInfo.ChangeNum++
	//fileInfo.ChangeSize = append(fileInfo.ChangeSize, file_length)

	// Store new fileNode
	fileData := concat(concat(fileDataHMACPart, IntToBytes(len(EncedContent))), EncedContent)
	file_uuid, err := json.Marshal(file.FileUUID)
	if err != nil {
		panic("json marshal err")
	}
	location, err = uuid.FromBytes(userlib.Hash(concat(fileNum, concat(userlib.Hash(userlib.Hash([]byte(file.Owner))), file_uuid)))[:16])
	if err != nil {
		return err
	}
	_, ok = userlib.DatastoreGet(location)
	if ok { //||bytes.Equal(value_chunck, []byte("Access has been revoked"))
		fileInfo.ChangeNum--
		return errors.New("Access has been revoked")

	}
	userlib.DatastoreSet(location, fileData)
	userdata.StoreFileInfo(filename, &fileInfo)
	//Updata user info
	err = userdata.UpdataUserInfo()
	if err != nil {
		panic("Updata User Info error")
	}

	return err
	//return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// permission check
	var isOwner bool
	var file File
	//同步
	userdata, err = GetUser(string(userdata.Username), string(userdata.Password_plain_text))
	if err != nil {
		return []byte("broken"), errors.New("broken getuser")
	}
	//下面这一行应该要加一个判断，如果不是Owner，那么需要从Access里面获得mailbox，然后进行加载。
	file, isOwner = userdata.FileList[filename]
	if !isOwner {
		mailbox := userdata.AccessMailBox[filename]
		file, err = LockboxToFile(mailbox)
		if err != nil {
			delete(userdata.AccessMailBox, filename)
			return []byte("broken"), errors.New("broken locktofile")
		}

	}

	// Load fileInfo
	var fileInfo FileInfo
	fileInfo, err = GetFileInfo(file.InfoUUID, file.MacKey)
	if err != nil {
		return []byte("broken"), errors.New("broken loadfileinfo")
	}
	//Use fileInfo to get the file content
	for i := 0; i < int(fileInfo.ChangeNum); i++ {
		fileNum, err := json.Marshal(i)
		if err != nil {
			panic(err)
		}
		file_uuid, err := json.Marshal(file.FileUUID)
		if err != nil {
			panic("json marshal err")
		}
		location, err := uuid.FromBytes(userlib.Hash(concat(fileNum, concat(userlib.Hash(userlib.Hash([]byte(file.Owner))), file_uuid)))[:16])
		if err != nil {
			panic("uuid generation err")
		}
		if i == 0 {
			location = file.FileUUID
		}

		value, ok := userlib.DatastoreGet(location)

		if !ok {
			return []byte("err"), errors.New("err dsGet")
		}

		// pos := int(fileInfo.changeSize[i])
		// step := index + userlib.HashSizeBytes
		fileDataHMACPart := value[0:userlib.HashSizeBytes]
		fileLength := value[userlib.HashSizeBytes : userlib.HashSizeBytes+8]
		encedContent := value[userlib.HashSizeBytes+8:]

		//Validate the HMAC
		var arr []byte
		arr = make([]byte, BytesToInt(fileLength))
		copy(arr, encedContent)
		arr = concat(arr, fileNum)

		correctFileDataHMACPart, err := userlib.HMACEval(file.MacKey, arr)
		if err != nil {
			panic("Hmac generate err")
		}
		if !(userlib.HMACEqual(fileDataHMACPart, correctFileDataHMACPart)) {
			return []byte("broken"), errors.New("broken hamc")
		}

		//Decrypt
		partialContent := userlib.SymDec(file.EncKey, encedContent)
		content = concat(content, partialContent)

	}

	return content, err
}
func LockboxToFile(lockbox LockBox) (filestruct File, err error) {

	//因为mailbox是会进行更新的，所以希望每次访问的时候进行下面的操作。检查mailbox是否更新。
	//不存储到FileList里面，只存储到AccessMailBox里面。
	//那么在FileList里面的文件，都是自己创建的；在AccessMailBox里面的，都是有权限访问的。
	//然后在file的struct里面有一个children来放直接相连的所有孩子
	//???移动？  或者作为helper funciton， 传入lockbox，返回file struct
	//mailbox
	var enmailboxByte []byte
	var mailbox MailBox
	var file File

	mailbox_UUID := lockbox.MailboxUUID
	enmailboxByte, ok := userlib.DatastoreGet(mailbox_UUID)
	if !ok {
		return file, errors.New("broken")
	}

	var enmailbox EnMailBox
	err = json.Unmarshal(enmailboxByte, &enmailbox)
	if err != nil {
		return file, errors.New("broken")
	}
	//HMAC integrity check 加密的mailbox
	var hmac []byte
	hmac, err = userlib.HMACEval(lockbox.Hkey, enmailbox.Enmailbox)
	if err != nil {
		panic(err)
	}
	equal := userlib.HMACEqual(hmac, enmailbox.Sig)
	if !equal {
		return file, errors.New("broken")
	}

	//decrypte mailbox
	mailboxByte := userlib.SymDec(lockbox.SymKey, enmailbox.Enmailbox)

	err = json.Unmarshal(mailboxByte, &mailbox)
	if err != nil {
		return file, errors.New("broken")
	}
	//下面对mailbox里面的内容进行处理
	//即将mailbox里面的内容存储到file结构中
	//这里的报错也是不能改map的值
	file.FileUUID = mailbox.FileUUID
	file.InfoUUID = mailbox.FileInfoUUID
	file.EncKey = mailbox.SymKey
	file.MacKey = mailbox.Hkey
	file.Owner = mailbox.Owner
	//上面存储进来了，应该就算是完成了。即接受了邀请
	return file, nil
}
func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	/*修改：Time：4/8/2022 19:00 comment：add a layer "mailbox"
	1）之前写的lockbox里面不再是放file的信息，而是放中间层mailbox的信息
	2）lockbox:包含mailbox的UUID、Hkey,sym_key.
	   UUID: location
	   Hkey: key of HMAC to intergation and auth
	   sym_key:key of Symmetric Encryption to encrypt
	3) 加密和签名1）中文件。
	   encryte file in 1) encrypted with sender's pk,
	   and sign this file by invitee's sk
	   then send this file's uuid
	4) contents in mailbox: UUID of file, sym_key of file, Hmac of file
	5)如果不是创建者发起的邀请，就只需要将2）中的mailbox，再执行一遍3）的步骤，然后uuid方式发送就行。
	  如果是创建者，那就需要再创建一个新的mailbox去指向了，内容倒是不会改变。4）中的信息，需要是最新的。
	6）撤回时候：对file进行更换uuid以及重新加密；更改剩余的user所指向的mailbox中的key和uuid信息。
	   Q: creator如何管理自己的mailbox呢？通过 user里面的结构去获得mailbox的相关信息。
	   那如何通过revoke的接收对象的那个参数去确定要放弃哪个?
	   A: 我应该在user里面存储，它创建的file、直接相连的user：其对应的mailbox地址。
	   同时，每个user里面也应该储存他们有权访问的mailbox以及对应的key，作为一个map

	*/
	//同步userdata
	userdata, err = GetUser(string(userdata.Username), string(userdata.Password_plain_text))
	if err != nil {
		return invitationPtr, errors.New("broken")
	}
	//一、获取或者创建lockbox
	//1、如果是creator，那么需要先建立mailbox, 然后再让lockbox指向这个mailbox
	//??? 这里记得完善如何确定是不是creator

	var lockbox LockBox
	var isOwner bool
	_, isOwner = userdata.FileList[filename]
	if isOwner {
		//产生一个mailbox
		//uuid
		uuid_string := string(userlib.Hash([]byte(userdata.Username))) + string(userlib.Hash([]byte(recipientUsername))) + string(userlib.Hash([]byte(filename)))
		uuid_hash := userlib.Hash([]byte(uuid_string))
		lockbox.MailboxUUID, err = uuid.FromBytes(uuid_hash[:16])

		if err != nil {
			panic("uuid generate err")
		}
		lockbox.Hkey, lockbox.SymKey, err = userdata.CreateMailBox(filename, recipientUsername, lockbox.MailboxUUID)
		if err != nil {
			return invitationPtr, errors.New("broken")
		}
		//添加子用户
		userdata.Children[filename] = append(userdata.Children[filename], recipientUsername)
		err = userdata.UpdataUserInfo()
		if err != nil {
			panic("Updata User Info error")
		}
	} else {
		lockbox = userdata.AccessMailBox[filename]
	}
	//这里是想要获取到用户已经有的MaiBox
	//mailbox应该存储在用户的user结构里面吧
	//？？？如何获取？根据文件名吧

	//二、对lockbox加密，用接收方的公钥
	_, ok := userlib.DatastoreGet(lockbox.MailboxUUID)
	if !ok {
		return invitationPtr, errors.New("revoke")
	}

	var enlockbox EnLockBox
	pk, ok := userlib.KeystoreGet(recipientUsername + "PKlockbox")
	if !ok {
		return invitationPtr, errors.New("broken")
	}

	lockboxByte, err := json.Marshal(lockbox)
	if err != nil {
		panic(err)
	}
	enlockbox.Enlockbox, err = userlib.PKEEnc(pk, lockboxByte)
	if err != nil {
		panic(err)
	}
	//三、进行signature
	//???这里的私钥也要改进一下
	//生成一个新的签名密钥对，存储到keystore中，存储时候用到的location："sign"+sender+invitee，也就是两个用户之间，不管多少文件，都用这一个skey。
	//但是，如果两个用户不是第一次共享，也就是说keystore里面已经有值了，需要进行一个验证，有值了，就不要再往里面存储了，直接get就可
	//这里是对所有文件用一个
	//???? 下面这个签名的私钥对生成，是否应该放在InitUser里面，然后就直接从中获取userdata.Signkey呗
	location_sign_verifykey := string(userlib.Hash([]byte("sign_lockbox"))) + string(userlib.Hash([]byte(userdata.Username))) //+ string(userlib.Hash([]byte(recipientUsername)))
	_, ok = userlib.KeystoreGet(location_sign_verifykey)

	//如果已经有了，就直接从userdata里面获取私钥就可以
	var sk userlib.DSSignKey
	if ok {
		sk = userdata.Signkey
	} else {
		//生成新的key pair
		var sign_verifykey userlib.DSVerifyKey
		//把签名的Signkey存储到了。但是Signkey面对不同的用户应该是不一样的？那就需要一个map？接受方的username：发送方的signname
		userdata.Signkey, sign_verifykey, err = userlib.DSKeyGen()
		if err != nil {
			panic(err)
		}
		sk = userdata.Signkey
		//存储keypair
		err = userlib.KeystoreSet(location_sign_verifykey, sign_verifykey)
		if err != nil {
			panic(err)
		}
	}

	enlockbox.Sig, err = userlib.DSSign(sk, enlockbox.Enlockbox)
	if err != nil {
		return invitationPtr, errors.New("broken")
	}
	enlockboxByte, err := json.Marshal(enlockbox)
	if err != nil {
		return invitationPtr, errors.New("broken")
	}
	//四、生成uuid，存储到ds，然后return这个uuid给接收方
	uuid_enlockbox := uuid.New()
	userlib.DatastoreSet(uuid_enlockbox, enlockboxByte)
	//这里会不会有bug？
	invitationPtr = uuid_enlockbox
	//Updata user info
	err = userdata.UpdataUserInfo()
	if err != nil {
		panic("Updata User Info error")
	}
	return invitationPtr, err

}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	/*修改：Time：4/8/2022 19:00 comment：add a layer "mailbox"
	1、获得lockbox
	2、验证+解码，然后存储到access那个列表里面。然后获得mailbox，
	3、对mailbox，进行验证和解码
	4、将3中得到的内容存储到file结构
	*/
	var enlockbox EnLockBox
	//同步userdata
	userdata, err := GetUser(string(userdata.Username), string(userdata.Password_plain_text))
	if err != nil {
		return errors.New("broken getuser")
	}
	for k, _ := range userdata.FileList {
		if k == filename {
			return errors.New("filename repeate")
		}
	}
	for k, _ := range userdata.AccessMailBox {
		if k == filename {
			//如果已经被撤销权限了，那么accessmailbox里面也清空
			mailbox := userdata.AccessMailBox[filename]
			_, err := LockboxToFile(mailbox)
			if err != nil {
				delete(userdata.AccessMailBox, k)
				//return errors.New("broken")
			} else { //代表还能访问前文件
				return errors.New("filename repeate")
			}
			// _, ok := userlib.DatastoreGet(old_filestruct.FileUUID)
			// if !ok { //代表，已经被撤销权限了
			// 	delete(userdata.AccessMailBox, k)
			// } else { //代表还能访问前文件
			// 	return errors.New("filename repeate")
			// }
		}
	}
	//1、获取lockbox
	enlockboxByte, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("broken get error")
	}
	json.Unmarshal(enlockboxByte, &enlockbox)
	//这里进行数字签名的认证
	location_sign_verifykey := string(userlib.Hash([]byte("sign_lockbox"))) + string(userlib.Hash([]byte(senderUsername))) //+ string(userlib.Hash([]byte(userdata.Username)))
	sign_verifykey, ok := userlib.KeystoreGet(location_sign_verifykey)
	if !ok {
		return errors.New("broken sign_verifykey")
	}
	err = userlib.DSVerify(sign_verifykey, enlockbox.Enlockbox, enlockbox.Sig)

	if err != nil {
		return errors.New("broken sign verify")
	}
	//这里进行解码，用的userdata里面的SKlockbox
	lockboxByte, err := userlib.PKEDec(userdata.SKlockbox, enlockbox.Enlockbox)
	if err != nil {
		return errors.New("broken decrypt")
	}
	var lockbox LockBox
	err = json.Unmarshal(lockboxByte, &lockbox)
	if err != nil {
		return errors.New("broken unmarshal")
	}

	//如果被撤回了，那么mailbox位置也被清理了，所以可以由这里判断是否被撤回了
	_, ok = userlib.DatastoreGet(lockbox.MailboxUUID)
	if !ok {
		return errors.New("revoke dsget")
	}

	//!!!这里的想法是：下面这些都放在loadfile里面进行。而将这个lockbox存储到user.AccessMailBox就可以了
	//得到的lockbox是空的？
	userdata.AccessMailBox[filename] = lockbox

	//Updata user info
	err = userdata.UpdataUserInfo()
	if err != nil {
		panic("Updata User Info error")
	}

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	//分为对文件的更改：更换UUID和重新存储
	//对剩余用户所指向的mailbox里面的内容进行更改。
	//那用户每次loadfile的时候，是需要重新从mailbox里面获取的。
	//也就说，要存储的是mailbox的内容，然后在每次loadfile的时候，对mailbox再执行获取解码内容
	//对文件进行更改

	//同步userdata
	userdata, err := GetUser(string(userdata.Username), string(userdata.Password_plain_text))
	if err != nil {
		return errors.New("broken")
	}
	//验证是否是创建者：
	var isOwner bool
	var file File
	file, isOwner = userdata.FileList[filename]
	if !isOwner {
		return errors.New("only creator can revoke")
	}
	//获取下来file和uuid
	var MailboxUUID uuid.UUID
	content, err := userdata.LoadFile(filename)
	if err != nil {
		return errors.New("broken")
	}
	// var file_info_uuid uuid.UUID
	// //事实上，因为我将content内容下载，打包后重新编码了。所以file_info 也用新的了
	// file_info_uuid = userdata.FileList[filename].InfoUUID
	//将file原来的数据库内容，进行清除.此处先保存，后面再清除
	// var used_file_uuid uuid.UUID
	// used_file_uuid = userdata.FileList[filename].FileUUID
	//userlib.DatastoreDelete(used_file_uuid)
	var fileinfo FileInfo
	fileinfo, err = GetFileInfo(file.InfoUUID, file.MacKey)
	if err != nil {
		return errors.New("broken")
	}

	//file的info要合并一下
	//这里完成了对文件的更改
	err = userdata.ChangeFileForRevoke(filename, content)
	if err != nil {
		return errors.New("broken")
	}
	for i := 0; i < int(fileinfo.ChangeNum)+1; i++ {
		fileNum, err := json.Marshal(i)
		if err != nil {
			panic(err)
		}
		file_uuid, err := json.Marshal(file.FileUUID)
		if err != nil {
			panic("json marshal err")
		}

		location, err := uuid.FromBytes(userlib.Hash(concat(fileNum, concat(userlib.Hash(userlib.Hash([]byte(file.Owner))), file_uuid)))[:16])
		if err != nil {
			panic("uuid generation err")
		}
		if i == 0 {
			location = file.FileUUID
		}
		if i == int(fileinfo.ChangeNum) {
			userlib.DatastoreSet(location, []byte("Access has been revoked"))
		} else {
			userlib.DatastoreDelete(location)
		}
	}

	//将file原来的数据库内容，进行清除

	//将filenode内容全部删除

	//更新mailbox里面的内容，其mailbox里面的uuid是不变的
	//遍历剩下的用户的list
	for i := 0; i < len(userdata.Children[filename]); i++ {
		if recipientUsername != userdata.Children[filename][i] {
			uuid_string := string(userlib.Hash([]byte(userdata.Username))) + string(userlib.Hash([]byte(userdata.Children[filename][i]))) + string(userlib.Hash([]byte(filename)))
			uuid_hash := userlib.Hash([]byte(uuid_string))
			MailboxUUID, err = uuid.FromBytes(uuid_hash[:16])
			if err != nil {
				panic("uuid generate err")
			}
			userdata.CreateMailBox(filename, userdata.Children[filename][i], MailboxUUID)
		} else {
			//将被撤销权限对应的mailbox删除
			uuid_string := string(userlib.Hash([]byte(userdata.Username))) + string(userlib.Hash([]byte(userdata.Children[filename][i]))) + string(userlib.Hash([]byte(filename)))
			uuid_hash := userlib.Hash([]byte(uuid_string))

			MailboxUUID, err = uuid.FromBytes(uuid_hash[:16])
			if err != nil {
				panic("uuid generate err")
			}

			userlib.DatastoreDelete(MailboxUUID)
		}
	}
	//Updata user info
	err = userdata.UpdataUserInfo()
	if err != nil {
		panic("Updata User Info error")
	}

	return nil
}

//下面函数实际上是对mailbox内容的更改，完成了存储。第三个参数
func (userdata *User) CreateMailBox(filename string, recipientUsername string, MailUUID uuid.UUID) ([]byte, []byte, error) {
	//这里是先创建一个mailbox，再创建一个指向mailbox的lockbox，然后将这个lockbox共享了
	var lockbox LockBox
	var mailbox MailBox
	var enmailbox EnMailBox
	//!!下面是mailbox里面存储的内容
	lockbox.MailboxUUID = MailUUID
	mailbox.FileUUID = userdata.FileList[filename].FileUUID
	mailbox.SymKey = userdata.FileList[filename].EncKey
	mailbox.Hkey = userdata.FileList[filename].MacKey
	mailbox.Owner = userdata.FileList[filename].Owner
	mailbox.FileInfoUUID = userdata.FileList[filename].InfoUUID
	//对mailbox进行加密,采用的是对称加密，并且把key放到了lockbox里面
	mailboxByte, err := json.Marshal(mailbox)
	if err != nil {
		panic(err)
	}

	//生成了lockbox需要的内容，也即对mailbox进行加密所需要的信息
	//固定方式产生key和uuid
	//Key产生的方式：pbkdf由userdata.Password,[]byte("mailbox"),16，三个参数生成；然后再hash时，三个参数：发送方用户名、接收方用户名、文件名
	//EncKey
	hash_purpose_enckey := string(userlib.Hash([]byte("mailbox_enckey"))) + string(userlib.Hash([]byte(userdata.Username))) + string(userlib.Hash([]byte(recipientUsername))) + string(userlib.Hash([]byte(filename)))
	symkey, err := userlib.HashKDF(userdata.Pbkdf, []byte(hash_purpose_enckey))
	lockbox.SymKey = symkey[:16]
	if err != nil {
		panic(err)
	}
	//Hahskey
	hash_purpose_hkey := string(userlib.Hash([]byte("mailbox_hkey"))) + string(userlib.Hash([]byte(userdata.Username))) + string(userlib.Hash([]byte(recipientUsername))) + string(userlib.Hash([]byte(filename)))
	Hkey, err := userlib.HashKDF(userdata.Pbkdf, []byte(hash_purpose_hkey))
	lockbox.Hkey = Hkey[:16]
	if err != nil {
		panic(err)
	}

	if err != nil {
		panic(err)
	}

	//所以revoke的时候，只要输入uuid_string，就可以获得到mailbox的位置，就可以实现修改了。
	//所以只需要记住自己这个文件都分享过那些recipientUsername,然后去手动生成uuid就行了
	//所以file里面要有一个[]，来记录creator直接的分享者？如果revoke了，记得移除
	//revoke时候，只需要给剩余的直接相连着对应的mailbox内容进行更新就可以。

	//对mailbox进行加密
	enmailbox.Enmailbox = userlib.SymEnc(lockbox.SymKey, userlib.RandomBytes(16), mailboxByte)
	enmailbox.Sig, err = userlib.HMACEval(lockbox.Hkey, enmailbox.Enmailbox)
	if err != nil {
		panic(err)
	}
	//对mailbox进行了存储
	enmailboxByte, err := json.Marshal(enmailbox)
	if err != nil {
		panic(err)
	}
	userlib.DatastoreSet(lockbox.MailboxUUID, enmailboxByte)

	return lockbox.Hkey, lockbox.SymKey, err
}

//改变了：uuid、enckey、mackey
func (userdata *User) ChangeFileForRevoke(filename string, content []byte) error {
	var file File
	file.InfoUUID = uuid.New()
	file.Owner = userdata.Username
	file.EncKey = userlib.RandomBytes(16)
	file.MacKey = userlib.RandomBytes(16)

	fileNum, err := json.Marshal(0)
	if err != nil {
		panic(err)
	}

	file.FileUUID = uuid.New()
	if err != nil {
		panic(err)
	}

	//Associate the created file with the owner(user)
	userdata.FileList[filename] = file

	//Encrypt the content
	EncedContent := userlib.SymEnc(file.EncKey, userlib.RandomBytes(userlib.AESBlockSizeBytes), content)

	//Create FileInfo to record the file's relevant information including how many times it has been changed and the changed length each time
	//The default value are 1 and len(content) respectively
	var fileInfo FileInfo
	fileInfo.TotalSize = uint(len(EncedContent))
	fileInfo.ChangeNum = 1
	//fileInfo.ChangeSize = []uint{uint(len(EncedContent))}

	//Call StoreFileInfo() to store fileInfo in DataStore
	userdata.StoreFileInfo(filename, &fileInfo)

	//Store file content

	var arr []byte
	arr = make([]byte, len(EncedContent))
	copy(arr, EncedContent)
	arr = concat(arr, fileNum)

	fileDataHMACPart, err := userlib.HMACEval(file.MacKey, arr)
	if err != nil {
		panic(err)
	}

	fileData := concat(concat(fileDataHMACPart, IntToBytes(len(EncedContent))), EncedContent)
	//updata
	userlib.DatastoreSet(file.FileUUID, fileData)
	err = userdata.UpdataUserInfo()
	if err != nil {
		panic("Updata User Info error")
	}
	return nil
}

func GetFileInfo(FileInfoUUID userlib.UUID, Mackey []byte) (FileInfo, error) {
	var fileInfo FileInfo
	//Get the location where the fileInfo is stored in DataStore
	location := FileInfoUUID

	//Get the value using function DatastoreGet()
	value, ok := userlib.DatastoreGet(location)
	if !ok {
		return fileInfo, errors.New("broken")
	}
	var HMACPair MACPair

	//Unmarshal the value to get the HMACPair
	err := json.Unmarshal(value, &HMACPair)
	if err != nil {
		return fileInfo, errors.New("broken")
	}
	//Validate the HMAC Pair
	correctHMAC, err := userlib.HMACEval(Mackey, HMACPair.Content)
	if err != nil {
		panic("Hmac generate err")
	}
	if !(userlib.HMACEqual(HMACPair.MAC, correctHMAC)) {
		return fileInfo, errors.New("broken")
	}
	//Unmarshal to get the fileInfo
	err = json.Unmarshal(HMACPair.Content, &fileInfo)
	if err != nil {
		return fileInfo, errors.New("broken")
	}
	return fileInfo, nil
}
