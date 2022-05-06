package client_test

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "fmt"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	// var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})
	Describe("Test0.1", func() {
		Specify("Test0.1: ", func() {
			alice, err = client.InitUser("alice", emptyString)
			Expect(err).To(BeNil())

			_, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

		})
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("(flag:[11,18,24]) LHT:Bob can't revoke file %s as a invitee", bobFile)
			err = bob.RevokeAccess(bobFile, "charles")
			Expect(err).ToNot(BeNil())

			// userlib.DebugMsg("Alice can revoke access from Charles")
			// err = alice.RevokeAccess(aliceFile, "charles")
			// Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())
			//​撤销的用户不可以通过datastore去访问任何文件信息
			// _, ok := userlib.DatastoreGet(invite)
			// Expect(ok).To(Equal(false))

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Flag(flag:[11,18,24])  LHT Checking that revoked user can't invitate")
			_, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).ToNot(BeNil())

			_, err = charles.CreateInvitation(charlesFile, "bob")
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users can store a file with the same filename.")
			err = bob.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo + contentTwo)))

			userlib.DebugMsg("Checking that the revoked users can store a file with the same filename.")
			err = charles.StoreFile(charlesFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo + contentTwo)))

			userlib.DebugMsg("Checking that the owner can load the correct file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

		})
	})

	Describe("Test1", func() {
		Specify("Test1: Accepting invitation from a wrong username", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))

			bob, _ = client.InitUser("bob", defaultPassword)
			ptr, _ := alice.CreateInvitation(aliceFile, "bob")
			err = bob.AcceptInvitation("bob", ptr, "alicefile")

			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Test1.1", func() {
		Specify("Test1.1: Creating invitation to a wrong username", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))

			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Test1.2", func() {
		Specify("Test1.2: Creating invitation to a user who already has access", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))

			_, err := alice.CreateInvitation(aliceFile, "alice")
			Expect(err).To(BeNil())
		})
	})

	Describe("Test1:(flag:[11,18,24]) ", func() {
		Specify("Test: Testing appending to an invalid file", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can append to an invalid file.")
			err := alice.AppendToFile(aliceFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Test1:", func() {
		Specify("Test: Testing loading an invalid file", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can load an invalid file.")
			_, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Test2:[12/22/23]", func() {
		Specify("Test2: Accepting wrong ptr or b accept a", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			bob, _ = client.InitUser("bob", defaultPassword)
			charles, _ = client.InitUser("charles", defaultPassword)

			alice.CreateInvitation(aliceFile, "bob")
			ptr2, _ := alice.CreateInvitation(aliceFile, "charles")
			err = bob.AcceptInvitation("alice", ptr2, "alicefile")
			Expect(err).ToNot(BeNil())

		})
	})

	Describe("Test3:[12/22/23]", func() {
		Specify("Test3: create invitation wrong username", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			bob, _ = client.InitUser("bob", defaultPassword)
			//wrong invitee name
			_, err := alice.CreateInvitation(aliceFile, "bob2")
			Expect(err).ToNot(BeNil())
			//wrong uuid，即ptr
		})
	})

	Describe("Test3.1:", func() {
		Specify("Test3.1: create invitation wrong username", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			bob, _ = client.InitUser("bob", defaultPassword)
			//wrong invitee name
			_, err := alice.CreateInvitation(bobFile, "bob")
			Expect(err).ToNot(BeNil())
			//wrong uuid，即ptr
		})
	})

	Describe("Test3.2[2]:", func() {
		Specify("Test3.2:store files with same filename", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
		})
	})

	Describe("Test4:[12/22/23]", func() {
		Specify("Test4: create revoke accept err", func() {
			//Init alice
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			//Init bob
			bob, _ = client.InitUser("bob", defaultPassword)
			ptr, _ := alice.CreateInvitation(aliceFile, "bob")
			//creat revoke accept
			//err = bob.AcceptInvitation("alice", ptr, "alicefile")
			alice.RevokeAccess(aliceFile, "bob")
			err = bob.AcceptInvitation("alice", ptr, "alicefile")
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Test4.3:[10,16]", func() {
		Specify("Test4.3: a share c, b share c, then c use a's name and b ptr", func() {
			//Init alice
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			//Init bob
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			err = bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())
			//Init charles
			charles, err = client.InitUser("charles", defaultPassword)
			alice.CreateInvitation(aliceFile, "charles")
			ptr2, _ := bob.CreateInvitation(bobFile, "charles")
			//creat revoke accept
			err = charles.AcceptInvitation("alice", ptr2, "alicefile")
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Test4.4:", func() {
		Specify("Test4.4: a share b, b share c, then c use a's name and b ptr", func() {
			//Init alice
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			//Init bob
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			ptr, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", ptr, bobFile)
			Expect(err).To(BeNil())

			//Init charles
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			ptr2, err := bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("alice", ptr2, charlesFile)
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Test4.4", func() {
		Specify("Test4.4: revoke then invite the same", func() {
			//Init alice
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			//Init bob
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			err = bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", defaultPassword)
			charles.StoreFile(charlesFile, []byte(contentTwo))
			ptr2, err := charles.CreateInvitation(charlesFile, "bob")
			Expect(err).To(BeNil())

			ptr, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			bob.AcceptInvitation("alice", ptr, "alicefile")
			data, err := bob.LoadFile("alicefile")
			Expect(data).To(Equal([]byte(contentOne)))
			Expect(err).To(BeNil())
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			_, err = bob.LoadFile("alicefile")
			Expect(err).ToNot(BeNil())
			ptr, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", ptr, "alicefile")
			Expect(err).ToNot(BeNil())
			data, err = bob.LoadFile("alicefile")
			Expect(data).To(Equal([]byte(contentOne)))
			Expect(err).To(BeNil())
			alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("charles", ptr2, "alicefile")
			Expect(err).To(BeNil())
			data, err = bob.LoadFile("alicefile")
			Expect(data).To(Equal([]byte(contentTwo)))
			Expect(err).To(BeNil())
		})
	})

	Describe("Test4.4.1", func() {
		Specify("Test4.4.1: revoke invite among multiple instances", func() {
			//Init alice
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			//Init bob
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			ptr, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", ptr, bobFile)
			Expect(err).To(BeNil())

			err = aliceDesktop.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Test4.4.3", func() {
		Specify("Test4.4.3: If Bob already has f1.txt and calls acceptInvitation on f1.txt, that would return an error.", func() {
			//Init alice
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			//Init bob
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			err = bob.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			ptr, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", ptr, aliceFile)
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Test4.4.2", func() {
		Specify("Test4.4.2: revoke invite among multiple instances", func() {
			//Init alice
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			//Init bob
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			err = bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			//Init charles
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			ptr, err := bob.CreateInvitation(bobFile, "alice")
			Expect(err).To(BeNil())

			aliceLaptop.AcceptInvitation("bob", ptr, aliceFile)

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that aliceDesktop can append to the file.")
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			data, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			ptr2, err := aliceLaptop.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			charles.AcceptInvitation("alice", ptr2, charlesFile)

			err = bob.RevokeAccess(bobFile, "alice")
			Expect(err).To(BeNil())

			_, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
			err = aliceLaptop.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			_, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())
			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Test4.4.3", func() {
		Specify("Test4.4.3: Testing if an invitee could overwrite the file content using StoreFile().", func() {
			//Init alice
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			//Init bob
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			ptr, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", ptr, bobFile)
			Expect(err).To(BeNil())

			err = bob.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			data, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
		})
	})

	Describe("Test4.4.4", func() {
		Specify("Test4.4.4: Testing if an inviter could overwrite the file content using StoreFile().", func() {
			//Init alice
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			//Init bob
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			ptr, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", ptr, bobFile)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			// data, err := bob.LoadFile(bobFile)
			// Expect(err).To(BeNil())
			// Expect(data).To(Equal([]byte(contentTwo)))

			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
		})
	})

	Describe("Test4.4.5", func() {
		Specify("Test4.4.5: Testing accept invitation under same filename", func() {
			//Init alice
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			//Init bob
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			ptr, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", ptr, aliceFile)
			Expect(err).To(BeNil())
		})
	})

	Describe("Test4.5:[14]", func() {
		Specify("Test4.5:same username+filename same;username+password same", func() {
			//user's test
			//Init alice
			alice, err = client.InitUser("alice", "nd")
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			// //same user name
			// _, err = client.InitUser("alice", "nd")
			// Expect(err).ToNot(BeNil())
			//Init bob
			alic, err := client.InitUser("alic", "end")
			Expect(err).To(BeNil())
			_, err = alic.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			//file's test
			//Init charles
			alicea, err := client.InitUser("alicea", defaultPassword)
			Expect(err).To(BeNil())
			_, err = alicea.LoadFile("liceFile.txt")
			Expect(err).ToNot(BeNil())

			bob, err = client.InitUser("bob", "")
			Expect(err).To(BeNil())

			bo, err := client.InitUser("bo", "")
			Expect(err).To(BeNil())

			ptr, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", ptr, "bobFile")
			Expect(err).To(BeNil())

			ptr2, err := alice.CreateInvitation(aliceFile, "bo")
			Expect(err).To(BeNil())
			err = bo.AcceptInvitation("alice", ptr2, "bbobFile")
			Expect(err).To(BeNil())

			content, err := bob.LoadFile("bobFile")
			Expect(content).To(Equal([]byte(contentOne)))
			Expect(err).To(BeNil())

			content, err = bo.LoadFile("bbobFile")
			Expect(content).To(Equal([]byte(contentOne)))
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", "")
			Expect(err).To(BeNil())
			//null password

			err = bob.StoreFile("", []byte(contentOne))
			Expect(err).To(BeNil())
			content, err = bob.LoadFile("")
			Expect(content).To(Equal([]byte(contentOne)))
			Expect(err).To(BeNil())
			err = bob.AppendToFile("", []byte(contentTwo))
			Expect(err).To(BeNil())
			content, err = bob.LoadFile("")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentOne + contentTwo)))
			ptr, err = bob.CreateInvitation("", "charles")
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("bob", ptr, "")
			Expect(err).To(BeNil())

		})
	})

	Describe("Test4.6", func() {
		Specify("Test4.6: second flag:long list", func() {
			a, err := client.InitUser("a", defaultPassword)
			Expect(err).To(BeNil())
			b, err := client.InitUser("b", defaultPassword)
			Expect(err).To(BeNil())
			c, err := client.InitUser("c", defaultPassword)
			Expect(err).To(BeNil())
			d, err := client.InitUser("d", defaultPassword)
			Expect(err).To(BeNil())
			e, err := client.InitUser("e", defaultPassword)
			Expect(err).To(BeNil())
			f, err := client.InitUser("f", defaultPassword)
			Expect(err).To(BeNil())
			g, err := client.InitUser("g", defaultPassword)
			Expect(err).To(BeNil())
			h, err := client.InitUser("h", defaultPassword)
			Expect(err).To(BeNil())
			n, err := client.InitUser("n", defaultPassword)
			Expect(err).To(BeNil())
			l, err := client.InitUser("l", defaultPassword)
			Expect(err).To(BeNil())
			m, err := client.InitUser("m", defaultPassword)

			//Init alice
			Expect(err).To(BeNil())
			err = a.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			//Init bob
			ptr, err := a.CreateInvitation(aliceFile, "b")
			Expect(err).To(BeNil())
			err = b.AcceptInvitation("a", ptr, "afile")
			Expect(err).To(BeNil())
			ptr, err = b.CreateInvitation("afile", "c")
			Expect(err).To(BeNil())
			err = c.AcceptInvitation("b", ptr, "bfile")
			Expect(err).To(BeNil())
			ptr, err = c.CreateInvitation("bfile", "d")
			Expect(err).To(BeNil())
			err = d.AcceptInvitation("c", ptr, "cfile")
			Expect(err).To(BeNil())
			ptr, err = c.CreateInvitation("bfile", "n")
			Expect(err).To(BeNil())
			err = n.AcceptInvitation("c", ptr, "cfile")
			Expect(err).To(BeNil())
			ptr, err = d.CreateInvitation("cfile", "e")
			Expect(err).To(BeNil())
			err = e.AcceptInvitation("d", ptr, "dfile")
			Expect(err).To(BeNil())
			ptr, err = d.CreateInvitation("cfile", "f")
			Expect(err).To(BeNil())
			err = f.AcceptInvitation("d", ptr, "dfile")
			Expect(err).To(BeNil())
			ptr, err = a.CreateInvitation(aliceFile, "g")
			Expect(err).To(BeNil())
			err = g.AcceptInvitation("a", ptr, "afile")
			Expect(err).To(BeNil())
			ptr, err = g.CreateInvitation("afile", "h")
			Expect(err).To(BeNil())
			err = h.AcceptInvitation("g", ptr, "gfile")
			Expect(err).To(BeNil())
			ptr, err = a.CreateInvitation(aliceFile, "l")
			Expect(err).To(BeNil())
			err = l.AcceptInvitation("a", ptr, "afile")
			Expect(err).To(BeNil())
			ptr, err = l.CreateInvitation("afile", "m")
			Expect(err).To(BeNil())
			err = m.AcceptInvitation("l", ptr, "lfile")
			Expect(err).To(BeNil())

			//Init charles

			//append and then load
			err = a.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			err = e.AppendToFile("dfile", []byte(contentThree))
			Expect(err).To(BeNil())
			err = g.AppendToFile("afile", []byte(contentOne))
			Expect(err).To(BeNil())
			data, err := h.LoadFile("gfile")
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree + contentOne)))
			Expect(err).To(BeNil())
			data, err = d.LoadFile("cfile")
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree + contentOne)))
			Expect(err).To(BeNil())

			//revoke
			err = d.RevokeAccess("cfile", "e")
			Expect(err).ToNot(BeNil())
			err = a.RevokeAccess(aliceFile, "l")
			Expect(err).To(BeNil())
			data, err = f.LoadFile("dfile")
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree + contentOne)))
			Expect(err).To(BeNil())
			err = m.AppendToFile("lfile", []byte(contentOne))
			Expect(err).ToNot(BeNil())
			err = f.AppendToFile("dfile", []byte(contentTwo))
			Expect(err).To(BeNil())
			data, err = h.LoadFile("gfile")
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree + contentOne + contentTwo)))
			Expect(err).To(BeNil())
			//second file
			err = g.StoreFile("file2", []byte(contentOne))
			Expect(err).To(BeNil())
			ptr, err = g.CreateInvitation("file2", "h")
			Expect(err).To(BeNil())
			err = h.AcceptInvitation("g", ptr, "file2g")
			Expect(err).To(BeNil())
			err = a.RevokeAccess("file2", "h")
			Expect(err).ToNot(BeNil())
			err = a.RevokeAccess(aliceFile, "g")
			Expect(err).To(BeNil())
			data, err = h.LoadFile("file2g")
			Expect(data).To(Equal([]byte(contentOne)))
			Expect(err).To(BeNil())
			data, err = a.LoadFile(aliceFile)
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree + contentOne + contentTwo)))
			Expect(err).To(BeNil())

		})
	})

	Describe("Test6", func() {
		Specify("Test6: Appending empty file", func() {
			userlib.DebugMsg("Initializing user Alice and Bob..")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", emptyString)
			err = alice.StoreFile(emptyString, []byte(emptyString))

			userlib.DebugMsg("Appending file data: %s", emptyString)
			err = alice.AppendToFile(emptyString, []byte(emptyString))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(emptyString)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(emptyString)))

			userlib.DebugMsg("Alice creating invite for Bob with empty filename.")
			invite, err := alice.CreateInvitation(emptyString, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", emptyString)
			err = bob.AcceptInvitation("alice", invite, emptyString)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data1, err := bob.LoadFile(emptyString)
			Expect(err).To(BeNil())
			Expect(data1).To(Equal([]byte(emptyString)))
		})
	})

	Describe("Test8", func() {
		Specify("Test8: Getting user with wrong password", func() {
			userlib.DebugMsg("Initializing users Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice with wrong password.")
			alice, err = client.GetUser("alice", emptyString)
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Test8.1", func() {
		Specify("Test8.1: Testing usernames are case-sensitive", func() {
			userlib.DebugMsg("Initializing users Alice.")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing users alice.")
			alice, err = client.InitUser("alice", emptyString)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice with wrong password.")
			alice, err = client.GetUser("Alice", emptyString)
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Test9", func() {
		Specify("Test9: Initializing user with empty username", func() {
			userlib.DebugMsg("Initializing user ''.")
			alice, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Test10", func() {
		Specify("Test10: Testing two users could have same file names", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob storing file %s with content: %s", aliceFile, contentTwo)
			err = bob.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data1, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data1).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Loading file...")
			data2, err := bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data2).To(Equal([]byte(contentTwo)))

			Expect(data2).ToNot(Equal(data1))
		})
	})

	Describe("Test11", func() {
		Specify("Test11: accept ", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob storing file %s with content: %s", bobFile, contentOne)
			err = bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Alice.")
			invite, err := bob.CreateInvitation(bobFile, "alice")
			Expect(err).To(BeNil())

			userlib.DebugMsg("AliceDesktop accepting invite from Bob under filename %s.", aliceFile)
			err = aliceLaptop.AcceptInvitation("bob", invite, aliceFile)
			Expect(err).To(BeNil())

			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			data2, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data2).To(Equal([]byte(contentOne)))
		})
	})
})
