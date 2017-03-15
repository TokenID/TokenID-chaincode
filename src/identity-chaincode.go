/*
Copyright Victor Ikoro 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/hyperledger/fabric/core/chaincode/shim"
)

// IdentityChainCode  Chaincode implementation
type IdentityChainCode struct {
}

type Identity struct {
	ProviderEnrollmentID     string `json:"providerEnrollmentID"`     //Mundane identity ID - Identity Provider given
	IdentityCode             string `json:"identityCode"`             //Issuer given identity ID
	IdentityTypeCode         string `json:"identityTypeCode"`         //Virtual Identity Type Code (Issuer defined) - gotten from TCert
	IssuerCode               string `json:"issuerCode"`               //Virtual Identity Issuer Code - gotten from TCert
	IssuerOrganization       string `json:"issuerOrganization"`       //Virtual Identity Issuer Organization - gotten from TCert or Ecert
	EncryptedPayload         string `json:"encryptedPayload"`         // Encrypted Virtual Identity (EVI) payload
	EncryptedKey             string `json:"encryptedKey"`             //Symmetric encryption key for EVI payload encrypted with the public key
	MetaData                 string `json:"metaData"`                 //Miscellanous Identity Information - ONLY NON-SENSITIVE IDENTITY INFORMATION/ATTRIBUTES SHOULD BE ADDED
	EncryptedAttachmentURI   string `json:"encryptedAttachmentURI"`   //Encrypted URIs to Virtual Identity Document e.g. Scanned document image
	CreatedBy                string `json:"createdBy"`                //Identity Creator
	CreatedOnTxTimestamp     int64  `json:"createdOnTxTimestamp"`     //Created on Timestamp -   which is currently taken from the peer receiving the transaction. Note that this timestamp may not be the same with the other peers' time.
	LastUpdatedBy            string `json:"lastUpdatedBy"`            //Last Updated By
	LastUpdatedOnTxTimestamp int64  `json:"lastUpdatedOnTxTimestamp"` //Last Updated On Timestamp -   which is currently taken from the peer receiving the transaction. Note that this timestamp may not be the same with the other peers' time.
	IssuerVerified           bool   `json:"issuerVerified"`           //Identity verified by Issuer
}

type IdentityMin struct {
	ProviderEnrollmentID     string `json:"providerEnrollmentID"`
	IdentityCode             string `json:"identityCode"`
	IdentityTypeCode         string `json:"identityTypeCode"`
	IssuerCode               string `json:"issuerCode"`
	IssuerOrganization       string `json:"issuerOrganization"`
	CreatedBy                string `json:"createdBy"`
	CreatedOnTxTimestamp     int64  `json:"createdOnTxTimestamp"`
	LastUpdatedBy            string `json:"lastUpdatedBy"`
	LastUpdatedOnTxTimestamp int64  `json:"lastUpdatedOnTxTimestamp"`
	IssuerVerified           bool   `json:"issuerVerified"`
}

type Issuer struct {
	IssuerUser               string `json:"issuerUser"`
	IssuerID                 string `json:"issuerID"`
	IssuerIdentityTypeCodes  string `json:"issuerIdentityTypeCodes"`
	IssuerCode               string `json:"issuerCode"`
	IssuerOrganization       string `json:"issuerOrganization"`
	CreatedBy                string `json:"createdBy"`
	CreatedOnTxTimestamp     int64  `json:"createdOnTxTimestamp"`
	LastUpdatedBy            string `json:"lastUpdatedBy"`
	LastUpdatedOnTxTimestamp int64  `json:"lastUpdatedOnTxTimestamp"`
}

//States key prefixes
const PUBLIC_KEY_PREFIX = "_PK"
const IDENTITY_TBL_PREFIX = "_TABLE"
const ISSUER_TBL_NAME = "ISSUERS_TABLE"

//"EVENTS"
const EVENT_NEW_IDENTITY_ENROLLED = "EVENT_NEW_IDENTITY_ENROLLED"
const EVENT_NEW_IDENTITY_ISSUED = "EVENT_NEW_IDENTITY_ISSUED"
const EVENT_NEW_ISSUER_ENROLLED = "EVENT_NEW_ISSUER_ENROLLED"

//ROLES
const ROLE_ISSUER = "Issuer"
const ROLE_PROVIDER = "Provider"
const ROLE_RELYING_PARTNER = "RP"

var logger = shim.NewLogger("IdentityChaincode")

// ============================================================================================================================
// Main
// ============================================================================================================================
func main() {
	err := shim.Start(new(IdentityChainCode))
	if err != nil {
		fmt.Printf("Error starting Identity ChainCode: %s", err)
	}
}

//=================================================================================================================================
//	 Ping Function
//=================================================================================================================================
//	 Pings the peer to keep the connection alive
//=================================================================================================================================
func (t *IdentityChainCode) Ping(stub shim.ChaincodeStubInterface) ([]byte, error) {
	return []byte("Hi, I'm up!"), nil
}

//=================================================================================================================================
//Initializes chaincode when deployed
//=================================================================================================================================
func (t *IdentityChainCode) Init(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	if len(args) != 0 {
		return nil, errors.New("Incorrect number of arguments. Expecting 0")
	}
	//Create initial issuer tables
	fmt.Println("Initializing Issuers Table")
	err := t.createIssuerTable(stub)
	if err != nil {
		fmt.Println(err)
		return nil, err

	}

	return nil, nil
}

//=================================================================================================================================
//Initializes the Identity and sets the default states
//=================================================================================================================================
func (t *IdentityChainCode) InitIdentity(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {

	if len(args) < 2 {
		return nil, errors.New("Incorrect number of arguments. Expecting 2 -> [providerEnrollmentID , identityPublicKey]")
	}

	var providerEnrollmentID, identityPublicKey string
	providerEnrollmentID = args[0]
	identityPublicKey = args[1]

	//Verify that Enrollment ID and Pubic key is not null
	if providerEnrollmentID == "" || identityPublicKey == "" {
		return nil, errors.New("Provider Enrollment ID or Public key cannot be null")
	}

	//Add Public key state
	existingPKBytes, err := stub.GetState(providerEnrollmentID + PUBLIC_KEY_PREFIX)

	if err == nil && existingPKBytes != nil {
		return nil, fmt.Errorf("Public Key for " + providerEnrollmentID + " already exists ")
	}

	pkBytes := []byte(identityPublicKey)

	//Validate Public key is PEM format
	err = validatePublicKey(pkBytes)

	if err != nil {
		return nil, fmt.Errorf("Bad Public Key -> Public key must be in PEM format - [%v]", err)
	}

	//Set Public key state
	err = stub.PutState(providerEnrollmentID+PUBLIC_KEY_PREFIX, pkBytes)

	if err != nil {
		return nil, fmt.Errorf("Failed inserting public key, [%v] -> "+providerEnrollmentID, err)
	}

	//Create Identity Table
	err = t.createIdentityTable(stub, providerEnrollmentID)
	if err != nil {
		return nil, fmt.Errorf("Failed creating Identity Table, [%v] -> "+providerEnrollmentID, err)
	}

	//Broadcast 'New Enrollment'  Event with enrollment ID
	err = stub.SetEvent(EVENT_NEW_IDENTITY_ENROLLED, []byte(providerEnrollmentID))

	if err != nil {
		return nil, fmt.Errorf("Failed to broadcast enrollment event, [%v] -> "+providerEnrollmentID, err)
	}

	return []byte("Enrollment Successful"), nil
}

//=================================================================================================================================
//Initializes new Issuer
//=================================================================================================================================
func (t *IdentityChainCode) InitIssuer(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {

	if len(args) < 5 {
		return nil, errors.New("Incorrect number of arguments. Expecting 5 -> [issuerEnrollmentUserName , issuerID , issuerCode , issuerOrganization , identityTypeCodes]")
	}

	var issuerEnrollmentUserName, issuerID, issuerCode, issuerOrganization, identityTypeCodes string
	issuerEnrollmentUserName = args[0]
	issuerID = args[1]
	issuerCode = args[2]
	issuerOrganization = args[3]
	identityTypeCodes = args[4]

	//Check if user is provider
	callerDetails, err := readCallerDetails(&stub)
	if err != nil {
		return nil, fmt.Errorf("Error getting caller details, [%v]", err)
	}
	isProv := isProvider(callerDetails)
	if isProv == false {
		return nil, errors.New("Access Denied")
	}

	//Verify required fields
	if issuerEnrollmentUserName == "" || issuerID == "" || issuerCode == "" || issuerOrganization == "" {
		return nil, errors.New("One or more Mandatory field(s) missing. Mandatory fields include 'issuerEnrollmentUserName', 'issuerID', 'issuerCode', 'issuerOrganization'")
	}

	//Check for existing issuer
	var columns []shim.Column
	//keyCol1 := shim.Column{Value: &shim.Column_String_{String_: issuerEnrollmentUserName}}
	keyCol2 := shim.Column{Value: &shim.Column_String_{String_: issuerID}}
	keyCol3 := shim.Column{Value: &shim.Column_String_{String_: issuerCode}}
	columns = append(columns, keyCol2, keyCol3)

	exists, err := recordExistsInTable(&stub, ISSUER_TBL_NAME, columns)

	if err != nil {
		return nil, fmt.Errorf("Error checking for existing issuers, [%v]", err)
	}
	if exists == true {
		return nil, errors.New("Issuer ID or Code  already exist -> " + issuerID + "|" + issuerCode)
	}

	//Get Transaction TimeStamp
	stampPointer, err := stub.GetTxTimestamp()

	if err != nil {
		return nil, fmt.Errorf("Could not get Transaction timestamp from peer, [%v]", err)

	}
	timestamp := *stampPointer
	//Insert Issuer
	_, err = stub.InsertRow(
		ISSUER_TBL_NAME,
		shim.Row{
			Columns: []*shim.Column{
				&shim.Column{Value: &shim.Column_String_{String_: issuerEnrollmentUserName}},
				&shim.Column{Value: &shim.Column_String_{String_: issuerID}},
				&shim.Column{Value: &shim.Column_String_{String_: issuerCode}},
				&shim.Column{Value: &shim.Column_String_{String_: issuerOrganization}},
				&shim.Column{Value: &shim.Column_String_{String_: identityTypeCodes}},
				&shim.Column{Value: &shim.Column_String_{String_: callerDetails.user}},
				&shim.Column{Value: &shim.Column_Int64{Int64: timestamp.Seconds}},
				&shim.Column{Value: &shim.Column_String_{String_: ""}},
				&shim.Column{Value: &shim.Column_Int64{Int64: 0}},
				&shim.Column{Value: &shim.Column_String_{String_: ""}},
				&shim.Column{Value: &shim.Column_String_{String_: ""}},
				&shim.Column{Value: &shim.Column_String_{String_: ""}},
			},
		})

	//Broadcast 'New Issuer Enrollment'  Event Issuer ID
	err = stub.SetEvent(EVENT_NEW_ISSUER_ENROLLED, []byte(issuerID))

	if err != nil {
		return nil, fmt.Errorf("Failed to broadcast issuer enrollment event, [%v] -> "+issuerID, err)
	}

	return []byte("Issuer successfully added -> " + issuerID), nil
}

//=================================================================================================================================
//	 Entry point to invoke a chaincode function
//=================================================================================================================================
func (t *IdentityChainCode) Invoke(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	fmt.Println("invoke is running " + function)

	var bytes []byte
	var err error

	fmt.Println("function -> " + function)

	// Handle different functions
	if function == "init" { //initialize the chaincode state, used as reset
		bytes, err = t.Init(stub, "init", args)
	} else if function == "initIssuer" {
		bytes, err = t.InitIssuer(stub, args)
	} else if function == "initIdentity" {
		bytes, err = t.InitIdentity(stub, args)
	} else if function == "addIdentity" {
		bytes, err = t.AddIdentity(stub, args)
	} else {
		fmt.Println("invoke did not find func: " + function) //error

		return nil, errors.New("Received unknown function invocation: " + function)
	}
	if err != nil {
		fmt.Println(err)
	}
	return bytes, err

}

//=================================================================================================================================
//	 Query is our entry point for queries
//=================================================================================================================================
func (t *IdentityChainCode) Query(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	fmt.Println("query is running " + function)

	// Handle different functions

	var bytes []byte
	var err error

	fmt.Println("function -> " + function)
	if function == "ping" {
		bytes, err = t.Ping(stub)

	} else if function == "getIdentities" {
		bytes, err = t.GetIdentities(stub, args)

	} else if function == "getIssuers" {
		bytes, err = t.GetIssuers(stub, args)

	} else if function == "getIdentity" {
		bytes, err = t.GetIdentity(stub, args)
	} else if function == "getPublicKey" {
		bytes, err = t.GetPublicKey(stub, args)
	} else {
		fmt.Println("query did not find func: " + function) //error
		return nil, errors.New("Received unknown function query: " + function)
	}
	if err != nil {
		fmt.Println(err)
	}
	return bytes, err

}

//=================================================================================================================================
//	 Create Identity table
//=================================================================================================================================

//Create Identity Table
func (t *IdentityChainCode) createIdentityTable(stub shim.ChaincodeStubInterface, enrollmentID string) error {

	var tableName string

	tableName = enrollmentID + IDENTITY_TBL_PREFIX

	// Create Identity table
	tableErr := stub.CreateTable(tableName, []*shim.ColumnDefinition{
		&shim.ColumnDefinition{Name: "ProviderEnrollmentID", Type: shim.ColumnDefinition_STRING, Key: false},
		&shim.ColumnDefinition{Name: "IdentityCode", Type: shim.ColumnDefinition_STRING, Key: true},
		&shim.ColumnDefinition{Name: "IdentityTypeCode", Type: shim.ColumnDefinition_STRING, Key: true},
		&shim.ColumnDefinition{Name: "EncryptedPayload", Type: shim.ColumnDefinition_STRING, Key: false},
		&shim.ColumnDefinition{Name: "IssuerCode", Type: shim.ColumnDefinition_STRING, Key: true},
		&shim.ColumnDefinition{Name: "IssuerOrganization", Type: shim.ColumnDefinition_STRING, Key: false},
		&shim.ColumnDefinition{Name: "EncryptedKey", Type: shim.ColumnDefinition_BYTES, Key: false},
		&shim.ColumnDefinition{Name: "Metadata", Type: shim.ColumnDefinition_STRING, Key: false},
		&shim.ColumnDefinition{Name: "IssuerVerified", Type: shim.ColumnDefinition_BOOL, Key: false},
		&shim.ColumnDefinition{Name: "EncryptedAttachmentURI", Type: shim.ColumnDefinition_BYTES, Key: false},
		&shim.ColumnDefinition{Name: "CreatedBy", Type: shim.ColumnDefinition_STRING, Key: false},
		&shim.ColumnDefinition{Name: "CreatedOnTxTimeStamp", Type: shim.ColumnDefinition_INT64, Key: false},
		&shim.ColumnDefinition{Name: "LastUpdatedBy", Type: shim.ColumnDefinition_STRING, Key: false},
		&shim.ColumnDefinition{Name: "lastUpdatedOnTxTimeStamp", Type: shim.ColumnDefinition_INT64, Key: false},
		&shim.ColumnDefinition{Name: "additionalField1", Type: shim.ColumnDefinition_STRING, Key: false},
		&shim.ColumnDefinition{Name: "additionalField2", Type: shim.ColumnDefinition_STRING, Key: false},
		&shim.ColumnDefinition{Name: "additionalField3", Type: shim.ColumnDefinition_STRING, Key: false},
		&shim.ColumnDefinition{Name: "additionalField4", Type: shim.ColumnDefinition_STRING, Key: false},
	})
	if tableErr != nil {
		return fmt.Errorf("Failed creating IdentityTable table, [%v] -> "+enrollmentID, tableErr)
	}
	return nil
}

//=================================================================================================================================
//	 Create Issuer table
//=================================================================================================================================

func (t *IdentityChainCode) createIssuerTable(stub shim.ChaincodeStubInterface) error {

	// Create Issuer table
	tableErr := stub.CreateTable(ISSUER_TBL_NAME, []*shim.ColumnDefinition{
		&shim.ColumnDefinition{Name: "IssuerUserName", Type: shim.ColumnDefinition_STRING, Key: false},
		&shim.ColumnDefinition{Name: "IssuerID", Type: shim.ColumnDefinition_STRING, Key: true},
		&shim.ColumnDefinition{Name: "IssuerCode", Type: shim.ColumnDefinition_STRING, Key: true},
		&shim.ColumnDefinition{Name: "IssuerOrganization", Type: shim.ColumnDefinition_STRING, Key: false},
		&shim.ColumnDefinition{Name: "IssuerIdentityTypeCodes", Type: shim.ColumnDefinition_STRING, Key: false},
		&shim.ColumnDefinition{Name: "CreatedBy", Type: shim.ColumnDefinition_STRING, Key: false},
		&shim.ColumnDefinition{Name: "CreatedOnTxTimeStamp", Type: shim.ColumnDefinition_INT64, Key: false},
		&shim.ColumnDefinition{Name: "LastUpdatedBy", Type: shim.ColumnDefinition_STRING, Key: false},
		&shim.ColumnDefinition{Name: "LastUpdatedOnTxTimeStamp", Type: shim.ColumnDefinition_INT64, Key: false},
		&shim.ColumnDefinition{Name: "additionalField1", Type: shim.ColumnDefinition_STRING, Key: false},
		&shim.ColumnDefinition{Name: "additionalField2", Type: shim.ColumnDefinition_STRING, Key: false},
		&shim.ColumnDefinition{Name: "additionalField3", Type: shim.ColumnDefinition_STRING, Key: false},
	})
	if tableErr != nil {
		return fmt.Errorf("Failed creating Issuer table, [%v]", tableErr)
	}
	return nil
}

//=================================================================================================================================
//	 Add New Issued Identity
//=================================================================================================================================
func (t *IdentityChainCode) AddIdentity(stub shim.ChaincodeStubInterface, identityParams []string) ([]byte, error) {

	if len(identityParams) < 8 {
		return nil, errors.New("Incomplete number of arguments. Expected 6")
	}

	callerDetails, err := readCallerDetails(&stub)
	if err != nil {
		return nil, fmt.Errorf("Error getting caller details, [%v]", err)
	}
	if strings.EqualFold(callerDetails.role, ROLE_ISSUER) == false && strings.EqualFold(callerDetails.role, ROLE_PROVIDER) == false {
		return nil, errors.New("Access Denied. Not a provider or Issuer")
	}
	isProvider := isProvider(callerDetails)

	var issuerCode, issuerOrganization, issuerID string

	issuerVerified := false

	//For providers, issuer details are required to be submitted
	//Parameters should be in the order -> [ProviderEnrollmentID, IdentityCode, IdentityTypeCode, EncryptedIdentityPayload, EncryptionKey, IssuerID,  MetaData, EncryptedAttachmentURI]
	if isProvider == true {
		//Check for empty mandatory fields (first 5 fields)
		for i := 0; i < 6; i++ {
			if identityParams[i] == "" {
				return nil, errors.New("One or more mandatory fields is empty. Mandatory fields are the first 5 which are ProviderEnrollmentID, IdentityCode, IdentityTypeCode, IdentityPayload and IssuerID")
			}
		}
		issuerID = identityParams[5]
	} else {
		//Issuer details are gotten from Transaction Certificate
		//Check for empty mandatory fields
		for i := 0; i < 5; i++ {
			if identityParams[i] == "" {
				return nil, errors.New("One or more mandatory fields is empty. Mandatory fields are the first 4 which are ProviderEnrollmentID, IdentityCode, IdentityTypeCode  and IdentityPayload")
			}
		}
		issuerID = callerDetails.issuerID
		issuerVerified = true
	}

	//Get existing issuer
	var columns []shim.Column
	keyCol1 := shim.Column{Value: &shim.Column_String_{String_: issuerID}}
	columns = append(columns, keyCol1)

	rowPointers, err := getRows(&stub, ISSUER_TBL_NAME, columns)

	if err != nil {
		return nil, fmt.Errorf("Error checking for existing issuers, [%v]", err)
	}
	if len(rowPointers) == 0 {
		return nil, errors.New("Issuer does not exist -> " + issuerID)
	}
	row := *rowPointers[0]

	issuerCode = row.Columns[2].GetString_()
	issuerOrganization = row.Columns[3].GetString_()

	if strings.EqualFold(callerDetails.issuerCode, issuerCode) == false {
		return nil, errors.New("Issuer code (Certificate and Store) don't match -> " + issuerID)
	}

	identityTypeCode := identityParams[2]

	//Check for Identity Type code
	identityTypeCodes := strings.Split(row.Columns[3].GetString_(), ",")
	identityTypeCodeExists := false

	for i := 0; i < len(identityTypeCodes); i++ {
		if strings.EqualFold(strings.TrimSpace(identityTypeCodes[i]), issuerCode) {
			identityTypeCodeExists = true
		}
	}
	if !identityTypeCodeExists {
		return nil, errors.New("IdentityTypeCode does not exist -> " + identityTypeCode)
	}

	providerEnrollmentID := identityParams[0]
	identityCode := identityParams[1]

	//Encrypted Payload
	encryptedPayload, err := decodeBase64(identityParams[3])
	if err != nil {
		return nil, fmt.Errorf("Bad Encrypted Payload [%v] ", err)
	}

	//Encrypted Key
	encryptedKey, err := decodeBase64(identityParams[4])
	if err != nil {
		return nil, fmt.Errorf("Bad Encrypted Key [%v] ", err)
	}

	//Encrypted Payload
	encryptedAttachmentURIString := identityParams[7]
	var encryptedAttachmentURI []byte
	if encryptedAttachmentURIString != "" {
		encryptedAttachmentURI, err = decodeBase64(identityParams[3])
		if err != nil {
			return nil, fmt.Errorf("Bad Encrypted AttachmentURI [%v] ", err)
		}

	}

	//Check if similar Identity exists
	var key2columns []shim.Column
	key2Col1 := shim.Column{Value: &shim.Column_String_{String_: identityCode}}
	key2Col2 := shim.Column{Value: &shim.Column_String_{String_: identityTypeCode}}
	key2Col3 := shim.Column{Value: &shim.Column_String_{String_: issuerCode}}
	key2columns = append(key2columns, key2Col1, key2Col2, key2Col3)

	tableName := providerEnrollmentID + IDENTITY_TBL_PREFIX

	identityRow, err := stub.GetRow(tableName, key2columns)

	if err == nil && identityRow.Columns[0].GetString_() != "" {
		return nil, fmt.Errorf("Identity already exists -> " + identityCode + "|" + identityTypeCode + "|" + issuerCode)
	}
	//Get Transaction TimeStamp
	stampPointer, err := stub.GetTxTimestamp()

	if err != nil {
		return nil, fmt.Errorf("Could not get Transaction timestamp from peer, [%v]", err)

	}

	//Save Identity
	timestamp := *stampPointer
	_, err = stub.InsertRow(
		tableName,
		shim.Row{
			Columns: []*shim.Column{
				&shim.Column{Value: &shim.Column_String_{String_: providerEnrollmentID}},
				&shim.Column{Value: &shim.Column_String_{String_: identityCode}},
				&shim.Column{Value: &shim.Column_String_{String_: identityTypeCode}},
				&shim.Column{Value: &shim.Column_Bytes{Bytes: encryptedPayload}},
				&shim.Column{Value: &shim.Column_String_{String_: issuerCode}},
				&shim.Column{Value: &shim.Column_String_{String_: issuerOrganization}},
				&shim.Column{Value: &shim.Column_Bytes{Bytes: encryptedKey}},
				&shim.Column{Value: &shim.Column_String_{String_: identityParams[6]}},
				&shim.Column{Value: &shim.Column_Bool{Bool: issuerVerified}},
				&shim.Column{Value: &shim.Column_Bytes{Bytes: encryptedAttachmentURI}},
				&shim.Column{Value: &shim.Column_String_{String_: callerDetails.user}},
				&shim.Column{Value: &shim.Column_Int64{Int64: timestamp.Seconds}},
				&shim.Column{Value: &shim.Column_String_{String_: ""}},
				&shim.Column{Value: &shim.Column_Int64{Int64: 0}},
				&shim.Column{Value: &shim.Column_String_{String_: ""}},
				&shim.Column{Value: &shim.Column_String_{String_: ""}},
				&shim.Column{Value: &shim.Column_String_{String_: ""}},
				&shim.Column{Value: &shim.Column_String_{String_: ""}},
			},
		})

	eventPayload := providerEnrollmentID + "|" + identityCode

	//Broadcast 'New ID Issued'
	err = stub.SetEvent(EVENT_NEW_IDENTITY_ISSUED, []byte(eventPayload))

	if err != nil {
		return nil, fmt.Errorf("Failed to setevent EVENT_NEW_IDENTITY_ISSUED, [%v] -> "+eventPayload, err)
	}
	return nil, nil

}

func (t *IdentityChainCode) GetIdentities(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {

	if len(args) < 1 {
		return nil, errors.New("Incorrect number of arguments. Expecting 1 -> [enrollmentID]")
	}
	enrollmentID := args[0]

	//Check if user is provider
	callerDetails, err := readCallerDetails(&stub)
	if err != nil {
		return nil, fmt.Errorf("Error getting caller details, [%v]", err)
	}

	isProv := isProvider(callerDetails)
	var columns []shim.Column = []shim.Column{}

	if isProv == false {
		keyCol1 := shim.Column{Value: &shim.Column_String_{String_: callerDetails.issuerID}}
		columns = append(columns, keyCol1)
	}

	tableName := enrollmentID + IDENTITY_TBL_PREFIX
	rowPointers, err := getRows(&stub, tableName, columns)

	if err != nil {
		return nil, fmt.Errorf("Error Getting Identiites, [%v]", err)
	}
	var identities []IdentityMin
	for _, rowPointer := range rowPointers {
		row := *rowPointer
		var identity = IdentityMin{}
		identity.ProviderEnrollmentID = enrollmentID
		identity.IdentityCode = row.Columns[1].GetString_()
		identity.IdentityTypeCode = row.Columns[2].GetString_()
		identity.IssuerCode = row.Columns[4].GetString_()
		identity.IssuerOrganization = row.Columns[5].GetString_()
		identity.CreatedBy = row.Columns[10].GetString_()
		identity.CreatedOnTxTimestamp = row.Columns[11].GetInt64()
		identity.LastUpdatedBy = row.Columns[12].GetString_()
		identity.LastUpdatedOnTxTimestamp = row.Columns[13].GetInt64()
		identity.IssuerVerified = row.Columns[8].GetBool()

		identities = append(identities, identity)

	}

	jsonRp, err := json.Marshal(identities)

	if err != nil {
		return nil, fmt.Errorf("Error Getting Identiites, [%v]", err)

	}

	return []byte(jsonRp), nil

}

func (t *IdentityChainCode) GetIssuers(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {

	if len(args) != 0 {
		return nil, errors.New("Incorrect number of arguments. Expecting none (0)")
	}

	//Check if user is provider
	callerDetails, err := readCallerDetails(&stub)
	if err != nil {
		return nil, fmt.Errorf("Error getting caller details, [%v]", err)
	}

	isProv := isProvider(callerDetails)
	var columns []shim.Column = []shim.Column{}

	if isProv == false {
		keyCol1 := shim.Column{Value: &shim.Column_String_{String_: callerDetails.issuerID}}
		columns = append(columns, keyCol1)
	}

	tableName := ISSUER_TBL_NAME
	rowPointers, err := getRows(&stub, tableName, columns)

	if err != nil {
		return nil, fmt.Errorf("Error Getting Issuers, [%v]", err)
	}
	var issuers []Issuer
	for _, rowPointer := range rowPointers {
		row := *rowPointer
		var issuer = Issuer{}
		issuer.IssuerUser = row.Columns[0].GetString_()
		issuer.IssuerID = row.Columns[1].GetString_()
		issuer.IssuerCode = row.Columns[2].GetString_()
		issuer.IssuerOrganization = row.Columns[3].GetString_()
		issuer.IssuerIdentityTypeCodes = row.Columns[4].GetString_()
		issuer.CreatedBy = row.Columns[5].GetString_()
		issuer.CreatedOnTxTimestamp = row.Columns[6].GetInt64()
		issuer.LastUpdatedBy = row.Columns[7].GetString_()
		issuer.LastUpdatedOnTxTimestamp = row.Columns[8].GetInt64()

		issuers = append(issuers, issuer)

	}

	jsonRp, err := json.Marshal(issuers)

	if err != nil {
		return nil, fmt.Errorf("Error Getting Issuers, [%v]", err)

	}
	fmt.Println(string(jsonRp))

	return jsonRp, nil

}

func (t *IdentityChainCode) GetIdentity(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {

	if len(args) < 2 {
		return nil, errors.New("Incorrect number of arguments. Expecting 1 -> [enrollmentID, identityCode]")
	}
	enrollmentID := args[0]
	identityCode := args[1]

	//Check if user is provider
	callerDetails, err := readCallerDetails(&stub)
	if err != nil {
		return nil, fmt.Errorf("Error getting caller details, [%v]", err)
	}

	isProv := isProvider(callerDetails)
	var columns []shim.Column = []shim.Column{}
	keyCol1 := shim.Column{Value: &shim.Column_String_{String_: identityCode}}
	columns = append(columns, keyCol1)

	if isProv == false {
		keyCol2 := shim.Column{Value: &shim.Column_String_{String_: callerDetails.issuerID}}
		columns = append(columns, keyCol2)
	}

	tableName := enrollmentID + IDENTITY_TBL_PREFIX
	rowPointers, err := getRows(&stub, tableName, columns)

	if err != nil {
		return nil, fmt.Errorf("Error Getting Identity, [%v]", err)
	}

	row := *rowPointers[0]
	var identity = Identity{}
	identity.ProviderEnrollmentID = enrollmentID
	identity.IdentityCode = row.Columns[1].GetString_()
	identity.IdentityTypeCode = row.Columns[2].GetString_()
	identity.EncryptedPayload = row.Columns[3].GetString_()
	identity.IssuerCode = row.Columns[4].GetString_()
	identity.IssuerOrganization = row.Columns[5].GetString_()
	identity.EncryptedKey = row.Columns[6].GetString_()
	identity.MetaData = row.Columns[7].GetString_()
	identity.IssuerVerified = row.Columns[8].GetBool()
	identity.EncryptedAttachmentURI = row.Columns[9].GetString_()
	identity.CreatedBy = row.Columns[10].GetString_()
	identity.CreatedOnTxTimestamp = row.Columns[11].GetInt64()
	identity.LastUpdatedBy = row.Columns[12].GetString_()
	identity.LastUpdatedOnTxTimestamp = row.Columns[13].GetInt64()

	jsonRp, err := json.Marshal(identity)

	if err != nil {
		return nil, fmt.Errorf("Error Getting Identity, [%v]", err)

	}
	fmt.Println(string(jsonRp))

	return jsonRp, nil

}

func (t *IdentityChainCode) GetPublicKey(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {

	if len(args) < 1 {
		return nil, errors.New("Incorrect number of arguments. Expecting 1 -> [enrollmentID]")
	}
	enrollmentID := args[0]

	//Verify that Enrollment ID and Pubic key is not null
	if enrollmentID == "" {
		return nil, errors.New("Provider Enrollment ID  required")
	}

	//Add Public key state
	existingPKBytes, err := stub.GetState(enrollmentID + PUBLIC_KEY_PREFIX)

	if err == nil {
		return nil, fmt.Errorf("Public Key for " + enrollmentID + "  does not exist")
	}

	return existingPKBytes, nil
}
