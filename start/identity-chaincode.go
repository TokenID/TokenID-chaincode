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
	"errors"
	"fmt"
	"strings"

	"github.com/hyperledger/fabric/core/chaincode/shim"
)

// IdentityChainCode  Chaincode implementation
type IdentityChainCode struct {
}

type Identity struct {
	providerEnrollmentID     string //Mundane identity ID - Identity Provider given
	identityCode             string //Issuer given identity ID
	identityTypeCode         string //Virtual Identity Type Code (Issuer defined) - gotten from TCert
	issuerCode               string //Virtual Identity Issuer Code - gotten from TCert
	issuerOrganization       string //Virtual Identity Issuer Organization - gotten from TCert or Ecert
	encryptedPayload         string // Encrypted Virtual Identity (EVI) payload
	encryptedKey             string //Symmetric encryption key for EVI payload encrypted with the public key
	metaData                 string //Miscellanous Identity Information - ONLY NON-SENSITIVE IDENTITY INFORMATION/ATTRIBUTES SHOULD BE ADDED
	encryptedAttachment      string //Encrypted URIs to Virtual Identity Document e.g. Scanned document image
	createdBy                string //Identity Creator
	createdOnTxTimestamp     int64  //Created on Timestamp -   which is currently taken from the peer receiving the transaction. Note that this timestamp may not be the same with the other peers' time.
	lastUpdatedBy            string //Last Updated By
	lastUpdatedOnTxTimestamp int64  //Last Updated On Timestamp -   which is currently taken from the peer receiving the transaction. Note that this timestamp may not be the same with the other peers' time.

}

type IdentityMin struct {
	identityCode             string `json:"identityCode"`
	identityTypeCode         string `json:"identityTypeCode"`
	issuerCode               string `json:"issuerCode"`
	issuerOrganization       string `json:"issuerOrganization"`
	createdBy                string `json:"createdBy"`
	createdOnTxTimestamp     int64  `json:"createdOnTxTimestamp"`
	lastUpdatedBy            string `json:"lastUpdatedBy"`
	lastUpdatedOnTxTimestamp int64  `json:"lastUpdatedOnTxTimestamp"`
}

type Issuer struct {
	issuerID                 string `json:"issuerID"`
	issuerIdentityTypeCodes  string `json:"issuerIdentityTypeCodes"`
	issuerCode               string `json:"issuerCode"`
	issuerOrganization       string `json:"issuerOrganization"`
	createdBy                string `json:"createdBy"`
	createdOnTxTimestamp     int64  `json:"createdOnTxTimestamp"`
	lastUpdatedBy            string `json:"lastUpdatedBy"`
	lastUpdatedOnTxTimestamp int64  `json:"lastUpdatedOnTxTimestamp"`
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
//Initializes chaincode when deployed
//=================================================================================================================================
func (t *IdentityChainCode) Init(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	if len(args) != 0 {
		return nil, errors.New("Incorrect number of arguments. Expecting 0")
	}

	if function == "initCreateStates" {

		//Create initial issuer tables
		err := t.createIssuerTable(stub)
		if err != nil {
			return nil, err
		}
	}

	return nil, nil
}

//=================================================================================================================================
//Initializes the Identity and sets the default states
//=================================================================================================================================
func (t *IdentityChainCode) InitIdentity(stub shim.ChaincodeStubInterface, providerEnrollmentID string, identityPublicKey string) (string, error) {

	//Verify that Enrollment ID and Pubic key is not null
	if providerEnrollmentID == "" || identityPublicKey == "" {
		return "", errors.New("Provider Enrollment ID or Public key cannot be null")
	}

	//Add Public key state
	existingPKBytes, err := stub.GetState(providerEnrollmentID + PUBLIC_KEY_PREFIX)

	if err == nil && existingPKBytes != nil {
		return "", fmt.Errorf("Public Key for " + providerEnrollmentID + " already exists -> " + string(existingPKBytes[:]))
	}

	pkBytes := []byte(identityPublicKey)

	//Validate Public key
	err = validatePublicKey(pkBytes)

	if err != nil {
		return "", fmt.Errorf("Bad Public Key -> Public key must be in PEM format - [%v]", err)
	}

	//Set Public key state
	err = stub.PutState(providerEnrollmentID+PUBLIC_KEY_PREFIX, pkBytes)

	if err != nil {
		return "", fmt.Errorf("Failed inserting public key, [%v] -> "+providerEnrollmentID, err)
	}

	//Create Identity Table
	err = t.createIdentityTable(stub, providerEnrollmentID)
	if err != nil {
		return "", fmt.Errorf("Failed creating Identity Table, [%v] -> "+providerEnrollmentID, err)
	}

	//Broadcast 'New Enrollment'  Event with enrollment ID
	err = stub.SetEvent(EVENT_NEW_IDENTITY_ENROLLED, []byte(providerEnrollmentID))

	if err != nil {
		return "", fmt.Errorf("Failed to broadcast enrollment event, [%v] -> "+providerEnrollmentID, err)
	}

	return "Enrollment Successful", nil
}

//=================================================================================================================================
//Initializes new Issuer
//=================================================================================================================================
func (t *IdentityChainCode) InitIssuer(stub shim.ChaincodeStubInterface, issuerEnrollmentUserName string, issuerID string, issuerCode string, issuerOrganization string, identityTypeCodes string) ([]byte, error) {

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
	//keyCol3 := shim.Column{Value: &shim.Column_String_{String_: issuerCode}}
	columns = append(columns, keyCol2)

	row, err := stub.GetRow(ISSUER_TBL_NAME, columns)

	if err != nil {
		return nil, fmt.Errorf("Error checking for existing issuers, [%v]", err)
	}
	if row.Columns[1].GetBytes() != nil {
		return nil, errors.New("Issuer already exist -> " + string(row.Columns[0].GetBytes()) + " | " + string(row.Columns[1].GetBytes()) + " | " + string(row.Columns[2].GetBytes()))
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

	return nil, nil
}

//=================================================================================================================================
//	 Entry point to invoke a chaincode function
//=================================================================================================================================
func (t *IdentityChainCode) Invoke(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	fmt.Println("invoke is running " + function)

	// Handle different functions
	if function == "init" { //initialize the chaincode state, used as reset
		return t.Init(stub, "init", args)
	}
	fmt.Println("invoke did not find func: " + function) //error

	return nil, errors.New("Received unknown function invocation: " + function)
}

//=================================================================================================================================
//	 Query is our entry point for queries
//=================================================================================================================================
func (t *IdentityChainCode) Query(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	fmt.Println("query is running " + function)

	// Handle different functions
	if function == "dummy_query" { //read a variable
		fmt.Println("hi there " + function) //error
		return nil, nil
	}
	fmt.Println("query did not find func: " + function) //error
	return nil, errors.New("Received unknown function query: " + function)
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
		&shim.ColumnDefinition{Name: "IssuerUserName", Type: shim.ColumnDefinition_STRING, Key: true},
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
func (t *IdentityChainCode) addIdentity(stub shim.ChaincodeStubInterface, identityParams []string) ([]byte, error) {

	if len(identityParams) < 7 {
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
	if isProvider == true {
		//Check for empty mandatory fields (first 5 fields)
		for i := 0; i < 5; i++ {
			if identityParams[i] == "" {
				return nil, errors.New("One or more mandatory fields is empty. Mandatory fields are the first 5 which are ProviderEnrollmentID, IdentityCode, IdentityTypeCode, IdentityPayload and IssuerID")
			}
		}
		issuerID = identityParams[4]
	} else {
		//Issuer details are gotten from Transaction Certificate
		//Check for empty mandatory fields
		for i := 0; i < 4; i++ {
			if identityParams[i] == "" {
				return nil, errors.New("One or more mandatory fields is empty. Mandatory fields are the first 4 which are ProviderEnrollmentID, IdentityCode, IdentityTypeCode  and IdentityPayload")
			}
		}
		issuerID = callerDetails.issuerID
	}

	//Get existing issuer
	var columns []shim.Column
	keyCol1 := shim.Column{Value: &shim.Column_String_{String_: issuerID}}
	columns = append(columns, keyCol1)

	row, err := stub.GetRow(ISSUER_TBL_NAME, columns)

	if err != nil {
		return nil, fmt.Errorf("Error checking for existing issuers, [%v]", err)
	}
	if row.Columns[1].GetBytes() == nil {
		return nil, errors.New("Issuer does not exist -> " + issuerID)
	}

	issuerCode = string(row.Columns[2].GetBytes())
	issuerOrganization = string(row.Columns[3].GetBytes())

	if strings.EqualFold(callerDetails.issuerCode, issuerCode) == false {
		return nil, errors.New("Issuer code (Certificate and Store) don't match -> " + issuerID)
	}

	identityTypeCode := identityParams[2]

	//Check for Identity Type code
	identityTypeCodes := strings.Split(string(row.Columns[3].GetBytes()), ",")
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
	identityPayload := identityParams[3]

	//Get Public Key
	publicKey, err := stub.GetState(providerEnrollmentID + PUBLIC_KEY_PREFIX)

	if err != nil {
		return nil, fmt.Errorf("Could not get Public Key for " + providerEnrollmentID)
	}

	//Check if similar Identity exists
	var key2columns []shim.Column
	key2Col1 := shim.Column{Value: &shim.Column_String_{String_: identityCode}}
	key2Col2 := shim.Column{Value: &shim.Column_String_{String_: identityTypeCode}}
	key2Col3 := shim.Column{Value: &shim.Column_String_{String_: issuerCode}}
	key2columns = append(columns, key2Col1, key2Col2, key2Col3)

	tableName := providerEnrollmentID + IDENTITY_TBL_PREFIX

	identityRow, err := stub.GetRow(tableName, key2columns)

	if err == nil && identityRow.Columns[0].GetBytes() != nil {
		return nil, fmt.Errorf("Identity already exists -> " + identityCode + "|" + identityTypeCode + "|" + issuerCode)
	}

	//Generate AES key
	aesKey, err := generateKeyBytes()
	if err != nil {
		return nil, err
	}

	//Encrypt IdentityPayload
	encryptedPayload, err := encryptAES([]byte(identityPayload), aesKey)

	if err != nil {
		return nil, fmt.Errorf("Error encrypting Payload, [%v]", err)
	}

	//Encrypt AttachmentURI
	attachmentURI := identityParams[6]
	var encryptedAttachmentURI []byte
	if attachmentURI != "" {
		encryptedAttachmentURI, err = encryptAES([]byte(attachmentURI), aesKey)

		if err != nil {
			return nil, fmt.Errorf("Error encrypting attachment URI, [%v]", err)
		}
	}

	//Encrypt AES Key
	encryptedKey, err := encryptRSA(aesKey, publicKey)

	if err != nil {
		return nil, fmt.Errorf("Error encrypting DEK, [%v]", err)
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
				&shim.Column{Value: &shim.Column_String_{String_: identityParams[5]}},
				&shim.Column{Value: &shim.Column_Bool{Bool: false}},
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

func (t *IdentityChainCode) getIdentities(stub shim.ChaincodeStubInterface, string enrollmentId) ([]byte, error) {

	//Check if user is provider
	callerDetails, err := readCallerDetails(&stub)
	if err != nil {
		return nil, fmt.Errorf("Error getting caller details, [%v]", err)
	}
	isProv := isProvider(callerDetails)
	if isProv == false {
		return nil, errors.New("Access Denied")
	}
}
