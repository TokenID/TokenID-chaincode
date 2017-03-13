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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/hyperledger/fabric/core/chaincode/shim"
)

type CallerDetails struct {
	user         string
	role         string
	issuerCode   string
	issuerID     string
	organization string
}

func readCallerDetails(stubPointer *shim.ChaincodeStubInterface) (CallerDetails, error) {
	var callerDetails CallerDetails

	stub := *stubPointer
	userBytes, err := stub.ReadCertAttribute("username")
	if err != nil {
		return callerDetails, fmt.Errorf("Error reading attribute 'user', [%v]", err)
	}
	callerDetails.user = string(userBytes)

	roleBytes, err := stub.ReadCertAttribute("role")
	if err != nil {
		return callerDetails, fmt.Errorf("Error reading attribute 'role', [%v]", err)
	}
	callerDetails.role = string(roleBytes)

	//==============Optional Fields....for the time being=================================

	issuerCodeBytes, err := stub.ReadCertAttribute("issuerCode")
	if err != nil {
		callerDetails.issuerCode = ""
		//return callerDetails, fmt.Errorf("Error reading attribute 'issuerCode', [%v]", err)
	} else {
		callerDetails.issuerCode = string(issuerCodeBytes)
	}

	issuerIDBytes, err := stub.ReadCertAttribute("issuerID")
	if err != nil {
		callerDetails.issuerID = ""
		//return callerDetails, fmt.Errorf("Error reading attribute 'issuerID', [%v]", err)
	} else {
		callerDetails.issuerID = string(issuerIDBytes)
	}

	orgBytes, err := stub.ReadCertAttribute("organization")
	if err != nil {
		callerDetails.organization = ""
		//return callerDetails, fmt.Errorf("Error reading attribute 'organization', [%v]", err)
	} else {
		callerDetails.organization = string(orgBytes)
	}

	return callerDetails, nil

}

func isProvider(callerDetails CallerDetails) bool {
	if strings.EqualFold(callerDetails.role, ROLE_PROVIDER) {
		return true
	}
	return false
}

func generateKeyBytes() ([]byte, error) {
	key := make([]byte, 32)

	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("Error generating random bytes', [%v]", err)
	}
	return key, nil

}

func encodeBase64(bytes []byte) string {
	return base64.URLEncoding.EncodeToString(bytes)
}
func decodeBase64(val string) []byte {
	return base64.URLEncoding.DecodeString(val)
}

func encryptAES(src []byte, key []byte) ([]byte, error) {

	iv, err := generateKeyBytes()
	dst := make([]byte, len(src))
	if err != nil {
		return nil, err
	}
	aesBlockEncrypter, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesEncrypter := cipher.NewCFBEncrypter(aesBlockEncrypter, iv)
	aesEncrypter.XORKeyStream(dst, src)

	//Append Initializing Vector to encrypted bytes
	dst = append(dst, iv...)

	return dst, nil
}

func encryptRSA(src []byte, pemKeyBytes []byte) ([]byte, error) {

	block, _ := pem.Decode(pemKeyBytes)

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)

	if err != nil {
		return nil, fmt.Errorf("Failed to parse RSA public key: [%v]", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)

	if !ok {
		return nil, fmt.Errorf("Value returned from ParsePKIXPublicKey was not an RSA public key")

	}
	rng := rand.Reader
	label, _ := generateKeyBytes()
	cipherValue, err := rsa.EncryptOAEP(sha256.New(), rng, rsaPub, src, label)
	if err != nil {
		return nil, fmt.Errorf("Error from encryption: [%v]", err)
	}
	return cipherValue, nil
}

func validatePublicKey(pemPbBytes []byte) error {

	block, err := pem.Decode(pemKeyBytes)

	if err != nil {
		return fmt.Errorf("Failed Decoding PEM public key: [%v]", err)
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)

	if err != nil {
		return fmt.Errorf("Failed to parse RSA public key: [%v]", err)
	}
	return nil
}
