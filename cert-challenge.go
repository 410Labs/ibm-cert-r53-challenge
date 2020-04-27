package main

// cert-challenge is an AWS Lambda functino that updates dns01 acme-challenges
// in Route 53.
// GOOS=linux go build -o cert-challenge cert-challenge.go && zip cert-challenge.zip cert-challenge

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/route53"
	jwt "github.com/dgrijalva/jwt-go"
)

type IbmMessage struct {
	Body string
}

type IbmChallenge struct {
	Certificate_manager_url string
	Certificates            []struct {
		Cert_crn   string
		Domains    string
		Expires_on string
		Name       string
	}
	Event_type               string
	Instance_crn             string
	CertificateCRN           string
	Domain_validation_method string
	Domain                   string
	Challenge                struct {
		Txt_record_name string
		Txt_record_val  string
	}
	LatestVersion int
	Version       int
	jwt.StandardClaims
}

//go:generate go run script/includetxt.go

var IbmPubKey = mustDecode([]byte(ibmpublickey))

func getChallenge(data []byte) (ic IbmChallenge, err error) {
	var body map[string]string
	err = json.Unmarshal(data, &body)
	if err != nil {
		return
	}
	token, err := jwt.ParseWithClaims(body["data"], &IbmChallenge{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Bad sign: %v", token.Header["alg"])
		}
		return IbmPubKey, nil
	})
	if err != nil {
		return
	}

	if claims, ok := token.Claims.(*IbmChallenge); ok {
		return *claims, nil
	}
	err = fmt.Errorf("token claims isn't an IBM record")
	return
}

func mustDecode(pubkey []byte) interface{} {
	block, _ := pem.Decode(pubkey)
	if block == nil || block.Type != "PUBLIC KEY" {
		panic("Failed to decode PEM block containing public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("Failed to parse x509: " + err.Error())
	}
	return key
}

func updateR53(zone, name, target, operation string) (string, error) {
	authZone := zone + "."
	name = fmt.Sprintf("%s.%s.", name, zone)
	target = fmt.Sprintf("\"%s\"", target)

	svc := route53.New(session.Must(session.NewSession()))
	reqParams := &route53.ListHostedZonesByNameInput{
		DNSName: aws.String(zone),
	}
	resp, err := svc.ListHostedZonesByName(reqParams)
	if err != nil {
		return "no zone", err
	}

	var hostedZoneID string
	for _, hostedZone := range resp.HostedZones {
		if !aws.BoolValue(hostedZone.Config.PrivateZone) && aws.StringValue(hostedZone.Name) == authZone {
			hostedZoneID = aws.StringValue(hostedZone.Id)
			break
		}
	}
	if strings.HasPrefix(hostedZoneID, "/hostedzone/") {
		hostedZoneID = strings.TrimPrefix(hostedZoneID, "/hostedzone/")
	}
	params := &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(hostedZoneID), // Required
		ChangeBatch: &route53.ChangeBatch{ // Required
			Changes: []*route53.Change{{ // Required
				Action: aws.String(operation),
				ResourceRecordSet: &route53.ResourceRecordSet{ // Required
					Name: aws.String(name),  // Required
					Type: aws.String("TXT"), // Required
					ResourceRecords: []*route53.ResourceRecord{
						{ // Required
							Value: aws.String(target), // Required
						},
					},
					TTL:    aws.Int64(300),
					Weight: aws.Int64(10),

					SetIdentifier: aws.String("challenge"),
				},
			}},
			Comment: aws.String("acme-cert challenge update."),
		},
	}
	resp2, err := svc.ChangeResourceRecordSets(params)
	if err != nil {
		return "change failed", err
	}
	return *resp2.ChangeInfo.Id, nil
}

func handlereq(ctx context.Context, data IbmMessage) (string, error) {
	if data.Body == "" {
		return fmt.Sprintf("No data"), nil
	}
	claims, err := getChallenge([]byte(data.Body))
	if err != nil {
		return fmt.Sprintf("Bad Claims"), err
	}

	fmt.Printf("Claims: %#v\n", claims)
	change := "ok"
	switch claims.Event_type {
	case "test_notification_channel":
		fmt.Printf("Test %s\n", claims.Certificates[0].Domains)
	case "cert_domain_validation_required":
		fmt.Printf("Validate %s\n", claims.Domain)
		change, err = updateR53(claims.Domain, claims.Challenge.Txt_record_name, claims.Challenge.Txt_record_val, route53.ChangeActionUpsert)
	case "cert_domain_validation_completed":
		fmt.Printf("Complete %s\n", claims.Domain)
		change, err = updateR53(claims.Domain, claims.Challenge.Txt_record_name, claims.Challenge.Txt_record_val, route53.ChangeActionDelete)
	case "cert_issued":
		fmt.Printf("Issued %s\n", claims.Domain)
		change, err = updateR53(claims.Domain, claims.Challenge.Txt_record_name, claims.Challenge.Txt_record_val, route53.ChangeActionDelete)
	}
	fmt.Printf("Change: %s, error: %s\n", change, err)
	return "ok", nil
}

func main() {
	lambda.Start(handlereq)
}
