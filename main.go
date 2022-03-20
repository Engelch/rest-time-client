//go:generate swagger generate spec

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	ce "github.com/engelch/go_libs/v2"
	cli "github.com/urfave/cli/v2"
)

const appVersion = "0.1.3"
const appName = "restTimeClient"

// These CLI options are used more than once below. So let's use constants that we do not get misbehaviour
// by typoos.
const _debug = "debug"     // long (normal) name of CLI option
const _logging = "logging" // long (normal) name of CLI option

// context makes the app context accessible for easy tests of set arguments
// Otherwise, we would have to use closures which finally makes the code more complex (KISS vioation)
var context *cli.Context

// Data returns the current date and time.
// todo returns date as epoch for easy comparisons with other date/time stamps.
type Data struct {
	SwVersion       string `json:"swVersion"`
	DateIsoUtc      string `json:"dateIsoUtc"`      // date in format YYYY-MM-DD
	Time24Utc       string `json:"time24Utc"`       // time in format hh:mm:ss
	DateTimeEpocUtc int64  `json:"dateTimeEpocUtc"` // time since 1.1.1970
}

// ResponseStruct is the data structure to be returned by the REST GET call.
type ResponseStruct struct {
	Data      Data   `json:"data"`      // time date data structure
	Digest    string `json:"digest"`    // digest/checksum of Data structure
	Signature string `json:"signature"` // signature of Checksum
}

var pubKeyFile string // file containing public key

// =======================================================================================

// checkOptions checks the command line options if properly set or in range.
// POST: either both key files are empty of filled and the port# is set or: err != nil
func checkOptions(c *cli.Context, pubKeyFile string) error {
	const FirstUnprivilegedPort = 1024
	if c.Bool(_debug) {
		ce.CondDebugSet(true)
	}
	ce.CondDebugln("Debug is enabled.")
	if pubKeyFile == "" {
		ce.CondDebugln("Public key file not set.")
		return nil
	}
	ce.CondDebugln("Public key file is: " + pubKeyFile)
	return nil
}

// commandLineOptions just separates the definition of command line options ==> creating a shorter main
func commandLineOptions(pubKeyFile *string) []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:    _debug,
			Aliases: []string{"d"},
			Value:   false,
			Usage:   "OPTIONAL: enable debug",
		},
		&cli.BoolFlag{
			Name:    _logging,
			Aliases: []string{"l"},
			Value:   false,
			Usage:   "OPTIONAL: log to syslog (default: stderr)",
		},
		&cli.StringFlag{
			Name:        "publicKeyFile",
			Aliases:     []string{"k"},
			Usage:       "Optional: specify the file with the public key for verification",
			Destination: pubKeyFile,
		},
	}
}

func prettyString(str string) (string, error) {
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, []byte(str), "", "    "); err != nil {
		return "", err
	}
	return prettyJSON.String(), nil
}

// main start routine
func main() {
	app := cli.NewApp() // global var, see discussion above
	app.Flags = commandLineOptions(&pubKeyFile)
	app.Name = appName
	app.Version = appVersion
	app.Usage = "restTimeClient [-d] [-l] [-k <<publicKeyFile>>] <<URL>>"

	app.Action = func(c *cli.Context) error {
		context = c
		if c.Bool(_logging) {
			ce.LogInit(app.Name)
		} else {
			ce.LogStringInit(app.Name)
		}
		ce.LogInfo(app.Name + ":version " + appVersion + ":start")
		err := checkOptions(c, pubKeyFile)
		ce.ExitIfError(err, 9, "checkOptions")
		if c.Args().Get(0) == "" {
			ce.ErrorExit(10, "No Remote URL specified")
		}
		ce.CondDebugln("URL is: " + c.Args().Get(0) + ", Len is: " + fmt.Sprintf("%d", len(c.Args().Get(0))))
		resp, err := http.Get(c.Args().Get(0))
		ce.ExitIfError(err, 100, "Get Call")
		// body, err := ioutil.ReadAll(resp.Body)
		// resp.Body.
		// 	ce.ExitIfError(err, 101, "Reading Body")
		// fmt.Printf("%s\n", string(body))
		var response ResponseStruct
		err = json.NewDecoder(resp.Body).Decode(&response)
		ce.ExitIfError(err, 110, "json decode")
		fmt.Printf("%#v\n", response)
		fmt.Printf("Data in #v is:\n%#v\n", response.Data)
		fmt.Printf("Data in v is:\n%v\n", response.Data)
		marshalledData, err := json.Marshal(response.Data)
		if err != nil {
			ce.LogErr(":" + ce.CurrentFunctionName() + ":marshall error 1:" + err.Error())
			return err
		}
		err = os.WriteFile("data.txt", marshalledData, 0644)
		ce.ExitIfError(err, 115, "Error writing file data.txt")

		signatureByte, err := base64.StdEncoding.DecodeString(response.Signature)
		err = os.WriteFile("data.sig", signatureByte, 0644)
		ce.ExitIfError(err, 116, "Error writing file data.sig")

		digest := ce.Sha256bytes2bytes(marshalledData)
		fmt.Printf("Digest for Data is: %x\n", digest)

		if pubKeyFile != "" {
			pubkey, err := ce.LoadPublicKey(pubKeyFile)
			ce.ExitIfError(err, 110, "Loading public key")
			err = ce.Verify115Base64String(pubkey, response.Signature, string(marshalledData))
			if err != nil {
				fmt.Println("Verification FAILED!")
			} else {
				fmt.Println("Verification successful. Message stored as data.txt, signature as data.sig.\nPlease verify again with something like:\nopenssl dgst -verify key1.pub -signature data.sig data.txt")
			}
		}
		return nil
	}
	err := app.Run(os.Args)
	if err != nil {
		panic(err.Error())
	}
}

// eof
