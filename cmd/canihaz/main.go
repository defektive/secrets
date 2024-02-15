package main

import (
	"flag"
	"fmt"
	"github.com/defektive/secrets"
	"log"
	"os"
)

func main() {
	creds := flag.Bool("creds", false, "get cred attrs instead of just the secret")
	flag.Parse()

	if len(flag.Args()) != 1 {
		fmt.Printf("You must supply a label to search for:\n\t%s example.com\n", os.Args[0])
		return
	}

	//secrets.Debug = true
	ss, err := secrets.NewSession()
	if err != nil {
		log.Fatalf("error creating new session: %s", err)
	}

	labelToSearch := flag.Arg(0)
	if *creds {
		str, err := ss.GetCredential(labelToSearch)
		if err != nil {
			log.Fatalf("searching for creds: %s", err)
		}

		fmt.Printf("found: %s", str)
	} else {
		str, err := ss.GetSecret(labelToSearch)
		if err != nil {
			log.Fatalf("searching for secret: %s", err)
		}
		fmt.Println(str)
	}
}
