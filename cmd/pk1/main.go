package main

import (
	"fmt"
	"os"

	"github.com/norwnd/multisig"
)

func _main() error {
	childKey, addr := multisig.DeriveAddr(multisig.PubKey1MasterBase58)

	// Compressed
	fmt.Println(fmt.Sprintf("pub child: %s", childKey))
	fmt.Println(fmt.Sprintf("addr child: %s", addr))
	// Uncompressed
	//fmt.Println(fmt.Sprintf("pub after: %s", pubKey1HexAfter))

	//pubKey1BytesAfter, err := hex.DecodeString(pubKey1HexBefore)
	//if err != nil {
	//	return err
	//}
	//pubKey1HexAfter, err := hdkeychain.NewKeyFromString( // hardcoded master pub key for now
	//	base58.Encode(pubKey1BytesAfter),
	//	multisig.ChainCfg,
	//)
	//if err != nil {
	//	return err
	//}

	//fmt.Println(fmt.Sprintf("pub: %x", pubKey1.String()))
	//fmt.Println(fmt.Sprintf("addr: %s", addrPubKey1.String()))

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
