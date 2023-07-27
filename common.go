package multisig

import (
	"encoding/hex"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/hdkeychain/v3"
	"github.com/decred/dcrd/txscript/v4/stdaddr"
)

// PubKey1MasterBase58 is a master pub key for dcrwallet.
// Note: we can't use dcrwallet maspetr pub key for multisig because it doesn't track transactions
// related to it, it only probably tracks transactions related to accounts.
const (
	PartiallySignedTx = "01000000018c7869ee3495769d0beb6038127b304207d6d841370c4efe7d237763be94e6830100000000ffffffff019dd234310000000000001976a91435c46341faa39c02d9dc06cd39b905462d3130f988ac0000000000000000012bdb34310000000000000000ffffffff91483045022100e9b2fb23bb904befb6e461a24ca67d829202898f174c2e5dd746698794fa4983022032d1a11e10eba9eb93c7e0624433c095776749ee10e9ea8ec606e35cf2f8d82301475221030e4db4d37cfa43553c645ad20ca79ae79eef966f41243628310e7624d33a41452102dc7aaeb575d3170760f3c719befd52805a0301b200a1e4efb700ebcc379a9af552ae"
	// PrevOutUnlockScriptHex represents output unlock script for our multisig address, it's
	// hardcoded for now, note that we always have single unlock script for our multisig
	// address because we always use single multisig address.
	PrevOutUnlockScriptHex = "a914abb90acd25884d6238b26a585caf123a7212a5e587"

	ExpMultisigAddr     = "TcoAoGJUeo6dPojqgwKjWxUpPanncZEofoJ" // we are working with this single address for now
	PubKey1MasterBase58 = "tpubVoovD5uE5T4ia4kfdmKXs988QLGLkDxBddBKeMWMx1SPuLUwZhYXQJKpg1D1gNtzL8GUCEM4sj3sGEj3iCdfERoiUpvJx2U7AVKQ1Ah94wk"
)

//# latest signed / broadcast
//~ » decred/dcrctl --testnet --wallet purchaseticket imported 40 1 "TcoAoGJUeo6dPojqgwKjWxUpPanncZEofoJ" 1 "" 0 0 "test" true
//{
//"unsignedtickets": [
//"01000000018c7869ee3495769d0beb6038127b304207d6d841370c4efe7d237763be94e6830000000000ffffffff034d11d6bd00000000000018baa914abb90acd25884d6238b26a585caf123a7212a5e58700000000000000000000206a1eabb90acd25884d6238b26a585caf123a7212a5e56d28d6bd00000080004e000000000000000000001abd76a914000000000000000000000000000000000000000088ac0000000000000000016d28d6bd0000000000000000ffffffff00"
//],
//"splittx": "0100000004b9ff188304c117c3b9a56239e4a48a4955a9c46cd358fddde9ee9315fd73bec30000000000ffffffff56feda9729216a5d88c58709c243ef28b477e21ded5d47697ffaca0dcf2538550000000000fffffffffed773159008d614ccb66d7ca3bbb2d028803cee9f5854ec2bee1d42f4b9160d0100000000fffffffffed773159008d614ccb66d7ca3bbb2d028803cee9f5854ec2bee1d42f4b9160d0000000000ffffffff026d28d6bd00000000000017a914abb90acd25884d6238b26a585caf123a7212a5e5872bdb343100000000000017a914abb90acd25884d6238b26a585caf123a7212a5e587000000000000000004e09304000000000000000000ffffffff00809698000000000000000000ffffffff007ff797300000000000000000ffffffff00dd1cd6bd0000000000000000ffffffff00"
//}

var ChainCfg = chaincfg.TestNet3Params()

func DeriveAddr(masterPubKeyBase58 string) (childPub, childAddr string) {
	// Build master pub key, below we'll be deriving multisig pub key at the following path:
	// master/0/1 which corresponds to master/account/address.
	// For dcrwallet-generated addresses the branch seems to be 0, which is defined as
	// ExternalBranch constant in dcrwallet code.
	pubKey1Master, err := hdkeychain.NewKeyFromString(
		masterPubKeyBase58,
		ChainCfg,
	)
	if err != nil {
		panic(err)
	}
	branchKey, err := pubKey1Master.Child(0)
	if err != nil {
		panic(err)
	}
	childKey, err := branchKey.Child(1)
	if err != nil {
		panic(err)
	}
	addr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(
		stdaddr.Hash160(childKey.SerializedPubKey()),
		ChainCfg,
	)
	if err != nil {
		panic(err)
	}

	return hex.EncodeToString(childKey.SerializedPubKey()), addr.String()
}
