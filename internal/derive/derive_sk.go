package derive

import (
	"errors"
	"strconv"

	bip32 "github.com/vcvvvc/go-wallet-sdk/crypto/go-bip32"
	bip39 "github.com/vcvvvc/go-wallet-sdk/crypto/go-bip39"
)

var (
	ErrInvalidMnemonic = errors.New("invalid mnemonic")
	ErrInvalidIndex    = errors.New("invalid index")
	ErrDerivation      = errors.New("derivation failed")
)

// Why(中文): 先冻结派生入口与错误边界，让后续接入 BIP39/BIP32 时不需要反复改调用方契约。
// Why(English): Freeze the derivation entrypoint and error boundaries first so BIP39/BIP32 wiring can evolve without call-site churn.
func DeriveSK(mnemonicCanonical string, index string) ([]byte, error) {
	if mnemonicCanonical == "" {
		return nil, ErrInvalidMnemonic
	}
	if len(index) == 0 || (len(index) > 1 && index[0] == '0') {
		return nil, ErrInvalidIndex
	}
	n, err := strconv.ParseInt(index, 10, 64)
	if err != nil || n < 0 || n > 2147483647 {
		return nil, ErrInvalidIndex
	}
	seed, err := bip39.NewSeedWithErrorChecking(mnemonicCanonical, "")
	if err != nil {
		return nil, ErrInvalidMnemonic
	}
	master, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, ErrDerivation
	}
	child, err := master.NewChildKeyByPathString("m/44'/60'/0'/0/" + index)
	if err != nil {
		return nil, ErrDerivation
	}
	if len(child.Key) != 32 {
		return nil, ErrDerivation
	}
	sk := make([]byte, 32)
	copy(sk, child.Key)
	return sk, nil
}
