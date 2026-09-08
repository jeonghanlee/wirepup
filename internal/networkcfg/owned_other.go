//go:build !linux

package networkcfg

import (
	"context"
	"errors"
)

func ownedAddressPresent(ctx context.Context, e Entry) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return false, errors.New("networkcfg: exact address inspection requires Linux")
}
