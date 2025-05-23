package ja3

import (
	"errors"

	uquic "github.com/refraction-networking/uquic"
)

type USpec struct {
	QUICID uquic.QUICID
}

func (obj USpec) Spec() (uquic.QUICSpec, error) {
	spec, err := uquic.QUICID2Spec(obj.QUICID)
	if err != nil {
		return uquic.QUICSpec{}, err
	}
	return spec, nil
}
func CreateUSpec(value any) (uquic.QUICSpec, error) {
	switch data := value.(type) {
	case bool:
		if data {
			return uquic.QUICID2Spec(uquic.QUICFirefox_116)
		}
		return uquic.QUICSpec{}, nil
	case uquic.QUICID:
		return uquic.QUICID2Spec(data)
	case USpec:
		return data.Spec()
	default:
		return uquic.QUICSpec{}, errors.New("unsupported type")
	}
}
