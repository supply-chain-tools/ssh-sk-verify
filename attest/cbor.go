package attest

import "fmt"

// https://www.rfc-editor.org/rfc/rfc8949.html

func cborReadMap(data []byte) (map[int]any, []byte, error) {
	high, low := cborDecodeType(data[0])
	data = data[1:]

	if high != 5 {
		return nil, nil, fmt.Errorf("got %d, expected CBOR major type 5 (map)", high)
	}

	numberOfPairs, data, err := cborReadValue(low, data)
	if err != nil {
		return nil, nil, err
	}

	result := make(map[int]any)
	for i := 0; i < numberOfPairs; i++ {
		var key int
		key, data, err = cborReadInteger(data)
		if err != nil {
			return nil, nil, err
		}

		var value any
		value, data, err = cborReadAny(data)
		if err != nil {
			return nil, nil, err
		}

		_, found := result[key]
		if found {
			return nil, nil, fmt.Errorf("duplicate key in CBOR map: %d", key)
		}

		result[key] = value
	}

	return result, data, nil
}

func cborReadAny(data []byte) (any, []byte, error) {
	high, _ := cborDecodeType(data[0])

	if high == 0 || high == 1 {
		return cborReadInteger(data)
	} else if high == 2 {
		return cborReadArray(data)
	} else {
		return nil, nil, fmt.Errorf("got %d, expected CBOR major type 0, 1 or 2", high)
	}
}

func cborReadArray(data []byte) ([]byte, []byte, error) {
	high, low := cborDecodeType(data[0])
	data = data[1:]
	if high != 2 {
		return nil, nil, fmt.Errorf("got %d, expected CBOR major type 2 (array)", high)
	}

	length, data, err := cborReadValue(low, data)
	if err != nil {
		return nil, nil, err
	}

	array := data[0:length]
	rest := data[length:]

	return array, rest, nil
}

func cborReadInteger(data []byte) (int, []byte, error) {
	high, low := cborDecodeType(data[0])
	data = data[1:]

	var v int
	var err error
	v, data, err = cborReadValue(low, data)
	if err != nil {
		return 0, nil, err
	}

	if high == 0 {
		return v, data, nil
	} else if high == 1 {
		return -1 - v, data, nil
	} else {
		return 0, nil, fmt.Errorf("got %d, expected CBOR major type 0 (unsigned int) or 1 (negative int)", high)
	}
}

func cborReadValue(low byte, data []byte) (int, []byte, error) {
	if low < 24 {
		return int(low), data, nil
	} else if low == 24 {
		v := int(data[0])
		return v, data[1:], nil
	} else if low == 25 {
		v := int(data[0])<<8 + int(data[1])
		return v, data[2:], nil
	} else {
		return 0, nil, fmt.Errorf("not implemented error: cbor value %d", low)
	}
}

func cborDecodeType(data byte) (byte, byte) {
	high := data >> 5
	low := data & 0b11111
	return high, low
}
