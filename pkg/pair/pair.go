package pair

import (
	"bytes"
	"crypto/aes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/avereha/pod/pkg/message"

	"github.com/davecgh/go-spew/spew"
	"github.com/jacobsa/crypto/cmac"
	aesccm "github.com/pschlump/AesCCM"
	log "github.com/sirupsen/logrus"
)

type Direction byte

const (
	sp1 = "SP1="
	sp2 = ",SP2="

	sps0  = "SPS0="
	sps1  = "SPS1="
	sps21 = "SPS2.1="
	sps22 = "SPS2.2="

	sp0gp0 = "SP0,GP0"
	p0     = "P0="

	Read  Direction = 0x01
	Write Direction = 0x02
)

type Pair struct {
	podPublic  []byte
	podPrivate []byte
	podNonce   []byte
	podConf    []byte

	pdmPublic []byte
	pdmNonce  []byte
	pdmConf   []byte
	sps0      []byte

	sharedSecret []byte
	pdmID        []byte
	podID        []byte

	pdmCert []byte

	ltk     []byte
	confKey []byte // key used to sign the "Conf" values
}

func parseStringByte(expectedNames []string, data []byte) (map[string][]byte, error) {
	ret := make(map[string][]byte)
	for _, name := range expectedNames {
		n := len(name)
		if string(data[:n]) != name {
			return nil, fmt.Errorf("Name not found %s in %x", name, data)
		}
		data = data[n:]
		length := int(data[0])<<8 | int(data[1])
		ret[name] = data[2 : 2+length]
		data = data[2+length:]
	}
	return ret, nil
}

func buildStringByte(names []string, values map[string][]byte) ([]byte, error) {
	var buf bytes.Buffer
	for _, name := range names {
		buf.WriteString(name)
		n := len(values[name])
		buf.WriteByte(byte(n >> 8 & 0xff))
		buf.WriteByte(byte(n & 0xff))
		buf.Write(values[name])
	}
	return buf.Bytes(), nil
}

func (c *Pair) ParseSP1SP2(msg *message.Message) error {
	log.Infof("Received SP1 SP2 payload %x", msg.Payload)

	sp, err := parseStringByte([]string{sp1, sp2}, msg.Payload)
	if err != nil {
		log.Debugf("Message :%s", spew.Sdump(msg))
		return err
	}

	log.Infof("Received SP1 SP2: %x :: %x", sp[sp1], sp[sp2])
	c.podID = msg.Destination
	c.pdmID = msg.Source
	return nil
}

func (c *Pair) ParseSPS0(msg *message.Message) error {
	sp, err := parseStringByte([]string{sps0}, msg.Payload)
	if err != nil {
		log.Debugf("Message :%s", spew.Sdump(msg))
		return err
	}

	log.Infof("Received SPS0  %x", sp[sps0])
	copy(c.pdmNonce, []byte(sps0))

	err = c.computeMyData()
	if err != nil {
		return err
	}
	return nil
}

func (c *Pair) ParseSPS1(msg *message.Message) error {
	sp, err := parseStringByte([]string{sps1}, msg.Payload)
	if err != nil {
		log.Debugf("Message :%s", spew.Sdump(msg))
		return err
	}
	log.Infof("Received SPS1  %x", sp[sps1])
	pdmPublic := sp[sps1][:64]
	c.pdmPublic = make([]byte, 64)
	copy(c.pdmPublic, pdmPublic)

	pdmNonce := sp[sps1][64:]
	c.pdmNonce = make([]byte, 16)
	copy(c.pdmNonce, pdmNonce)
	log.Debugf("Pdm Public  %x :: %d", c.pdmPublic, len(c.pdmPublic))
	log.Debugf("Pdm Nonce   %x :: %d", c.pdmNonce, len(c.pdmNonce))

	return err
}

func (c *Pair) incrementNonce(nonce []byte) {
	num := binary.LittleEndian.Uint64(nonce)
	num += 1
	binary.LittleEndian.PutUint64(nonce, num)
	log.Infof("Nonce after increment: %x :: %d", nonce, len(nonce))
}

func (c *Pair) GenerateSPS0() (*message.Message, error) {
	var err error
	var buf bytes.Buffer
	//000109a218
	//0000099129
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)
	buf.WriteByte(0x09)
	buf.WriteByte(0x91)
	buf.WriteByte(0x29)

	sp := make(map[string][]byte)
	sp[sps0] = buf.Bytes()

	msg := message.NewMessage(message.MessageTypePairing, c.podID, c.pdmID)
	msg.Payload, err = buildStringByte([]string{sps0}, sp)
	if err != nil {
		return nil, err
	}
	log.Debugf("Sending SPS0: %x", msg.Payload)
	return msg, nil
}

func (c *Pair) GenerateSPS1() (*message.Message, error) {
	var err error
	var buf bytes.Buffer

	buf.Write(c.podPublic)
	buf.Write(c.podNonce)

	sp := make(map[string][]byte)
	sp[sps1] = buf.Bytes()

	msg := message.NewMessage(message.MessageTypePairing, c.podID, c.pdmID)
	msg.Payload, err = buildStringByte([]string{sps1}, sp)
	if err != nil {
		return nil, err
	}
	err = c.computePairData()
	if err != nil {
		return nil, err
	}
	log.Infof("Sending SPS1: %x", msg.Payload)
	return msg, nil
}

func (c *Pair) nonce13(direction Direction) []byte {
	ret := make([]byte, 0)
	ret = append(ret, byte(direction))
	if direction == Read {
		ret = append(ret, c.pdmNonce[:6]...)
		ret = append(ret, c.podNonce[:6]...)
	} else {
		// TODO
		ret = append(ret, c.podNonce[:6]...)
		ret = append(ret, c.pdmNonce[:6]...)
	}
	return ret
}

func (c *Pair) decryptSPS21(sps21 []byte) ([]byte, error) {
	hash := sha256.New()
	firmwareId, _ := hex.DecodeString("9b0ab96a76f4") // Hard coded
	controllerId, _ := hex.DecodeString("00000000")
	lengthBytes := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	lengthBytes[7] = byte(len(firmwareId))
	hash.Write(lengthBytes) // length 6 at pos 8
	hash.Write(firmwareId)  // firmwareId (9b0ab96a76f4)
	lengthBytes[7] = byte(len(controllerId))
	hash.Write(lengthBytes)  // length 6 at pos 8
	hash.Write(controllerId) // controllerId
	lengthBytes[7] = byte(len(c.pdmPublic))
	hash.Write(lengthBytes) // length 6 at pos 8
	hash.Write(c.pdmPublic) // key 1
	lengthBytes[7] = byte(len(c.podPublic))
	hash.Write(lengthBytes) // length 6 at pos 8
	hash.Write(c.podPublic) // key 2
	lengthBytes[7] = byte(len(c.sharedSecret))
	hash.Write(lengthBytes) // length 6 at pos 8
	hash.Write(c.sharedSecret)
	derivedKey := hash.Sum(nil)
	log.Infof("DerivedKey: %x :: %d", derivedKey, len(derivedKey))
	confKey := derivedKey[:16]
	ltk := derivedKey[16:]

	c.confKey = confKey
	c.ltk = ltk
	log.Infof("ConfKey: %x :: %d", confKey, len(confKey))
	log.Infof("LTK:     %x :: %d", ltk, len(ltk))

	nonce := c.nonce13(Read)
	tagSize := 8
	aes, _ := aes.NewCipher(c.confKey)
	accm, _ := aesccm.NewCCM(aes, tagSize, len(nonce))
	decrypted, err := accm.Open(nil, nonce, sps21, nil)
	if err != nil {
		return nil, err
	}
	c.incrementNonce(c.pdmNonce)
	return decrypted, nil
}

func (c *Pair) ParseSPS21(msg *message.Message) error {
	sp, err := parseStringByte([]string{sps21}, msg.Payload)
	if err != nil {
		log.Infof("Error parsing SPS2.1 Message :%s", spew.Sdump(msg))
		return err
	}
	log.Infof("Received SPS2.1: %x :: %d", sp[sps21], len(sp[sps21]))

	c.pdmCert, err = c.decryptSPS21(sp[sps21])
	log.Infof("Validated PDM SPS2: %x", sp[sps21])
	return err
}

func (c *Pair) GenerateSPS21() (*message.Message, error) {
	var err error
	sp := make(map[string][]byte)
	sp[sps21] = c.encryptSPS21()

	msg := message.NewMessage(message.MessageTypePairing, c.podID, c.pdmID)
	msg.Payload, err = buildStringByte([]string{sps21}, sp)
	if err != nil {
		return nil, err
	}
	log.Debugf("Generated SPS2: %x :: %d", msg.Payload, len(msg.Payload))
	return msg, nil
}

func (c *Pair) GenerateSPS22() (*message.Message, error) {
	panic("unimplemented")
}

func (c *Pair) ParseSPS22(msg *message.Message) any {
	sp, err := parseStringByte([]string{sps22}, msg.Payload)
	if err != nil {
		log.Infof("Error parsing SPS2.2 Message :%s", spew.Sdump(msg))
		return err
	}
	log.Infof("Received SPS2.2: %x :: %d", sp[sps22], len(sp[sps22]))

	c.pdmCert, err = c.decryptSPS22(sp[sps22])
	log.Infof("Validated PDM SPS2: %x", sp[sps21])
	return err
}

func (c *Pair) decryptSPS22(b []byte) ([]byte, error) {
	panic("unimplemented")
}

func (c *Pair) encryptSPS21() []byte {
	nonce := c.nonce13(Write)
	tagSize := 8
	aes, _ := aes.NewCipher(c.confKey)
	accm, _ := aesccm.NewCCM(aes, tagSize, len(nonce))
	c.incrementNonce(c.podNonce)
	return accm.Seal(nil, nonce, c.pdmCert, nil)
}

func (c *Pair) ParseSP0GP0(msg *message.Message) error {
	if string(msg.Payload) != sp0gp0 {
		log.Debugf("Message :%s", spew.Sdump(msg))
		return fmt.Errorf("Expected SP0GP0, got %x", msg.Payload)
	}
	log.Debugf("Parsed SP0GP0")
	return nil
}

var ZeroReader io.Reader = zeroReader{}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
func (c *Pair) GenerateP0() (*message.Message, error) {
	var err error
	msg := message.NewMessage(message.MessageTypePairing, c.podID, c.pdmID)
	sp := make(map[string][]byte)
	sp[p0] = []byte{0xa5} // magic constant ???
	msg.Payload, err = buildStringByte([]string{p0}, sp)
	log.Debugf("Generated P0")

	return msg, err
}

func (c *Pair) LTK() ([]byte, error) {
	if c.sharedSecret != nil {
		return c.ltk, nil
	}
	return nil, errors.New("Missing  enough data to compute LTK")
}

func (c *Pair) computeMyData() error {
	var err error
	c.podPrivate = make([]byte, 32)
	c.podPublic = make([]byte, 64)
	c.podNonce = make([]byte, 16)

	//rand.Read(c.podNonce)
	ZeroReader.Read(c.podNonce)
	podPrivate, _ := ecdh.P256().GenerateKey(ZeroReader)
	c.podPrivate = podPrivate.Bytes()
	c.podPublic = podPrivate.PublicKey().Bytes()[1:]
	log.Infof("Pod Private %x :: %d", c.podPrivate, len(c.podPrivate))
	log.Infof("Pod Public  %x :: %d", c.podPublic, len(c.podPublic))
	log.Infof("Pod Nonce   %x :: %d", c.podNonce, len(c.podNonce))
	return err

}
func (c *Pair) computePairData() error {
	var err error
	// fill in: lrtk, podConf, pdmConf, intermediaryKey
	privateKey, err := ecdh.P256().NewPrivateKey(c.podPrivate)
	if err != nil {
		return err
	}
	publicKey, err := ecdh.P256().NewPublicKey(append([]byte{0x04}, c.pdmPublic...))
	if err != nil {
		return err
	}
	c.sharedSecret, err = privateKey.ECDH(publicKey)
	if err != nil {
		return err
	}
	log.Infof("Shared secret %x :: %d", c.sharedSecret, len(c.sharedSecret))

	//first_key = data.pod_public[-4:] + data.pdm_public[-4:] + data.pod_nonce[-4:] + data.pdm_nonce[-4:]
	var endSize = 4
	firstKey := append(c.podPublic[len(c.podPublic)-endSize:], c.pdmPublic[len(c.pdmPublic)-endSize:]...)
	firstKey = append(firstKey, c.podNonce[len(c.podNonce)-endSize:]...)
	firstKey = append(firstKey, c.pdmNonce[len(c.pdmNonce)-endSize:]...)
	log.Infof("First key %x :: %d", firstKey, len(firstKey))

	first, err := cmac.New(firstKey)
	if err != nil {
		return err
	}
	log.Infof("CMAC: %d", first.Size())
	first.Write(c.sharedSecret)
	intermediarKey := first.Sum([]byte{})

	log.Infof("Intermediary key %x :: %d", intermediarKey, len(intermediarKey))

	// bb_data = bytes.fromhex("01") + bytes("TWIt", "ascii") + data.pod_nonce + data.pdm_nonce + bytes.fromhex("0001")
	var bbData bytes.Buffer
	bbData.WriteByte(0x01)
	bbData.WriteString("TWIt")
	bbData.Write(c.podNonce)
	bbData.Write(c.pdmNonce)
	bbData.WriteByte(0x00)
	bbData.WriteByte(0x01)
	bbHash, err := cmac.New(intermediarKey)
	if err != nil {
		return err
	}
	bbHash.Write(bbData.Bytes())
	c.confKey = bbHash.Sum([]byte{})
	log.Infof("Conf key %x :: %d", c.ltk, len(c.ltk))

	// ab_data = bytes.fromhex("02") + bytes("TWIt", "ascii") + data.pod_nonce + data.pdm_nonce + bytes.fromhex("0001")
	var abData bytes.Buffer
	abData.WriteByte(0x02) // this is the only difference
	abData.WriteString("TWIt")
	abData.Write(c.podNonce)
	abData.Write(c.pdmNonce)
	abData.WriteByte(0x00)
	abData.WriteByte(0x01)
	abHash, err := cmac.New(intermediarKey)
	if err != nil {
		return err
	}
	abHash.Write(abData.Bytes())
	c.ltk = abHash.Sum([]byte{})
	log.Infof("Long Term key %x :: %d", c.ltk, len(c.ltk))

	//  pdm_conf_data = bytes("KC_2_U", "ascii") + data.pdm_nonce + data.pod_nonce
	var pdmConfData bytes.Buffer
	pdmConfData.WriteString("KC_2_U")
	pdmConfData.Write(c.pdmNonce)
	pdmConfData.Write(c.podNonce)
	hash, err := cmac.New(c.confKey)
	if err != nil {
		return err
	}
	hash.Write(pdmConfData.Bytes())
	c.pdmConf = hash.Sum([]byte{})
	log.Infof("PDM Conf %x :: %d", c.pdmConf, len(c.pdmConf))

	//  pdm_conf_data = bytes("KC_2_V", "ascii") + data.pdm_nonce + data.pod_nonce
	var podConfData bytes.Buffer
	podConfData.WriteString("KC_2_V")
	podConfData.Write(c.podNonce) // ???
	podConfData.Write(c.pdmNonce)
	hash, err = cmac.New(c.confKey)
	if err != nil {
		return err
	}
	hash.Write(podConfData.Bytes())
	c.podConf = hash.Sum([]byte{})
	log.Infof("Pod Conf %x :: %d", c.podConf, len(c.podConf))

	return nil
}
