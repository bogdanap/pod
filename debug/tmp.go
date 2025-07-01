package main

import (
	"crypto/aes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"

	"github.com/davecgh/go-spew/spew"
	aesccm "github.com/pschlump/AesCCM"
	log "github.com/sirupsen/logrus"
)

var podPrivate []byte
var podPublic []byte
var podNonce []byte
var pdmPublic []byte
var pdmNonce []byte
var receivedSPS2 []byte
var firmwareId []byte

func main() {
	podPrivate, _ = hex.DecodeString("1003c1bb3324e52d23d65afee2339eb42f8f0bfc1662297d83e2cce7b6f614c5")
	podPublic, _ = hex.DecodeString("9116807b73ff8fc4de35d43c0e37f22749216ea0a72b930ca9b1b7b216b5b5f151552422a5c4841a76620c16149265bfb6b09d45e0908ce13799906f69222d9d")
	podNonce, _ = hex.DecodeString("157e1e1a0ea6a5382213f9af755a43c8")
	pdmPublic, _ = hex.DecodeString("a68d482b7cac876b56b18b776f9bc66ea44e76c75597955c0617dcc8a36f1c04cdb76236154f0048737ac80712eb1300a87b58ef2dbc31eecde9f29cfab60352")
	pdmNonce, _ = hex.DecodeString("0ef7fc9233488437704508b86b776e89")
	receivedSPS2, _ = hex.DecodeString("f22a278294b63136a5db4046ca8e24f9f9fc2fe73e271dd1d3b62d52d665089b43e7e80f2e4ebe1649ccc57945cffbb9829ce30bfeabee5b4f1accd081b68ef741b332a0daff07b4c3af73c8477615cf6e9ee4cdd4e1d8ae90803612badbe062632137d2230ce29ad7da4c1477f4473532783b77a535600b94bfdf75ae6fd6eaf6cb2f711b03af282461ee484721e229a6758a9e28f8c9f8d68b1a117efa818a1b49861685eba3ce21b40c681158cda2a1f32aef70c017356bf28550f9cd7532f3dd00a1e9d6640f94e64506327e268a8efb76b3d8ef804c14dfa8384a98668874f2dc63c188d138cc68a879419fb553aa0a5cc9abf376f3be027521e2ba4a22da3c36675246467f6689696be1e4bd3742a61386e1615448a57b12ce6df672cb1c076d1371454d34eb7392585b52ba19cfcc36b461374e9b766686bd4003a18304fb6001b3f8b0e60a4b98148f3967ef486885931ea66ca79226cdded962a69c02a93079223a8cfe9d52b05128d809d785d96d5fea694617e2a6ace0b3cff8091cdb32eb2e231066671aa31ec0a4991dfb2818edbeccf21ae29530c4647482a5205645298d76dd602270e54993ee4e809ec28b31f8c48555129573c50ba4745b685f7c1c3a3950fb4f1670e02d111445b6b3412b9c19557aa2bf527937159f36717b2145c9041bc88a7caa7db29a1f7f8fc678ca32b4d5a607e8aa5cd2d1a68107249b2d199dfa13b831eabc59621fe46569ad9708b514220863c40b70cfeb4a484b566df7c0d097f5046f844c7cdcd60bcef26f6a25191ba575d1afa504f9146707d8ed0d0a024bb6b47f490025d15b58d12d18550daba817ba00c8fb52c6ccd395b055f485f062e6bf83506401e89b9340de02d31ec669cfb6aee5a03012d2a402")
	firmwareId, _ = hex.DecodeString("9b0ab96a76f4") // Hard coded
	// log.Infof("receivedSPS2: %x :: %d", receivedSPS2, len(receivedSPS2))
	// 151 bytes ASN.1 DER encoded :: 64 bytes certificate :: 8 bytes CCM Checksum

	// var ans1der = receivedSPS2[:215]
	// log.Infof("ans1der: %x :: %d", ans1der, len(ans1der))
	// type resultType struct {
	// x int
	// }
	// var tmp resultType
	// var cert, err = asn1.Unmarshal(ans1der, tmp)
	// cert, err := x509.ParseCertificate(receivedSPS2[0:215])
	// if err != nil {
	// log.Infof("Error :%s", spew.Sdump(err))
	// }
	// log.Infof("result: %x :: %d", result, len(result))
	// log.Infof("cert: %x", spew.Sdump(cert))

	privateKey, err := ecdh.P256().NewPrivateKey(podPrivate)
	if err != nil {
		log.Infof("Error :%s", spew.Sdump(err))
	}

	publicKey, err := ecdh.P256().NewPublicKey(append([]byte{0x04}, pdmPublic...))
	if err != nil {
		log.Infof("Error :%s", spew.Sdump(err))
	}

	sharedSecret, err := privateKey.ECDH(publicKey)

	log.Infof("Shared Secret: %x :: %d", sharedSecret, len(sharedSecret))

	controllerId1, _ := hex.DecodeString("00004ca4") // (4ca4) - Set by PDM
	controllerId2, _ := hex.DecodeString("00004ca6") // (4ca4) - Set by PDM
	controllerId3, _ := hex.DecodeString("fffffffe") // (4ca4) - Set by PDM
	controllerId4, _ := hex.DecodeString("0004c5e4") // (4ca4) - Set by PDM
	controllerId5, _ := hex.DecodeString("ffffffff") // (4ca4) - Set by PDM

	testControllerId(controllerId1, sharedSecret)
	testControllerId(controllerId2, sharedSecret)
	testControllerId(controllerId3, sharedSecret)
	testControllerId(controllerId4, sharedSecret)
	testControllerId(controllerId5, sharedSecret)
}

func testControllerId(controllerId []byte, sharedSecret []byte) {
	// testKeyDerivation(controllerId, podPublic, podPublic, sharedSecret)
	testKeyDerivation(controllerId, podPublic, pdmPublic, sharedSecret)
	testKeyDerivation(controllerId, pdmPublic, podPublic, sharedSecret)
	// testKeyDerivation(controllerId, podPublic, pdmNonce, sharedSecret)
	// testKeyDerivation(controllerId, podPublic, podNonce, sharedSecret)
	// testKeyDerivation(controllerId, podPublic, firmwareId, sharedSecret)
	// testKeyDerivation(controllerId, pdmPublic, pdmPublic, sharedSecret)
	//testKeyDerivation(controllerId, pdmPublic, podPublic, sharedSecret)
	// testKeyDerivation(controllerId, pdmPublic, pdmNonce, sharedSecret)
	// testKeyDerivation(controllerId, pdmPublic, podNonce, sharedSecret)
	// testKeyDerivation(controllerId, pdmPublic, firmwareId, sharedSecret)
	// testKeyDerivation(controllerId, pdmNonce, pdmNonce, sharedSecret)
	// testKeyDerivation(controllerId, pdmNonce, podNonce, sharedSecret)
	// testKeyDerivation(controllerId, pdmNonce, podPublic, sharedSecret)
	// testKeyDerivation(controllerId, pdmNonce, pdmPublic, sharedSecret)
	// testKeyDerivation(controllerId, pdmNonce, firmwareId, sharedSecret)
	// testKeyDerivation(controllerId, podNonce, podNonce, sharedSecret)
	// testKeyDerivation(controllerId, podNonce, pdmNonce, sharedSecret)
	// testKeyDerivation(controllerId, podNonce, pdmPublic, sharedSecret)
	// testKeyDerivation(controllerId, podNonce, podPublic, sharedSecret)
	// testKeyDerivation(controllerId, podNonce, firmwareId, sharedSecret)
	// testKeyDerivation(controllerId, firmwareId, firmwareId, sharedSecret)
	// testKeyDerivation(controllerId, firmwareId, podNonce, sharedSecret)
	// testKeyDerivation(controllerId, firmwareId, pdmNonce, sharedSecret)
	// testKeyDerivation(controllerId, firmwareId, pdmPublic, sharedSecret)
	// testKeyDerivation(controllerId, firmwareId, podPublic, sharedSecret)
}

func testKeyDerivation(controllerId []byte, key1 []byte, key2 []byte, sharedSecret []byte) {
	hash := sha256.New()

	lengthBytes := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	lengthBytes[7] = byte(len(firmwareId))
	hash.Write(lengthBytes) // length 6 at pos 8
	hash.Write(firmwareId)  // firmwareId (9b0ab96a76f4)
	lengthBytes[7] = byte(len(controllerId))
	hash.Write(lengthBytes)  // length 6 at pos 8
	hash.Write(controllerId) // controllerId
	lengthBytes[7] = byte(len(key1))
	hash.Write(lengthBytes) // length 6 at pos 8
	hash.Write(key1)        // key 1
	lengthBytes[7] = byte(len(key2))
	hash.Write(lengthBytes) // length 6 at pos 8
	hash.Write(key2)        // key 2
	lengthBytes[7] = byte(len(sharedSecret))
	hash.Write(lengthBytes) // length 6 at pos 8
	hash.Write(sharedSecret)
	derivedKey := hash.Sum(nil)
	log.Infof("DerivedKey: %x :: %d", derivedKey, len(derivedKey))
	confKey := derivedKey[:16]
	ltk := derivedKey[16:]

	//log.Infof("ConfKey: %x :: %d", confKey, len(confKey))
	//log.Infof("LTK:     %x :: %d", ltk, len(ltk))

	testConfKey(confKey)
	testConfKey(ltk)
}

func testConfKey(key []byte) {
	// First byte could be 1 or 2. Don't know which nonce is first.
	nonce0 := make([]byte, 0)
	nonce0 = append(nonce0, 0x00)
	nonce0 = append(nonce0, podNonce[:6]...)
	nonce0 = append(nonce0, pdmNonce[:6]...)

	nonce1 := make([]byte, 0)
	nonce1 = append(nonce1, 0x01)
	nonce1 = append(nonce1, podNonce[:6]...)
	nonce1 = append(nonce1, pdmNonce[:6]...)

	nonce3 := make([]byte, 0)
	nonce3 = append(nonce3, 0x02)
	nonce3 = append(nonce3, podNonce[:6]...)
	nonce3 = append(nonce3, pdmNonce[:6]...)

	nonce5 := make([]byte, 0)
	nonce5 = append(nonce5, 0x00)
	nonce5 = append(nonce5, pdmNonce[:6]...)
	nonce5 = append(nonce5, podNonce[:6]...)

	nonce2 := make([]byte, 0)
	nonce2 = append(nonce2, 0x01)
	nonce2 = append(nonce2, pdmNonce[:6]...)
	nonce2 = append(nonce2, podNonce[:6]...)

	//Most likely correct
	nonce4 := make([]byte, 0)
	nonce4 = append(nonce4, 0x02)
	nonce4 = append(nonce4, pdmNonce[:6]...)
	nonce4 = append(nonce4, podNonce[:6]...)

	nonce6 := make([]byte, 0)
	nonce6 = append(nonce6, 0x00)
	nonce6 = append(nonce6, podNonce[10:]...)
	nonce6 = append(nonce6, pdmNonce[10:]...)

	nonce7 := make([]byte, 0)
	nonce7 = append(nonce7, 0x01)
	nonce7 = append(nonce7, podNonce[10:]...)
	nonce7 = append(nonce7, pdmNonce[10:]...)

	nonce8 := make([]byte, 0)
	nonce8 = append(nonce8, 0x02)
	nonce8 = append(nonce8, podNonce[10:]...)
	nonce8 = append(nonce8, pdmNonce[10:]...)

	nonce9 := make([]byte, 0)
	nonce9 = append(nonce9, 0x00)
	nonce9 = append(nonce9, pdmNonce[10:]...)
	nonce9 = append(nonce9, podNonce[10:]...)

	nonce10 := make([]byte, 0)
	nonce10 = append(nonce10, 0x01)
	nonce10 = append(nonce10, pdmNonce[10:]...)
	nonce10 = append(nonce10, podNonce[10:]...)

	//Most likely correct
	nonce11 := make([]byte, 0)
	nonce11 = append(nonce11, 0x02)
	nonce11 = append(nonce11, pdmNonce[10:]...)
	nonce11 = append(nonce11, podNonce[10:]...)
	i := 8
	testCCMOpen(key, i, nonce0)
	testCCMOpen(key, i, nonce1)
	testCCMOpen(key, i, nonce2)
	testCCMOpen(key, i, nonce3)
	testCCMOpen(key, i, nonce4)
	testCCMOpen(key, i, nonce5)
	testCCMOpen(key, i, nonce6)
	testCCMOpen(key, i, nonce7)
	testCCMOpen(key, i, nonce8)
	testCCMOpen(key, i, nonce9)
	testCCMOpen(key, i, nonce10)
	testCCMOpen(key, i, nonce11)
}

func testCCMOpen(key []byte, tagSize int, nonce []byte) {
	aes, _ := aes.NewCipher(key)
	accm, _ := aesccm.NewCCM(aes, tagSize, 13)

	// content := receivedSPS2[:len(receivedSPS2)-8]
	// tag := receivedSPS2[len(receivedSPS2)-8:]
	// cert := receivedSPS2[151:215]
	// asn1der := receivedSPS2[:151]
	// log.Infof("content: %x :: %d", content, len(content))
	// log.Infof("asn1der: %x :: %d", asn1der, len(asn1der))
	// log.Infof("cert: %x :: %d", cert, len(cert))
	// log.Infof("tag: %x :: %d", tag, len(tag))
	var dst []byte
	r, err := accm.Open(nil, nonce, receivedSPS2, nil)
	// log.Infof("nonce: %x :: %d", nonce, len(nonce))
	// log.Infof("r: %x :: %d", r, len(r))
	// log.Infof("dst: %x :: %d", dst, len(dst))
	//log.Infof("Error :%s", spew.Sdump(err))
	if err == nil {
		log.Infof("SUCCESS!!! r: %x :: %d", r, len(r))
		log.Infof("dst: %x :: %d", dst, len(dst))
	}
	for x := 642; x >= 0; x-- {
		a := receivedSPS2[:x]
		b := receivedSPS2[x:]
		result1, err := accm.Open(nil, nonce, b, a)
		if err != nil {
			// log.Infof("Error :%s", spew.Sdump(err))
		} else {
			// If this works we've got everything correct.
			log.Infof("SUCCESS!! tagsize: %d, key: %x, nonce: %x", tagSize, key, nonce)
			log.Infof("result: %x :: %d", result1, len(result1))
		}
		result2, err := accm.Open(nil, nonce, a, b)
		if err != nil {
			// log.Infof("Error :%s", spew.Sdump(err))
		} else {
			// If this works we've got everything correct.
			log.Infof("SUCCESS!! tagsize: %d, key: %x, nonce: %x", tagSize, key, nonce)
			log.Infof("result: %x :: %d", result2, len(result2))
		}
		result3, err := accm.Open(nil, nonce, receivedSPS2, b)
		if err != nil {
			// log.Infof("Error :%s", spew.Sdump(err))
		} else {
			// If this works we've got everything correct.
			log.Infof("SUCCESS!! tagsize: %d, key: %x, nonce: %x", tagSize, key, nonce)
			log.Infof("result: %x :: %d", result3, len(result3))
		}

		_, err = accm.Open(nil, nonce, a, nil)
		if err != nil {
			// log.Infof("Error :%s", spew.Sdump(err))
		} else {
			// If this works we've got everything correct.
			log.Infof("SUCCESS!! tagsize: %d, key: %x, nonce: %x", tagSize, key, nonce)
			log.Infof("result: %x :: %d", result3, len(result3))
		}

		_, err = accm.Open(nil, nonce, b, nil)
		if err != nil {
			// log.Infof("Error :%s", spew.Sdump(err))
		} else {
			// If this works we've got everything correct.
			log.Infof("SUCCESS!! tagsize: %d, key: %x, nonce: %x", tagSize, key, nonce)
			log.Infof("result: %x :: %d", result3, len(result3))
		}

		_, err = accm.Open(nil, nonce, nil, a)
		if err != nil {
			// log.Infof("Error :%s", spew.Sdump(err))
		} else {
			// If this works we've got everything correct.
			log.Infof("SUCCESS!! tagsize: %d, key: %x, nonce: %x", tagSize, key, nonce)
			log.Infof("result: %x :: %d", result3, len(result3))
		}

		_, err = accm.Open(nil, nonce, nil, b)
		if err != nil {
			// log.Infof("Error :%s", spew.Sdump(err))
		} else {
			// If this works we've got everything correct.
			log.Infof("SUCCESS!! tagsize: %d, key: %x, nonce: %x", tagSize, key, nonce)
			log.Infof("result: %x :: %d", result3, len(result3))
		}

	}
}
