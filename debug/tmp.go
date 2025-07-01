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
	podPrivate, _ = hex.DecodeString("0042000000000000000000000000000000000000000000000000000000000000")
	podPublic, _ = hex.DecodeString("1e1837ef0d195188357571b5e5545b122e8f0967fda724203eb2561cce97285ef82b2d4f9ef1079f6c4b5b8356e23242e958b6d749a6b5681a4103566bdc5a89")
	podNonce, _ = hex.DecodeString("00000000000000000000000000000000")
	pdmPublic, _ = hex.DecodeString("ab9edd2ca1085f8c97fe2b479a105bcb154a90884f6fcc20245805ff5d7414d01c90da4bb43dd7b722fdb89b694825e6e622c8982e754743afe71ffed68419bf")
	pdmNonce, _ = hex.DecodeString("386ad690604bddd68e9ddd61e4df6bc2")
	receivedSPS2, _ = hex.DecodeString("cf63677515c8ad253d8f792e25c9ddd1d979b70202ae4bfe1654ec7b55d828073b948b2d167b875de46905e7dd120ca47692e3f87e00a643ffb1a02a06d2f3b911403ee6125a4b17764907639d61a0dfcad5f641bcfa184ef0d4829a68ff729e428509ae3e8ef3eb6618dec02ffaf080a5e44077a6b936b5486630433e7d41e4b79d2321501ee854f1e291efd3d19bcee700f6b7348fc09c397230a6c0c39258d6323fd55ad52e52a89e9d233cbc867c1cc06b1a7f49244a173a111a0eec7abea0d795d9df08fa8e35c7d5ee6fc0e4dee417a45839978f9a8aebfda20bf876f2f0938a1058b2380d32f0cc33d0cc77f707ba14160d0735d6748c2d2b5d76a3191315c9de8a9b4dda1592db97436f72874452c5485665e69a6a7356b39c31366d24c2dc31e782f9fce435e5377af21b9eeb533429075de2fa3b79bc6dcb69471bcb5f797f6526cb5ede0a8ecde52ac5bfab132c7855d615348576301d1b90bb4b96e544d2ef102c1f25e99384b1880fff322d2053210701f9b17d170cd56b86202a0d008511a64e4c74cbe60ecb2712c8b43fcf0eb4f9d384b9964e56d0be5c7f0c02928258267fdd6fa8a4d525fbbfc653b20cc37209220141bd9891d293db757b380acbffc93af86f5e241e82e8a36f98f3c4862e97dc461af306b6300cf26c77538b2644cacdb913e594579ed52aecde8228708ba006fec14ec2c5158e6ff34c0dd405c9a1432e28246e167d88120a8262fe1547fc70620b1694d74df664dcf9b6dfc6bf7a509e1a7eb092eca9eab49f39cea7a1d7ff53b0b00cc1d91d096bc7414fc41bf2856d4689b43d7ed3eb675bef04215b86b394481de95e751a36b9b0051b8d23e805f8ba8ec87a5a6cbf59c31d16b5af44d46a2283f790d3fd159baf0f")
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
	privateKey.Public()
	publicKey, err := ecdh.P256().NewPublicKey(append([]byte{0x04}, pdmPublic...))
	if err != nil {
		log.Infof("Error :%s", spew.Sdump(err))
	}

	sharedSecret, err := privateKey.ECDH(publicKey)
	if err != nil {
		log.Infof("Error :%s", spew.Sdump(err))
	}
	log.Infof("Shared Secret: %x :: %d", sharedSecret, len(sharedSecret))
	/*
	   	controllerId1, _ := hex.DecodeString("00004ca4") // (4ca4) - Set by PDM
	   	controllerId2, _ := hex.DecodeString("00004ca6") // (4ca4) - Set by PDM
	   	controllerId3, _ := hex.DecodeString("fffffffe") // (4ca4) - Set by PDM
	   	controllerId8, _ := hex.DecodeString("0004c5e3") // (4ca4) - Set by PDM

	   	controllerId4, _ := hex.DecodeString("0004c5e4") // (4ca4) - Set by PDM
	   	controllerId5, _ := hex.DecodeString("0004c5e5") // (4ca4) - Set by PDM
	   	controllerId6, _ := hex.DecodeString("0004c5e6") // (4ca4) - Set by PDM

	   	controllerId7, _ := hex.DecodeString("ffffffff") // (4ca4) - Set by PDM
	   /*
	   	/*
	   		testControllerId(controllerId1, sharedSecret)
	   		testControllerId(controllerId2, sharedSecret)
	   		testControllerId(controllerId3, sharedSecret)
	   		testControllerId(controllerId4, sharedSecret)
	   		testControllerId(controllerId5, sharedSecret)
	   		testControllerId(controllerId6, sharedSecret)
	   		testControllerId(controllerId7, sharedSecret)
	   		testControllerId(controllerId8, sharedSecret)
	*/
	controllerId9, _ := hex.DecodeString("00000000") // (4ca4) - Set by PDM

	testControllerId(controllerId9, sharedSecret)

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
