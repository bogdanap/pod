package pair

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func decodeHex(h string) []byte {
	ret, _ := hex.DecodeString(h)
	return ret
}
func TestPair_decryptSPS21(t *testing.T) {
	type fields struct {
		podPublic    []byte
		podPrivate   []byte
		podNonce     []byte
		podConf      []byte
		pdmPublic    []byte
		pdmNonce     []byte
		pdmConf      []byte
		sps0         []byte
		sharedSecret []byte
		pdmID        []byte
		podID        []byte
		pdmCert      []byte
		ltk          []byte
		confKey      []byte
	}
	type args struct {
		sps21 []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "one",
			fields: fields{
				podPublic:    decodeHex("1e1837ef0d195188357571b5e5545b122e8f0967fda724203eb2561cce97285ef82b2d4f9ef1079f6c4b5b8356e23242e958b6d749a6b5681a4103566bdc5a89"),
				podPrivate:   decodeHex("0042000000000000000000000000000000000000000000000000000000000000"),
				podNonce:     decodeHex("00000000000000000000000000000000"),
				pdmPublic:    decodeHex("ab9edd2ca1085f8c97fe2b479a105bcb154a90884f6fcc20245805ff5d7414d01c90da4bb43dd7b722fdb89b694825e6e622c8982e754743afe71ffed68419bf"),
				pdmNonce:     decodeHex("386ad690604bddd68e9ddd61e4df6bc2"),
				sharedSecret: decodeHex("9e4f578ae60da4f7a028f9b2699827cb377ee8707d44f19aab1be81cd85d7a51"),
			},
			args: args{
				sps21: decodeHex("cf63677515c8ad253d8f792e25c9ddd1d979b70202ae4bfe1654ec7b55d828073b948b2d167b875de46905e7dd120ca47692e3f87e00a643ffb1a02a06d2f3b911403ee6125a4b17764907639d61a0dfcad5f641bcfa184ef0d4829a68ff729e428509ae3e8ef3eb6618dec02ffaf080a5e44077a6b936b5486630433e7d41e4b79d2321501ee854f1e291efd3d19bcee700f6b7348fc09c397230a6c0c39258d6323fd55ad52e52a89e9d233cbc867c1cc06b1a7f49244a173a111a0eec7abea0d795d9df08fa8e35c7d5ee6fc0e4dee417a45839978f9a8aebfda20bf876f2f0938a1058b2380d32f0cc33d0cc77f707ba14160d0735d6748c2d2b5d76a3191315c9de8a9b4dda1592db97436f72874452c5485665e69a6a7356b39c31366d24c2dc31e782f9fce435e5377af21b9eeb533429075de2fa3b79bc6dcb69471bcb5f797f6526cb5ede0a8ecde52ac5bfab132c7855d615348576301d1b90bb4b96e544d2ef102c1f25e99384b1880fff322d2053210701f9b17d170cd56b86202a0d008511a64e4c74cbe60ecb2712c8b43fcf0eb4f9d384b9964e56d0be5c7f0c02928258267fdd6fa8a4d525fbbfc653b20cc37209220141bd9891d293db757b380acbffc93af86f5e241e82e8a36f98f3c4862e97dc461af306b6300cf26c77538b2644cacdb913e594579ed52aecde8228708ba006fec14ec2c5158e6ff34c0dd405c9a1432e28246e167d88120a8262fe1547fc70620b1694d74df664dcf9b6dfc6bf7a509e1a7eb092eca9eab49f39cea7a1d7ff53b0b00cc1d91d096bc7414fc41bf2856d4689b43d7ed3eb675bef04215b86b394481de95e751a36b9b0051b8d23e805f8ba8ec87a5a6cbf59c31d16b5af44d46a2283f790d3fd159baf0f"),
			},
			want:    decodeHex("308202763082021ca0030201020214315d61e9a5a9d2e14a1ee439be1775ce4e7c1d69300a06082a8648ce3d04030230253110300e060355040a0c07496e73756c65743111300f06035504030c08494e533030504731301e170d3231303330323230343733365a170d3336303232373230343733355a30253110300e060355040a0c07496e73756c65743111300f06035504030c08494e5330325047313059301306072a8648ce3d020106082a8648ce3d03010703420004c83618a58fbdce1efd69ecc64784b5b3c0d9a40c8590e3c84fc41a48505fc461e5df4b19a24eef20101c5bee946cb1560d1190dd30ac3415600d034292287150a382012830820124300f0603551d130101ff040530030101ff301f0603551d23041830168014e1046965d31c40730ac802fcc1e600ac51485e293081c00603551d1f0481b83081b53081b2a08184a08181867f687474703a2f2f69737375696e672e70726f642d6f6d6e69706f64636c6f75642e75732e70726f642e736161732e7072696d656b65792e636f6d2f656a6263612f7075626c69637765622f63726c732f7365617263682e6367693f734b4944486173683d345152705a644d6351484d4b79414c38776559417246464958696ba229a42730253111300f06035504030c08494e5330305047313110300e060355040a0c07496e73756c6574301d0603551d0e04160414b08ad05214c026c03b0ab395eaa62003a1c74d0c300e0603551d0f0101ff040403020186300a06082a8648ce3d04030203480030450220619121b40c25aea50c209a4ad7bc2b74cb17e2663abcd2a96ce21c28516ca830022100bb8215d91e0734353bf26b2d2cb04aa0baee3299e32a737bd55a3f5216ccdcfc"),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Pair{
				podPublic:    tt.fields.podPublic,
				podPrivate:   tt.fields.podPrivate,
				podNonce:     tt.fields.podNonce,
				podConf:      tt.fields.podConf,
				pdmPublic:    tt.fields.pdmPublic,
				pdmNonce:     tt.fields.pdmNonce,
				pdmConf:      tt.fields.pdmConf,
				sps0:         tt.fields.sps0,
				sharedSecret: tt.fields.sharedSecret,
				pdmID:        tt.fields.pdmID,
				podID:        tt.fields.podID,
				pdmCert:      tt.fields.pdmCert,
				ltk:          tt.fields.ltk,
				confKey:      tt.fields.confKey,
			}
			got, err := c.decryptSPS(tt.args.sps21)
			if (err != nil) != tt.wantErr {
				t.Errorf("Pair.decryptSPS21() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Pair.decryptSPS21() = %v, want %v", got, tt.want)
			}
		})
	}
}
